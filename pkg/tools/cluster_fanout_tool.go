// Copyright 2026 https://github.com/KongZ/kubeai-chatbot
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tools

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KongZ/kubeai-chatbot/gollm"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"k8s.io/klog/v2"
)

// defaultFanoutMaxIterations and defaultFanoutMaxConcurrency are used when the
// caller (Agent.DispatchToolCalls) doesn't populate the corresponding context
// values — this keeps the tool safe to call even if wiring is incomplete.
const (
	defaultFanoutMaxIterations  = 5
	defaultFanoutMaxConcurrency = 4

	// perClusterTimeout is a hard wall-clock ceiling for a single cluster's
	// sub-conversation, independent of its iteration budget, so one stuck
	// cluster (a hanging LLM call, a slow retry backoff) can't stall the
	// whole fan-out indefinitely.
	perClusterTimeout = 3 * time.Minute
)

// ClusterFanoutTool lets the agent answer one question across several
// Kubernetes clusters in a single tool call, without violating the
// top-level agent's one-cluster-per-response rule (Agent.activeKubeContext
// in pkg/agent/conversation.go). It runs one small, isolated, read-only
// sub-conversation per target cluster — in parallel, under a hard iteration
// budget — and returns a structured per-cluster result for the top-level
// model to format however the user asked.
//
// It deliberately does NOT implement KubeContextExtractor: the top-level
// agent's single-context gate only fires for tools that report a
// KubeContext, so this tool is structurally exempt from it rather than
// needing a special case there.
type ClusterFanoutTool struct{}

func NewClusterFanoutTool() *ClusterFanoutTool {
	return &ClusterFanoutTool{}
}

func (t *ClusterFanoutTool) Name() string {
	return "multi_cluster_query"
}

func (t *ClusterFanoutTool) Description() string {
	return `Runs a single, read-only investigation across multiple Kubernetes clusters at once and returns one result per cluster. Use this instead of repeating kubectl calls with different --context values when asked to check, compare, or summarize something across "all clusters", "every cluster", or a named list of clusters — looping clusters yourself is blocked and will exhaust your iteration budget.`
}

func (t *ClusterFanoutTool) FunctionDefinition() *gollm.FunctionDefinition {
	return &gollm.FunctionDefinition{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &gollm.Schema{
			Type: gollm.TypeObject,
			Properties: map[string]*gollm.Schema{
				"task": {
					Type:        gollm.TypeString,
					Description: `A precise, self-contained description of what to check on each cluster, e.g. "Determine the Istio control plane version". Write it as if instructing a colleague who will only ever see one cluster.`,
				},
				"clusters": {
					Type:        gollm.TypeArray,
					Description: `Specific kubeconfig context names to target. Omit this to target every cluster the agent has access to.`,
					Items:       &gollm.Schema{Type: gollm.TypeString},
				},
			},
			Required: []string{"task"},
		},
	}
}

func (t *ClusterFanoutTool) IsInteractive(args map[string]any) (bool, error) {
	return false, nil
}

// CheckModifiesResource always returns "no": every per-cluster sub-call this
// tool makes is forced read-only internally (see runOneCluster), regardless
// of the top-level agent's ModifyResources mode.
func (t *ClusterFanoutTool) CheckModifiesResource(args map[string]any) string {
	return "no"
}

// clusterResult is one cluster's outcome from a fan-out run.
type clusterResult struct {
	Cluster string `json:"cluster"`
	Result  string `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (t *ClusterFanoutTool) Run(ctx context.Context, args map[string]any) (any, error) {
	task, _ := args["task"].(string)
	if strings.TrimSpace(task) == "" {
		return nil, fmt.Errorf("multi_cluster_query requires a non-empty \"task\"")
	}

	llm, _ := ctx.Value(FanoutLLMKey).(gollm.Client)
	model, _ := ctx.Value(FanoutModelKey).(string)
	toolset, _ := ctx.Value(FanoutToolsKey).(*Tools)
	if llm == nil || model == "" || toolset == nil {
		return nil, fmt.Errorf("multi_cluster_query is not available in this context (missing LLM/model/tools wiring)")
	}

	maxIterations, _ := ctx.Value(FanoutMaxIterationsKey).(int)
	if maxIterations <= 0 {
		maxIterations = defaultFanoutMaxIterations
	}
	maxConcurrency, _ := ctx.Value(FanoutMaxConcurrencyKey).(int)
	if maxConcurrency <= 0 {
		maxConcurrency = defaultFanoutMaxConcurrency
	}
	progress, _ := ctx.Value(FanoutProgressKey).(func(cluster, status, detail string))

	clusters, err := resolveFanoutClusters(ctx, args)
	if err != nil {
		return nil, err
	}

	// Sub-conversations must never be able to call multi_cluster_query
	// themselves — recursion guard.
	subToolset := toolset.withoutTool(t.Name())

	if maxConcurrency > len(clusters) {
		maxConcurrency = len(clusters)
	}

	results := make([]clusterResult, len(clusters))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i, cluster := range clusters {
		wg.Add(1)
		go func(i int, cluster string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if progress != nil {
				progress(cluster, "started", task)
			}

			clusterCtx, cancel := context.WithTimeout(ctx, perClusterTimeout)
			defer cancel()

			result, err := runOneCluster(clusterCtx, llm, model, subToolset, cluster, task, maxIterations)
			if err != nil {
				results[i] = clusterResult{Cluster: cluster, Error: err.Error()}
				if progress != nil {
					progress(cluster, "error", err.Error())
				}
				return
			}
			results[i] = clusterResult{Cluster: cluster, Result: result}
			if progress != nil {
				progress(cluster, "done", result)
			}
		}(i, cluster)
	}
	wg.Wait()

	return map[string]any{"results": results}, nil
}

// resolveFanoutClusters determines the target cluster list: explicit
// "clusters" arguments take priority, otherwise every cluster the agent
// knows is reachable (FanoutAvailableClustersKey, populated at Agent.Init
// from the kubeconfig).
func resolveFanoutClusters(ctx context.Context, args map[string]any) ([]string, error) {
	if raw, ok := args["clusters"]; ok {
		if list, ok := raw.([]any); ok && len(list) > 0 {
			clusters := make([]string, 0, len(list))
			for _, v := range list {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					clusters = append(clusters, s)
				}
			}
			if len(clusters) > 0 {
				return clusters, nil
			}
		}
	}

	available, _ := ctx.Value(FanoutAvailableClustersKey).([]string)
	if len(available) == 0 {
		return nil, fmt.Errorf("no target clusters: none were specified and no reachable clusters are known — ask the user which cluster(s) to check")
	}
	return available, nil
}

// runOneCluster runs a small, self-contained, read-only sub-conversation
// scoped to exactly one cluster context, bounded by maxIterations. It is
// deliberately independent of Agent.Run()'s state machine — that loop is
// entangled with interactive confirmation/session/UI concerns that don't
// apply to this headless, one-shot sub-task.
func runOneCluster(ctx context.Context, llm gollm.Client, model string, toolset *Tools, cluster, task string, maxIterations int) (string, error) {
	systemPrompt := fanoutSystemPrompt(cluster, task)

	chat := gollm.NewRetryChat(
		llm.StartChat(systemPrompt, model),
		gollm.RetryConfig{
			MaxAttempts:    3,
			InitialBackoff: 5 * time.Second,
			MaxBackoff:     30 * time.Second,
			BackoffFactor:  2,
			Jitter:         true,
		},
	)

	var functionDefinitions []*gollm.FunctionDefinition
	for _, tool := range toolset.AllTools() {
		functionDefinitions = append(functionDefinitions, tool.FunctionDefinition())
	}
	if err := chat.SetFunctionDefinitions(functionDefinitions); err != nil {
		return "", fmt.Errorf("configuring tools for cluster %q: %w", cluster, err)
	}

	content := []any{fmt.Sprintf("Investigate cluster %q. Task: %s", cluster, task)}

	for iteration := 0; iteration < maxIterations; iteration++ {
		stream, err := chat.SendStreaming(ctx, content...)
		if err != nil {
			return "", fmt.Errorf("cluster %q: %w", cluster, err)
		}
		content = nil

		var text string
		var functionCalls []gollm.FunctionCall
		for response, err := range stream {
			if err != nil {
				return "", fmt.Errorf("cluster %q: %w", cluster, err)
			}
			if response == nil || len(response.Candidates()) == 0 {
				break
			}
			for _, part := range response.Candidates()[0].Parts() {
				if t, ok := part.AsText(); ok {
					text += t
				}
				if calls, ok := part.AsFunctionCalls(); ok {
					functionCalls = append(functionCalls, calls...)
				}
			}
		}

		if len(functionCalls) == 0 {
			if strings.TrimSpace(text) == "" {
				return "", fmt.Errorf("cluster %q: empty response", cluster)
			}
			return strings.TrimSpace(text), nil
		}

		for _, call := range functionCalls {
			result, callErr := dispatchFanoutToolCall(ctx, toolset, cluster, call)
			content = append(content, gollm.FunctionCallResult{
				ID:     call.ID,
				Name:   call.Name,
				Result: result,
			})
			if callErr != nil {
				klog.V(2).Infof("multi_cluster_query: cluster %q tool call %q rejected: %v", cluster, call.Name, callErr)
			}
		}
	}

	return "", fmt.Errorf("cluster %q: reached the fan-out iteration budget (%d) without a final answer", cluster, maxIterations)
}

// dispatchFanoutToolCall runs one tool call on behalf of a per-cluster
// sub-conversation, enforcing two invariants unconditionally (independent of
// the top-level agent's ModifyResources mode):
//  1. read-only only — any call that CheckModifiesResource reports as
//     anything other than "no" is refused rather than executed.
//  2. exact cluster scoping — for a tool that implements
//     KubeContextExtractor, the call must explicitly target this cluster's
//     context; a missing or mismatched --context is refused rather than
//     silently falling back to the shared kubeconfig's current-context,
//     which could target the wrong cluster.
//
// A refusal is returned as a FunctionCallResult-shaped error so the
// sub-conversation's model can see it and correct its next call, rather than
// aborting the whole cluster's investigation.
func dispatchFanoutToolCall(ctx context.Context, toolset *Tools, cluster string, call gollm.FunctionCall) (map[string]any, error) {
	toolCall, err := toolset.ParseToolInvocation(ctx, call.Name, call.Arguments)
	if err != nil {
		return map[string]any{"error": err.Error()}, err
	}

	if modifies := toolCall.GetTool().CheckModifiesResource(call.Arguments); modifies != "no" {
		err := fmt.Errorf("multi_cluster_query runs read-only: %q was refused because it may modify resources", call.Name)
		return map[string]any{"error": err.Error()}, err
	}

	if extractor, ok := toolCall.GetTool().(KubeContextExtractor); ok {
		kubeContext, found := extractor.ExtractKubeContext(call.Arguments)
		if !found || kubeContext != cluster {
			err := fmt.Errorf("this command must explicitly target --context %s (got %q) — every command in this sub-conversation must stay scoped to that one cluster", cluster, kubeContext)
			return map[string]any{"error": err.Error()}, err
		}
	}

	kubeconfig, _ := ctx.Value(KubeconfigKey).(string)
	workDir, _ := ctx.Value(WorkDirKey).(string)
	identity, _ := ctx.Value(IdentityKey).(*api.Identity)

	opts := InvokeToolOptions{
		Kubeconfig: kubeconfig,
		WorkDir:    workDir,
		Identity:   identity,
	}

	output, err := toolCall.InvokeTool(ctx, opts)
	if err != nil {
		return map[string]any{"error": err.Error()}, err
	}
	result, err := ToolResultToMap(output)
	if err != nil {
		return map[string]any{"error": err.Error()}, err
	}
	return result, nil
}

// fanoutSystemPrompt builds a compact, single-cluster-scoped system prompt
// for a fan-out sub-conversation. It's intentionally much smaller than the
// main agent's system prompt template — no interactive confirmation flow,
// no manifest-generation guidance, nothing that doesn't apply to a headless,
// read-only, one-shot investigation of exactly one cluster.
func fanoutSystemPrompt(cluster, task string) string {
	return fmt.Sprintf(`You are investigating exactly one Kubernetes cluster: context %q. You are one of several parallel investigations running across different clusters; your findings will be combined into a single report, so stay strictly scoped to this cluster only.

Task: %s

Rules:
- Every command you run MUST explicitly include "--context %s". Never omit it or rely on a default context.
- You are READ-ONLY. Never run a command that creates, updates, or deletes a resource. Never retrieve Kubernetes Secrets.
- Use the fewest commands possible. Prefer one broad, well-filtered command over several narrow ones.
- When you have enough information, reply with ONLY your finding as a short, single, self-contained piece of plain text suitable for one cell of a table (no markdown code fences, no restating the task, no preamble). If you could not determine the answer, say so briefly and why.`, cluster, task, cluster)
}

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
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KongZ/kubeai-chatbot/gollm"
	"github.com/KongZ/kubeai-chatbot/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// --- minimal fake gollm response plumbing, mirroring pkg/agent's test helpers ---

type fakePart struct {
	text  string
	calls []gollm.FunctionCall
}

func (p fakePart) AsText() (string, bool) {
	if p.text != "" {
		return p.text, true
	}
	return "", false
}

func (p fakePart) AsFunctionCalls() ([]gollm.FunctionCall, bool) {
	if p.calls != nil {
		return p.calls, true
	}
	return nil, false
}

type fakeCandidate struct{ parts []gollm.Part }

func (c fakeCandidate) String() string      { return "" }
func (c fakeCandidate) Parts() []gollm.Part { return c.parts }

type fakeChatResponse struct{ candidate gollm.Candidate }

func (r fakeChatResponse) UsageMetadata() any            { return nil }
func (r fakeChatResponse) Candidates() []gollm.Candidate { return []gollm.Candidate{r.candidate} }

func textIter(text string) gollm.ChatResponseIterator {
	resp := fakeChatResponse{candidate: fakeCandidate{parts: []gollm.Part{fakePart{text: text}}}}
	return func(yield func(gollm.ChatResponse, error) bool) { yield(resp, nil) }
}

// --- FunctionDefinition / CheckModifiesResource / IsInteractive ---

func TestClusterFanoutTool_FunctionDefinition(t *testing.T) {
	tool := NewClusterFanoutTool()
	assert.Equal(t, "multi_cluster_query", tool.Name())

	def := tool.FunctionDefinition()
	require.NotNil(t, def)
	assert.Equal(t, "multi_cluster_query", def.Name)
	require.NotNil(t, def.Parameters)
	assert.Equal(t, gollm.TypeObject, def.Parameters.Type)
	assert.Contains(t, def.Parameters.Required, "task")

	taskProp := def.Parameters.Properties["task"]
	require.NotNil(t, taskProp)
	assert.Equal(t, gollm.TypeString, taskProp.Type)

	clustersProp := def.Parameters.Properties["clusters"]
	require.NotNil(t, clustersProp)
	assert.Equal(t, gollm.TypeArray, clustersProp.Type)
	require.NotNil(t, clustersProp.Items)
	assert.Equal(t, gollm.TypeString, clustersProp.Items.Type)
}

func TestClusterFanoutTool_CheckModifiesResource_AlwaysNo(t *testing.T) {
	tool := NewClusterFanoutTool()
	assert.Equal(t, "no", tool.CheckModifiesResource(map[string]any{"task": "anything"}))
	assert.Equal(t, "no", tool.CheckModifiesResource(nil))
}

func TestClusterFanoutTool_IsInteractive_AlwaysFalse(t *testing.T) {
	tool := NewClusterFanoutTool()
	interactive, err := tool.IsInteractive(map[string]any{"task": "anything"})
	assert.False(t, interactive)
	assert.NoError(t, err)
}

// --- resolveFanoutClusters ---

func TestResolveFanoutClusters_ExplicitList(t *testing.T) {
	args := map[string]any{"clusters": []any{"cluster-a", "cluster-b"}}
	clusters, err := resolveFanoutClusters(context.Background(), args)
	require.NoError(t, err)
	assert.Equal(t, []string{"cluster-a", "cluster-b"}, clusters)
}

func TestResolveFanoutClusters_DefaultsToAvailable(t *testing.T) {
	ctx := context.WithValue(context.Background(), FanoutAvailableClustersKey, []string{"cluster-x", "cluster-y"})
	clusters, err := resolveFanoutClusters(ctx, map[string]any{"task": "check"})
	require.NoError(t, err)
	assert.Equal(t, []string{"cluster-x", "cluster-y"}, clusters)
}

func TestResolveFanoutClusters_NoneAvailable_Errors(t *testing.T) {
	_, err := resolveFanoutClusters(context.Background(), map[string]any{"task": "check"})
	assert.Error(t, err)
}

func TestResolveFanoutClusters_EmptyExplicitList_FallsBackToAvailable(t *testing.T) {
	ctx := context.WithValue(context.Background(), FanoutAvailableClustersKey, []string{"cluster-x"})
	args := map[string]any{"clusters": []any{}}
	clusters, err := resolveFanoutClusters(ctx, args)
	require.NoError(t, err)
	assert.Equal(t, []string{"cluster-x"}, clusters)
}

// --- dispatchFanoutToolCall read-only + context-scoping enforcement ---

// countingTool is a minimal fake Tool that records how many times Run was
// called, used to prove a rejected call never actually executes.
type countingTool struct {
	name             string
	modifiesResource string
	runCount         int32
	kubeContext      string
	hasKubeContext   bool
}

func (t *countingTool) Name() string        { return t.name }
func (t *countingTool) Description() string { return "test tool" }
func (t *countingTool) FunctionDefinition() *gollm.FunctionDefinition {
	return &gollm.FunctionDefinition{Name: t.name}
}
func (t *countingTool) Run(ctx context.Context, args map[string]any) (any, error) {
	atomic.AddInt32(&t.runCount, 1)
	return map[string]any{"ok": true}, nil
}
func (t *countingTool) IsInteractive(args map[string]any) (bool, error) { return false, nil }
func (t *countingTool) CheckModifiesResource(args map[string]any) string {
	return t.modifiesResource
}
func (t *countingTool) ExtractKubeContext(args map[string]any) (string, bool) {
	return t.kubeContext, t.hasKubeContext
}

func TestDispatchFanoutToolCall_RejectsWrites(t *testing.T) {
	tool := &countingTool{name: "writer", modifiesResource: "yes"}
	var toolset Tools
	toolset.Init()
	toolset.RegisterTool(tool)

	_, err := dispatchFanoutToolCall(context.Background(), &toolset, "cluster-a",
		gollm.FunctionCall{Name: "writer", Arguments: map[string]any{}})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read-only")
	assert.Equal(t, int32(0), atomic.LoadInt32(&tool.runCount), "a write call must never actually run")
}

func TestDispatchFanoutToolCall_RejectsContextMismatch(t *testing.T) {
	tool := &countingTool{name: "kubectl_like", modifiesResource: "no", kubeContext: "cluster-b", hasKubeContext: true}
	var toolset Tools
	toolset.Init()
	toolset.RegisterTool(tool)

	_, err := dispatchFanoutToolCall(context.Background(), &toolset, "cluster-a",
		gollm.FunctionCall{Name: "kubectl_like", Arguments: map[string]any{}})

	assert.Error(t, err)
	assert.Equal(t, int32(0), atomic.LoadInt32(&tool.runCount), "a mismatched-context call must never actually run")
}

func TestDispatchFanoutToolCall_RejectsMissingContext(t *testing.T) {
	tool := &countingTool{name: "kubectl_like", modifiesResource: "no", hasKubeContext: false}
	var toolset Tools
	toolset.Init()
	toolset.RegisterTool(tool)

	_, err := dispatchFanoutToolCall(context.Background(), &toolset, "cluster-a",
		gollm.FunctionCall{Name: "kubectl_like", Arguments: map[string]any{}})

	assert.Error(t, err, "a call with no --context at all must be rejected, not silently defaulted")
	assert.Equal(t, int32(0), atomic.LoadInt32(&tool.runCount))
}

func TestDispatchFanoutToolCall_AllowsMatchingReadOnlyCall(t *testing.T) {
	tool := &countingTool{name: "kubectl_like", modifiesResource: "no", kubeContext: "cluster-a", hasKubeContext: true}
	var toolset Tools
	toolset.Init()
	toolset.RegisterTool(tool)

	_, err := dispatchFanoutToolCall(context.Background(), &toolset, "cluster-a",
		gollm.FunctionCall{Name: "kubectl_like", Arguments: map[string]any{}})

	assert.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&tool.runCount))
}

// --- Run: end-to-end fan-out orchestration ---

func TestClusterFanoutTool_Run_MissingWiring(t *testing.T) {
	tool := NewClusterFanoutTool()
	_, err := tool.Run(context.Background(), map[string]any{"task": "check"})
	assert.Error(t, err, "Run must fail clearly when the LLM/tools context wiring is absent")
}

func TestClusterFanoutTool_Run_EmptyTask(t *testing.T) {
	tool := NewClusterFanoutTool()
	_, err := tool.Run(context.Background(), map[string]any{"task": "   "})
	assert.Error(t, err)
}

func TestClusterFanoutTool_Run_AggregatesPerClusterResultsAndIsolatesErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	client := mocks.NewMockClient(ctrl)
	chatA := mocks.NewMockChat(ctrl)
	chatB := mocks.NewMockChat(ctrl)

	client.EXPECT().StartChat(gomock.Any(), "test-model").DoAndReturn(
		func(systemPrompt, model string) gollm.Chat {
			if strings.Contains(systemPrompt, `"cluster-a"`) {
				return chatA
			}
			return chatB
		},
	).Times(2)

	chatA.EXPECT().SetFunctionDefinitions(gomock.Any()).Return(nil)
	chatA.EXPECT().SendStreaming(gomock.Any(), gomock.Any()).Return(textIter("1.29.2"), nil)

	chatB.EXPECT().SetFunctionDefinitions(gomock.Any()).Return(nil)
	chatB.EXPECT().SendStreaming(gomock.Any(), gomock.Any()).Return(nil, errors.New("connection refused"))

	var toolset Tools
	toolset.Init()

	ctx := context.Background()
	ctx = context.WithValue(ctx, FanoutLLMKey, gollm.Client(client))
	ctx = context.WithValue(ctx, FanoutModelKey, "test-model")
	ctx = context.WithValue(ctx, FanoutToolsKey, &toolset)
	ctx = context.WithValue(ctx, FanoutMaxIterationsKey, 3)

	tool := NewClusterFanoutTool()
	out, err := tool.Run(ctx, map[string]any{
		"task":     "Determine the Istio control plane version",
		"clusters": []any{"cluster-a", "cluster-b"},
	})
	require.NoError(t, err)

	resultMap, ok := out.(map[string]any)
	require.True(t, ok)
	results, ok := resultMap["results"].([]clusterResult)
	require.True(t, ok)
	require.Len(t, results, 2)

	// Order must match the input cluster order regardless of which
	// goroutine finished first.
	assert.Equal(t, "cluster-a", results[0].Cluster)
	assert.Equal(t, "1.29.2", results[0].Result)
	assert.Empty(t, results[0].Error)

	assert.Equal(t, "cluster-b", results[1].Cluster)
	assert.Empty(t, results[1].Result)
	assert.Contains(t, results[1].Error, "connection refused")
}

func TestClusterFanoutTool_Run_RespectsMaxConcurrency(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const (
		numClusters    = 4
		maxConcurrency = 2
	)

	client := mocks.NewMockClient(ctrl)

	var mu sync.Mutex
	current, maxObserved := 0, 0

	// Every cluster gets its own MockChat instance, all sharing the same
	// blocking-and-counting SendStreaming behavior so we can observe how
	// many run at once.
	for i := 0; i < numClusters; i++ {
		chat := mocks.NewMockChat(ctrl)
		chat.EXPECT().SetFunctionDefinitions(gomock.Any()).Return(nil)
		chat.EXPECT().SendStreaming(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, contents ...any) (gollm.ChatResponseIterator, error) {
				mu.Lock()
				current++
				if current > maxObserved {
					maxObserved = current
				}
				mu.Unlock()

				time.Sleep(20 * time.Millisecond)

				mu.Lock()
				current--
				mu.Unlock()

				return textIter("ok"), nil
			},
		)
		client.EXPECT().StartChat(gomock.Any(), "test-model").Return(chat)
	}

	var toolset Tools
	toolset.Init()

	ctx := context.Background()
	ctx = context.WithValue(ctx, FanoutLLMKey, gollm.Client(client))
	ctx = context.WithValue(ctx, FanoutModelKey, "test-model")
	ctx = context.WithValue(ctx, FanoutToolsKey, &toolset)
	ctx = context.WithValue(ctx, FanoutMaxIterationsKey, 3)
	ctx = context.WithValue(ctx, FanoutMaxConcurrencyKey, maxConcurrency)

	clusters := make([]any, numClusters)
	for i := range clusters {
		clusters[i] = "cluster-" + string(rune('a'+i))
	}

	tool := NewClusterFanoutTool()
	_, err := tool.Run(ctx, map[string]any{"task": "check", "clusters": clusters})
	require.NoError(t, err)

	assert.LessOrEqual(t, maxObserved, maxConcurrency, "fan-out must never run more than FanoutMaxConcurrency clusters at once")
}

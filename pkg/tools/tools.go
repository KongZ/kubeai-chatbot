// Copyright 2025 Google LLC
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/KongZ/kubeai-chatbot/pkg/journal"
	"github.com/google/uuid"
	"k8s.io/klog/v2"
)

type ContextKey string

const (
	KubeconfigKey ContextKey = "kubeconfig"
	WorkDirKey    ContextKey = "work_dir"
	EnvKey        ContextKey = "env"
)

func Lookup(name string) Tool {
	return allTools.Lookup(name)
}

var allTools Tools = Tools{
	tools: make(map[string]Tool),
}

func Default() Tools {
	return allTools
}

// RegisterTool makes a tool available to the LLM.
func RegisterTool(tool Tool) {
	allTools.RegisterTool(tool)
}

type Tools struct {
	tools map[string]Tool
}

func (t *Tools) Init() {
	t.tools = make(map[string]Tool)
}

func (t *Tools) Lookup(name string) Tool {
	return t.tools[name]
}

func (t *Tools) AllTools() []Tool {
	tools := make([]Tool, 0, len(t.tools))
	for _, tool := range t.tools {
		tools = append(tools, tool)
	}
	return tools
}

func (t *Tools) Names() []string {
	names := make([]string, 0, len(t.tools))
	for name := range t.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (t *Tools) RegisterTool(tool Tool) {
	name := tool.Name()

	if _, exists := t.tools[name]; exists {
		klog.V(2).Infof("tool already registered: %s, skipping", name)
		return
	}
	t.tools[name] = tool
}

type ToolCall struct {
	tool      Tool
	name      string
	arguments map[string]any
}

// Description returns a description of the tool call.
func (t *ToolCall) Description() string {
	if command, ok := t.arguments["command"]; ok {
		return command.(string)
	}
	var args []string
	for k, v := range t.arguments {
		args = append(args, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(args)
	return fmt.Sprintf("%s(%s)", t.name, strings.Join(args, ", "))
}

// ParseToolInvocation parses a request from the LLM into a tool call.
func (t *Tools) ParseToolInvocation(ctx context.Context, name string, arguments map[string]any) (*ToolCall, error) {
	tool := t.Lookup(name)
	if tool == nil {
		return nil, fmt.Errorf("tool %q not recognized", name)
	}

	return &ToolCall{
		tool:      tool,
		name:      name,
		arguments: arguments,
	}, nil
}

type InvokeToolOptions struct {
	WorkDir string

	// Kubeconfig is the path to the kubeconfig file.
	Kubeconfig string

	// Env allows passing environment variables to the tool.
	Env map[string]string
}

type ToolRequestEvent struct {
	CallID    string         `json:"id,omitempty"`
	Name      string         `json:"name,omitempty"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type ToolResponseEvent struct {
	CallID   string `json:"id,omitempty"`
	Response any    `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
}

// InvokeTool handles the execution of a single action
func (t *ToolCall) InvokeTool(ctx context.Context, opt InvokeToolOptions) (any, error) {
	recorder := journal.RecorderFromContext(ctx)

	callID := uuid.NewString()
	slackUserID := journal.SlackUserIDFromContext(ctx)

	_ = recorder.Write(ctx, &journal.Event{
		Timestamp:   time.Now(),
		SlackUserID: slackUserID,
		Action:      "tool-request",
		Payload: ToolRequestEvent{
			CallID:    callID,
			Name:      t.name,
			Arguments: t.arguments,
		},
	})

	ctx = context.WithValue(ctx, KubeconfigKey, opt.Kubeconfig)
	ctx = context.WithValue(ctx, WorkDirKey, opt.WorkDir)

	response, err := t.tool.Run(ctx, t.arguments)

	{
		ev := ToolResponseEvent{
			CallID:   callID,
			Response: response,
		}
		if err != nil {
			ev.Error = err.Error()
		}
		_ = recorder.Write(ctx, &journal.Event{
			Timestamp:   time.Now(),
			SlackUserID: slackUserID,
			Action:      "tool-response",
			Payload:     ev,
		})
	}

	return response, err
}

// ToolResultToMap converts an arbitrary result to a map[string]any
func ToolResultToMap(result any) (map[string]any, error) {
	if str, ok := result.(string); ok {
		return map[string]any{"content": str}, nil
	}

	if result == nil {
		return map[string]any{"content": ""}, nil
	}

	b, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("converting result to json: %w", err)
	}

	m := make(map[string]any)
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{"content": result}, nil
	}
	return m, nil
}

// GetTool returns the tool
func (t *ToolCall) GetTool() Tool {
	return t.tool
}

// ExpandShellVar expands shell variables and syntax
func ExpandShellVar(value string) (string, error) {
	if strings.Contains(value, "~") {
		if len(value) >= 2 && value[0] == '~' && os.IsPathSeparator(value[1]) {
			if runtime.GOOS == "windows" {
				value = filepath.Join(os.Getenv("USERPROFILE"), value[2:])
			} else {
				value = filepath.Join(os.Getenv("HOME"), value[2:])
			}
		}
	}
	return os.ExpandEnv(value), nil
}

func IsInteractiveCommand(command string) (bool, error) {
	words := strings.Fields(command)
	if len(words) == 0 {
		return false, nil
	}
	base := filepath.Base(words[0])
	if base != "kubectl" {
		return false, nil
	}

	isExec := strings.Contains(command, " exec ") && strings.Contains(command, " -it")
	isPortForward := strings.Contains(command, " port-forward ")
	isEdit := strings.Contains(command, " edit ")

	if isExec || isPortForward || isEdit {
		return true, fmt.Errorf("interactive mode not supported for kubectl, please use non-interactive commands")
	}
	return false, nil
}

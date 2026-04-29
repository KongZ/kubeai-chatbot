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

package agent

import (
	"context"
	"testing"

	"github.com/KongZ/kubeai-chatbot/gollm"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/KongZ/kubeai-chatbot/pkg/sessions"
	"github.com/KongZ/kubeai-chatbot/pkg/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeWaitTool is a minimal Tool that also implements ToolWithWaitMessage.
type fakeWaitTool struct {
	waitMsg string
}

func (f *fakeWaitTool) Name() string        { return "fake-wait-tool" }
func (f *fakeWaitTool) Description() string { return "fake" }
func (f *fakeWaitTool) FunctionDefinition() *gollm.FunctionDefinition {
	return &gollm.FunctionDefinition{Name: f.Name()}
}
func (f *fakeWaitTool) Run(_ context.Context, _ map[string]any) (any, error) {
	return &tools.ExecResult{Command: "fake", Stdout: "ok"}, nil
}
func (f *fakeWaitTool) IsInteractive(_ map[string]any) (bool, error) { return false, nil }
func (f *fakeWaitTool) CheckModifiesResource(_ map[string]any) string { return "no" }
func (f *fakeWaitTool) WaitMessage() string                           { return f.waitMsg }

// fakeRegularTool is a Tool that does NOT implement ToolWithWaitMessage.
type fakeRegularTool struct{}

func (f *fakeRegularTool) Name() string        { return "fake-regular-tool" }
func (f *fakeRegularTool) Description() string { return "fake regular" }
func (f *fakeRegularTool) FunctionDefinition() *gollm.FunctionDefinition {
	return &gollm.FunctionDefinition{Name: f.Name()}
}
func (f *fakeRegularTool) Run(_ context.Context, _ map[string]any) (any, error) {
	return &tools.ExecResult{Command: "fake-regular", Stdout: "ok"}, nil
}
func (f *fakeRegularTool) IsInteractive(_ map[string]any) (bool, error) { return false, nil }
func (f *fakeRegularTool) CheckModifiesResource(_ map[string]any) string { return "no" }

func makeMinimalAgent(t *testing.T) *Agent {
	t.Helper()
	a := &Agent{
		Output: make(chan any, 20),
		Session: &api.Session{
			ID:               "dispatch-test",
			AgentState:       api.AgentStateIdle,
			ChatMessageStore: sessions.NewInMemoryChatStore(),
		},
	}
	a.Tools.Init()
	return a
}

func drainMessages(ch <-chan any) []*api.Message {
	var msgs []*api.Message
	for {
		select {
		case raw := <-ch:
			if m, ok := raw.(*api.Message); ok {
				msgs = append(msgs, m)
			}
		default:
			return msgs
		}
	}
}

// TestDispatchToolCalls_EmitsWaitMessage verifies that an agent-text message is
// sent before executing a tool that implements ToolWithWaitMessage.
func TestDispatchToolCalls_EmitsWaitMessage(t *testing.T) {
	a := makeMinimalAgent(t)
	fake := &fakeWaitTool{waitMsg: "please wait..."}
	a.Tools.RegisterTool(fake)

	toolCall, err := a.Tools.ParseToolInvocation(context.Background(), "fake-wait-tool", map[string]any{})
	require.NoError(t, err)

	a.pendingFunctionCalls = []ToolCallAnalysis{
		{
			FunctionCall:   gollm.FunctionCall{Name: "fake-wait-tool"},
			ParsedToolCall: toolCall,
		},
	}

	require.NoError(t, a.DispatchToolCalls(context.Background()))

	msgs := drainMessages(a.Output)
	var waitMsgFound bool
	for _, m := range msgs {
		if m.Source == api.MessageSourceAgent && m.Type == api.MessageTypeText {
			if payload, ok := m.Payload.(string); ok && payload == "please wait..." {
				waitMsgFound = true
			}
		}
	}
	assert.True(t, waitMsgFound, "expected wait message in output before tool execution")
}

// TestDispatchToolCalls_NoWaitMessageForRegularTool verifies that a tool that does
// NOT implement ToolWithWaitMessage does not produce an extra text message.
func TestDispatchToolCalls_NoWaitMessageForRegularTool(t *testing.T) {
	a := makeMinimalAgent(t)
	a.Tools.RegisterTool(&fakeRegularTool{})

	toolCall, err := a.Tools.ParseToolInvocation(context.Background(), "fake-regular-tool", map[string]any{})
	require.NoError(t, err)

	a.pendingFunctionCalls = []ToolCallAnalysis{
		{
			FunctionCall:   gollm.FunctionCall{Name: "fake-regular-tool"},
			ParsedToolCall: toolCall,
		},
	}

	require.NoError(t, a.DispatchToolCalls(context.Background()))

	msgs := drainMessages(a.Output)
	for _, m := range msgs {
		if m.Source == api.MessageSourceAgent && m.Type == api.MessageTypeText {
			t.Errorf("unexpected agent text message for regular tool: %v", m.Payload)
		}
	}
}

// TestDispatchToolCalls_WaitMessage_WaitMessageBeforeResponse verifies ordering:
// the wait message appears before the tool-call-response in the output stream.
func TestDispatchToolCalls_WaitMessage_WaitMessageBeforeResponse(t *testing.T) {
	a := makeMinimalAgent(t)
	fake := &fakeWaitTool{waitMsg: "consulting..."}
	a.Tools.RegisterTool(fake)

	toolCall, err := a.Tools.ParseToolInvocation(context.Background(), "fake-wait-tool", map[string]any{})
	require.NoError(t, err)

	a.pendingFunctionCalls = []ToolCallAnalysis{
		{
			FunctionCall:   gollm.FunctionCall{Name: "fake-wait-tool"},
			ParsedToolCall: toolCall,
		},
	}

	require.NoError(t, a.DispatchToolCalls(context.Background()))

	msgs := drainMessages(a.Output)
	var waitIdx, responseIdx int = -1, -1
	for i, m := range msgs {
		if m.Source == api.MessageSourceAgent && m.Type == api.MessageTypeText {
			if payload, ok := m.Payload.(string); ok && payload == "consulting..." {
				waitIdx = i
			}
		}
		if m.Source == api.MessageSourceAgent && m.Type == api.MessageTypeToolCallResponse {
			responseIdx = i
		}
	}

	require.NotEqual(t, -1, waitIdx, "wait message not found in output")
	require.NotEqual(t, -1, responseIdx, "tool-call-response not found in output")
	assert.Less(t, waitIdx, responseIdx, "wait message should appear before tool-call-response")
}

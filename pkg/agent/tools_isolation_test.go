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
	"github.com/KongZ/kubeai-chatbot/internal/mocks"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/KongZ/kubeai-chatbot/pkg/sessions"
	"github.com/KongZ/kubeai-chatbot/pkg/tools"
	"go.uber.org/mock/gomock"
)

// TestAgent_ToolsIsolation verifies that each agent has its own isolated Tools instance
// and that registering tools in one agent doesn't affect other agents.
func TestAgent_ToolsIsolation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create two agents with separate Tools instances
	agent1 := &Agent{}
	agent1.Tools.Init()

	agent2 := &Agent{}
	agent2.Tools.Init()

	// Create a mock tool
	mockTool1 := mocks.NewMockTool(ctrl)
	mockTool1.EXPECT().Name().Return("custom-tool-1").AnyTimes()
	mockTool1.EXPECT().FunctionDefinition().Return(&gollm.FunctionDefinition{
		Name:        "custom-tool-1",
		Description: "Custom tool for agent 1",
	}).AnyTimes()

	mockTool2 := mocks.NewMockTool(ctrl)
	mockTool2.EXPECT().Name().Return("custom-tool-2").AnyTimes()
	mockTool2.EXPECT().FunctionDefinition().Return(&gollm.FunctionDefinition{
		Name:        "custom-tool-2",
		Description: "Custom tool for agent 2",
	}).AnyTimes()

	// Register different tools in each agent
	agent1.Tools.RegisterTool(mockTool1)
	agent2.Tools.RegisterTool(mockTool2)

	// Verify agent1 has only its tool
	if agent1.Tools.Lookup("custom-tool-1") == nil {
		t.Error("agent1 should have custom-tool-1")
	}
	if agent1.Tools.Lookup("custom-tool-2") != nil {
		t.Error("agent1 should NOT have custom-tool-2")
	}

	// Verify agent2 has only its tool
	if agent2.Tools.Lookup("custom-tool-2") == nil {
		t.Error("agent2 should have custom-tool-2")
	}
	if agent2.Tools.Lookup("custom-tool-1") != nil {
		t.Error("agent2 should NOT have custom-tool-1")
	}

	// Verify tool counts
	if len(agent1.Tools.Names()) != 1 {
		t.Errorf("agent1 should have 1 tool, got %d", len(agent1.Tools.Names()))
	}
	if len(agent2.Tools.Names()) != 1 {
		t.Errorf("agent2 should have 1 tool, got %d", len(agent2.Tools.Names()))
	}

	t.Log("✓ Tools are properly isolated between agents")
}

// TestAgent_Init_RegistersKubectlPerAgent verifies that kubectl tool is registered
// independently for each agent during Init().
func TestAgent_Init_RegistersKubectlPerAgent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	// Helper to create and initialize an agent
	createAgent := func(sessionID string) *Agent {
		mockClient := mocks.NewMockClient(ctrl)
		mockChat := mocks.NewMockChat(ctrl)

		mockClient.EXPECT().StartChat(gomock.Any(), gomock.Any()).Return(mockChat)
		mockChat.EXPECT().Initialize(gomock.Any()).Return(nil)
		mockChat.EXPECT().SetFunctionDefinitions(gomock.Any()).Return(nil)

		session := &api.Session{
			ID:               sessionID,
			AgentState:       api.AgentStateIdle,
			ChatMessageStore: sessions.NewInMemoryChatStore(),
		}

		agent := &Agent{
			SessionBackend: "memory",
			LLM:            mockClient,
			Session:        session,
		}
		agent.Tools.Init()

		if err := agent.Init(ctx); err != nil {
			t.Fatalf("Init failed for session %s: %v", sessionID, err)
		}

		return agent
	}

	// Create multiple agents
	agent1 := createAgent("session-1")
	agent2 := createAgent("session-2")
	agent3 := createAgent("session-3")

	// Verify each agent has kubectl tool registered
	agents := []*Agent{agent1, agent2, agent3}
	for i, agent := range agents {
		if agent.Tools.Lookup("kubectl") == nil {
			t.Errorf("agent %d should have kubectl tool registered", i+1)
		}

		// Verify each agent has exactly 1 tool (kubectl)
		toolCount := len(agent.Tools.Names())
		if toolCount != 1 {
			t.Errorf("agent %d should have 1 tool, got %d: %v", i+1, toolCount, agent.Tools.Names())
		}
	}

	t.Log("✓ kubectl tool is properly registered per agent")
}

// TestAgent_Init_NoSharedToolsState verifies that agents don't share Tools state
// even when initialized concurrently.
func TestAgent_Init_NoSharedToolsState(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	// Create multiple agents concurrently
	const numAgents = 10
	agents := make([]*Agent, numAgents)
	errors := make(chan error, numAgents)

	for i := 0; i < numAgents; i++ {
		go func(idx int) {
			mockClient := mocks.NewMockClient(ctrl)
			mockChat := mocks.NewMockChat(ctrl)

			mockClient.EXPECT().StartChat(gomock.Any(), gomock.Any()).Return(mockChat)
			mockChat.EXPECT().Initialize(gomock.Any()).Return(nil)
			mockChat.EXPECT().SetFunctionDefinitions(gomock.Any()).Return(nil)

			session := &api.Session{
				ID:               "session-" + string(rune(idx)),
				AgentState:       api.AgentStateIdle,
				ChatMessageStore: sessions.NewInMemoryChatStore(),
			}

			agent := &Agent{
				SessionBackend: "memory",
				LLM:            mockClient,
				Session:        session,
			}
			agent.Tools.Init()

			if err := agent.Init(ctx); err != nil {
				errors <- err
				return
			}

			agents[idx] = agent
			errors <- nil
		}(i)
	}

	// Wait for all agents to initialize
	for i := 0; i < numAgents; i++ {
		if err := <-errors; err != nil {
			t.Fatalf("Agent initialization failed: %v", err)
		}
	}

	// Verify each agent has its own Tools instance
	for i := 0; i < numAgents; i++ {
		if agents[i] == nil {
			t.Fatalf("agent %d is nil", i)
		}

		// Each agent should have kubectl tool
		if agents[i].Tools.Lookup("kubectl") == nil {
			t.Errorf("agent %d missing kubectl tool", i)
		}

		// Verify no shared state by checking memory addresses
		for j := i + 1; j < numAgents; j++ {
			if &agents[i].Tools == &agents[j].Tools {
				t.Errorf("agents %d and %d share the same Tools instance", i, j)
			}
		}
	}

	t.Logf("✓ %d agents initialized concurrently with isolated Tools", numAgents)
}

// TestTools_RegisterTool_DuplicateHandling verifies that registering
// the same tool twice doesn't cause a panic.
func TestTools_RegisterTool_DuplicateHandling(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	toolsInstance := tools.Tools{}
	toolsInstance.Init()

	mockTool := mocks.NewMockTool(ctrl)
	mockTool.EXPECT().Name().Return("test-tool").AnyTimes()

	// First registration should succeed
	toolsInstance.RegisterTool(mockTool)

	// Second registration should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("RegisterTool panicked on duplicate: %v", r)
		}
	}()

	toolsInstance.RegisterTool(mockTool)

	// Verify tool is still registered
	if toolsInstance.Lookup("test-tool") == nil {
		t.Error("tool should still be registered after duplicate registration attempt")
	}

	// Verify only one instance
	if len(toolsInstance.Names()) != 1 {
		t.Errorf("expected 1 tool, got %d", len(toolsInstance.Names()))
	}

	t.Log("✓ Duplicate tool registration handled gracefully")
}

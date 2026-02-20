// Copyright 2026 https://github.com/KongZ/kubeai-chatbot
// Portions Copyright 2025 Google LLC
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
	"fmt"
	"sync"

	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/KongZ/kubeai-chatbot/pkg/sessions"
	"k8s.io/klog/v2"
)

// Factory is a function that creates a new Agent instance.
type Factory func(context.Context) (*Agent, error)

// AgentManager manages the lifecycle of agents and their sessions.
type AgentManager struct {
	factory        Factory
	sessionManager *sessions.SessionManager
	agents         map[string]*Agent // sessionID -> agent
	mu             sync.RWMutex
	onAgentCreated func(*Agent)
}

// NewAgentManager creates a new Manager.
func NewAgentManager(factory Factory, sessionManager *sessions.SessionManager) *AgentManager {
	return &AgentManager{
		factory:        factory,
		sessionManager: sessionManager,
		agents:         make(map[string]*Agent),
	}
}

// SetAgentCreatedCallback sets the callback to be called when a new agent is created.
// It also calls the callback immediately for all currently active agents.
func (sm *AgentManager) SetAgentCreatedCallback(cb func(*Agent)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onAgentCreated = cb
	for _, agent := range sm.agents {
		cb(agent)
	}
}

// GetAgent returns the agent for the given session ID, loading it if necessary.
func (sm *AgentManager) GetAgent(ctx context.Context, sessionID string) (*Agent, error) {
	sm.mu.RLock()
	agent, ok := sm.agents[sessionID]
	sm.mu.RUnlock()

	if ok {
		return agent, nil
	}

	session, err := sm.sessionManager.FindSessionByID(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	newAgent, err := sm.factory(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating agent: %w", err)
	}

	return sm.startAgent(ctx, session, newAgent)
}

// Close closes all active agents.
func (sm *AgentManager) Close() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, agent := range sm.agents {
		klog.Infof("Closing agent for session %s", id)
		if err := agent.Close(); err != nil {
			klog.Errorf("Error closing agent %s: %v", id, err)
		}
	}
	// Clear the map
	sm.agents = make(map[string]*Agent)
	return nil
}

// ListSessions delegates to the underlying store.
func (sm *AgentManager) ListSessions() ([]*api.Session, error) {
	return sm.sessionManager.ListSessions()
}

// FindSessionByID delegates to the underlying store.
func (sm *AgentManager) FindSessionByID(id string) (*api.Session, error) {
	return sm.sessionManager.FindSessionByID(id)
}

// DeleteSession delegates to the underlying store and closes the active agent if any.
func (sm *AgentManager) DeleteSession(id string) error {
	sm.mu.Lock()
	if agent, ok := sm.agents[id]; ok {
		_ = agent.Close()
		delete(sm.agents, id)
	}
	sm.mu.Unlock()
	return sm.sessionManager.DeleteSession(id)
}

// UpdateLastAccessed delegates to the underlying store.
func (sm *AgentManager) UpdateLastAccessed(session *api.Session) error {
	return sm.sessionManager.UpdateLastAccessed(session)
}

func (sm *AgentManager) startAgent(ctx context.Context, session *api.Session, agent *Agent) (*Agent, error) {
	agent.Session = session

	if err := agent.Init(ctx); err != nil {
		return nil, fmt.Errorf("initializing agent: %w", err)
	}

	agentCtx, cancel := context.WithCancel(context.Background())
	agent.cancel = cancel

	if err := agent.Run(agentCtx, ""); err != nil {
		cancel()
		return nil, fmt.Errorf("starting agent loop: %w", err)
	}

	sm.mu.Lock()
	sm.agents[session.ID] = agent
	if sm.onAgentCreated != nil {
		sm.onAgentCreated(agent)
	}
	sm.mu.Unlock()

	return agent, nil
}

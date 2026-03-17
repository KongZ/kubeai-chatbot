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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KongZ/kubeai-chatbot/gollm"
	"github.com/KongZ/kubeai-chatbot/internal/mocks"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/KongZ/kubeai-chatbot/pkg/sessions"
	"github.com/KongZ/kubeai-chatbot/pkg/skills"
	"go.uber.org/mock/gomock"
)

func TestBuildQueryWithSkills_NilRegistry(t *testing.T) {
	a := &Agent{SkillsRegistry: nil}
	got := a.buildQueryWithSkills("my query")
	if got != "my query" {
		t.Fatalf("expected query unchanged, got %q", got)
	}
}

func TestBuildQueryWithSkills_EmptyRegistry(t *testing.T) {
	a := &Agent{SkillsRegistry: &skills.Registry{}}
	got := a.buildQueryWithSkills("my query")
	if got != "my query" {
		t.Fatalf("expected query unchanged, got %q", got)
	}
}

func TestBuildQueryWithSkills_NoMatch(t *testing.T) {
	r := &skills.Registry{}
	r.Register(skills.Skill{Name: "crashloop", Triggers: []string{"crashloop"}, Instructions: "Do X"})
	a := &Agent{SkillsRegistry: r}
	got := a.buildQueryWithSkills("everything looks fine")
	if got != "everything looks fine" {
		t.Fatalf("expected query unchanged, got %q", got)
	}
}

func TestBuildQueryWithSkills_MatchPrependsInstructions(t *testing.T) {
	r := &skills.Registry{}
	r.Register(skills.Skill{Name: "crashloop", Triggers: []string{"crashloop"}, Instructions: "Step 1: describe\nStep 2: logs"})
	a := &Agent{SkillsRegistry: r}
	got := a.buildQueryWithSkills("my pod is in crashloop")
	if !strings.Contains(got, "## Skill: crashloop") {
		t.Fatalf("expected skill header in output, got %q", got)
	}
	if !strings.Contains(got, "Step 1: describe") {
		t.Fatalf("expected skill instructions in output, got %q", got)
	}
	if !strings.HasSuffix(got, "my pod is in crashloop") {
		t.Fatalf("expected original query at end, got %q", got)
	}
}

func TestBuildQueryWithSkills_SkillWithNoInstructions(t *testing.T) {
	r := &skills.Registry{}
	r.Register(skills.Skill{Name: "empty-skill", Triggers: []string{"trigger"}, Instructions: ""})
	a := &Agent{SkillsRegistry: r}
	got := a.buildQueryWithSkills("trigger word here")
	// skill has no instructions — nothing should be prepended
	if got != "trigger word here" {
		t.Fatalf("expected query unchanged for skill with no instructions, got %q", got)
	}
}

func TestBuildQueryWithSkills_MultipleMatches(t *testing.T) {
	r := &skills.Registry{}
	r.Register(skills.Skill{Name: "skill-a", Triggers: []string{"alpha"}, Instructions: "Instructions A"})
	r.Register(skills.Skill{Name: "skill-b", Triggers: []string{"beta"}, Instructions: "Instructions B"})
	a := &Agent{SkillsRegistry: r}
	got := a.buildQueryWithSkills("alpha and beta issue")
	if !strings.Contains(got, "Instructions A") {
		t.Fatalf("expected skill-a instructions, got %q", got)
	}
	if !strings.Contains(got, "Instructions B") {
		t.Fatalf("expected skill-b instructions, got %q", got)
	}
	if !strings.HasSuffix(got, "alpha and beta issue") {
		t.Fatalf("expected original query at end, got %q", got)
	}
}

func TestHandleMetaQuery(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		query        string
		expectations func(t *testing.T) *Agent
		verify       func(t *testing.T, a *Agent, answer string)
		expect       string
	}{
		{
			name:   "clear (shows store before/after with mocked model + tool outputs)",
			query:  "clear",
			expect: "Cleared the conversation.",
			expectations: func(t *testing.T) *Agent {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)

				store := sessions.NewInMemoryChatStore()

				chat := mocks.NewMockChat(ctrl)
				chat.EXPECT().Initialize([]*api.Message{}).Times(1)

				mt := mocks.NewMockTool(ctrl)
				mt.EXPECT().Name().Return("mock namespace tool").AnyTimes()
				mt.EXPECT().FunctionDefinition().Return(&gollm.FunctionDefinition{
					Name:        "mock namespace tool",
					Description: "Inspect current Kubernetes namespace",
				}).AnyTimes()

				const toolResult = `{"namespace":"test-namespace"}`

				mt.EXPECT().Run(gomock.Any(), gomock.Any()).
					Return(toolResult, nil).Times(1)

				const modelText = "The current namespace is test-namespace."

				now := time.Now()
				// user message
				_ = store.AddChatMessage(&api.Message{
					ID:        "u1",
					Source:    api.MessageSourceUser,
					Type:      api.MessageTypeText,
					Payload:   "What's my current namespace?",
					Timestamp: now,
				})

				// model response
				_ = store.AddChatMessage(&api.Message{
					ID:        "a1",
					Source:    api.MessageSourceAgent,
					Type:      api.MessageTypeText,
					Payload:   modelText,
					Timestamp: now,
				})

				// tool call result
				if out, err := mt.Run(ctx, map[string]any{}); err == nil {
					_ = store.AddChatMessage(&api.Message{
						ID:        "t1",
						Source:    api.MessageSourceAgent,
						Type:      api.MessageTypeText,
						Payload:   out,
						Timestamp: now,
					})
				} else {
					t.Fatalf("mock tool run failed: %v", err)
				}

				if got := len(store.ChatMessages()); got != 3 {
					t.Fatalf("precondition: expected 3 messages before clear, got %d", got)
				}

				a := &Agent{llmChat: chat}
				a.Session = &api.Session{
					ID:               "test-session",
					Name:             "Test Session",
					ProviderID:       "p",
					ModelID:          "m",
					SlackUserID:      "U123",
					AgentState:       api.AgentStateIdle,
					CreatedAt:        now,
					LastModified:     now,
					ChatMessageStore: store,
				}

				return a
			},
			verify: func(t *testing.T, a *Agent, _ string) {
				if got := len(a.Session.ChatMessageStore.ChatMessages()); got != 0 {
					t.Fatalf("expected store to be empty after clear, got %d", got)
				}
			},
		},
		{
			name:   "model",
			query:  "model",
			expect: "Current model is `test-model`",
			expectations: func(t *testing.T) *Agent {
				a := &Agent{Model: "test-model"}
				a.Session = &api.Session{
					ID:           "model-session",
					Name:         "Model Session",
					ProviderID:   "p",
					ModelID:      "m",
					SlackUserID:  "U123",
					AgentState:   api.AgentStateIdle,
					CreatedAt:    time.Now(),
					LastModified: time.Now(),
				}
				return a
			},
		},
		{
			name:   "models",
			query:  "models",
			expect: "Available models:\n\n  - a\n  - b\n\n",
			expectations: func(t *testing.T) *Agent {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)
				llm := mocks.NewMockClient(ctrl)
				llm.EXPECT().ListModels(ctx).Return([]string{"a", "b"}, nil)

				a := &Agent{LLM: llm}
				a.Session = &api.Session{
					ID:           "models-session",
					Name:         "Models Session",
					ProviderID:   "p",
					ModelID:      "m",
					SlackUserID:  "U123",
					AgentState:   api.AgentStateIdle,
					CreatedAt:    time.Now(),
					LastModified: time.Now(),
				}
				return a
			},
		},
		{
			name:   "tools",
			query:  "tools",
			expect: "Available tools:",
			expectations: func(t *testing.T) *Agent {
				ctrl := gomock.NewController(t)
				t.Cleanup(ctrl.Finish)

				mt := mocks.NewMockTool(ctrl)
				mt.EXPECT().Name().Return("mocktool").AnyTimes()
				mt.EXPECT().FunctionDefinition().Return(&gollm.FunctionDefinition{
					Name:        "mocktool",
					Description: "Mocked tool for tests",
				}).AnyTimes()

				a := &Agent{}

				a.Tools.Init()
				a.Tools.RegisterTool(mt)
				a.Session = &api.Session{
					ID:           "tools-session",
					Name:         "Tools Session",
					ProviderID:   "p",
					ModelID:      "m",
					SlackUserID:  "U123",
					AgentState:   api.AgentStateIdle,
					CreatedAt:    time.Now(),
					LastModified: time.Now(),
				}
				return a
			},
			verify: func(t *testing.T, _ *Agent, answer string) {
				if !strings.Contains(answer, "mocktool") {
					t.Fatalf("expected kubectl tool in output: %q", answer)
				}
			},
		},
		{
			name:   "session",
			query:  "session",
			expect: "Session ID:",
			expectations: func(t *testing.T) *Agent {
				home := t.TempDir()
				t.Setenv("HOME", home)

				manager, err := sessions.NewSessionManager("memory")
				if err != nil {
					t.Fatalf("creating session manager: %v", err)
				}
				sess, err := manager.NewSession(sessions.Metadata{ProviderID: "p", ModelID: "m", SlackUserID: "U123"})
				if err != nil {
					t.Fatalf("creating session: %v", err)
				}
				a := &Agent{ChatMessageStore: sess.ChatMessageStore, SessionBackend: "filesystem"}
				a.Session = sess
				return a
			},
			verify: func(t *testing.T, _ *Agent, answer string) {
				if !strings.Contains(answer, "ID:") {
					t.Fatalf("expected session info, got %q", answer)
				}
			},
		},
		{
			name:   "sessions",
			query:  "sessions",
			expect: "Available sessions:",
			expectations: func(t *testing.T) *Agent {
				home := t.TempDir()
				t.Setenv("HOME", home)

				manager, err := sessions.NewSessionManager("memory")
				if err != nil {
					t.Fatalf("creating session manager: %v", err)
				}
				if _, err := manager.NewSession(sessions.Metadata{ProviderID: "p1", ModelID: "m1", SlackUserID: "U123"}); err != nil {
					t.Fatalf("creating session: %v", err)
				}
				if _, err := manager.NewSession(sessions.Metadata{ProviderID: "p2", ModelID: "m2", SlackUserID: "U123"}); err != nil {
					t.Fatalf("creating session: %v", err)
				}

				a := &Agent{SessionBackend: "memory"}
				a.Session = &api.Session{
					ID:               "sessions-list",
					Name:             "Sessions List",
					ProviderID:       "p",
					ModelID:          "m",
					SlackUserID:      "U123",
					AgentState:       api.AgentStateIdle,
					CreatedAt:        time.Now(),
					LastModified:     time.Now(),
					ChatMessageStore: sessions.NewInMemoryChatStore(),
				}
				return a
			},
			verify: func(t *testing.T, _ *Agent, answer string) {
				if !strings.Contains(answer, "Available sessions:") {
					t.Fatalf("unexpected answer: %q", answer)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.expectations(t)
			ans, handled, err := a.handleMetaQuery(ctx, tt.query)
			if err != nil {
				t.Fatalf("handleMetaQuery returned error: %v", err)
			}
			if !handled {
				t.Fatalf("expected query %q to be handled", tt.query)
			}
			if tt.expect != "" && !strings.Contains(ans, tt.expect) {
				t.Fatalf("expected %q to contain %q", ans, tt.expect)
			}
			if tt.verify != nil {
				tt.verify(t, a, ans)
			}
		})
	}
}

func TestAgent_NewSession(t *testing.T) {
	// Setup
	manager, err := sessions.NewSessionManager("memory")
	if err != nil {
		t.Fatalf("creating session manager: %v", err)
	}

	// Create initial session
	sess1, err := manager.NewSession(sessions.Metadata{ProviderID: "p", ModelID: "m", SlackUserID: "U123"})
	if err != nil {
		t.Fatalf("creating session 1: %v", err)
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := mocks.NewMockClient(ctrl)
	mockChat := mocks.NewMockChat(ctrl)

	mockClient.EXPECT().StartChat(gomock.Any(), gomock.Any()).Return(mockChat)
	mockChat.EXPECT().Initialize(gomock.Any()).Return(nil)

	a := &Agent{
		SessionBackend: "memory",
		LLM:            mockClient,
		Model:          "m",
		Provider:       "p",
	}
	a.Tools.Init()
	a.Session = sess1

	// Call NewSession
	newID, err := a.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if newID == sess1.ID {
		t.Fatalf("expected new session ID to be different from old one")
	}

	if a.Session.ID != newID {
		t.Fatalf("agent session ID mismatch: got %s, want %s", a.Session.ID, newID)
	}
}

func TestAgent_LoadSession_ResetsState(t *testing.T) {
	// Setup
	manager, err := sessions.NewSessionManager("memory")
	if err != nil {
		t.Fatalf("creating session manager: %v", err)
	}

	// Create a session in "running" state
	sess1, err := manager.NewSession(sessions.Metadata{ProviderID: "p", ModelID: "m", SlackUserID: "U123"})
	if err != nil {
		t.Fatalf("creating session 1: %v", err)
	}
	sess1.AgentState = api.AgentStateRunning
	if err := manager.UpdateLastAccessed(sess1); err != nil {
		t.Fatalf("updating session: %v", err)
	}

	a := &Agent{
		SessionBackend: "memory",
	}
	a.Model = "m"
	a.Provider = "p"

	// Load the session
	if err := a.LoadSession(sess1.ID); err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}

	// Verify state is reset to idle
	if a.Session.AgentState != api.AgentStateIdle {
		t.Errorf("expected agent state to be idle, got %s", a.Session.AgentState)
	}
}

func TestAgent_Init_CreatesSessionInStore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mocks.NewMockClient(ctrl)
	mockChat := mocks.NewMockChat(ctrl)

	// Expect StartChat to be called
	mockClient.EXPECT().StartChat(gomock.Any(), gomock.Any()).Return(mockChat)
	// Expect Initialize to be called
	mockChat.EXPECT().Initialize(gomock.Any()).Return(nil)
	// Expect SetFunctionDefinitions to be called
	mockChat.EXPECT().SetFunctionDefinitions(gomock.Any()).Return(nil)

	// Setup
	session := &api.Session{
		ID:               "test-session",
		Name:             "Test Session",
		ProviderID:       "p",
		ModelID:          "m",
		SlackUserID:      "U123",
		AgentState:       api.AgentStateIdle,
		CreatedAt:        time.Now(),
		LastModified:     time.Now(),
		ChatMessageStore: sessions.NewInMemoryChatStore(),
	}

	a := &Agent{
		SessionBackend: "memory",
		// Init requires these
		Input:   make(chan any),
		Output:  make(chan any),
		LLM:     mockClient,
		Session: session,
	}
	a.Tools.Init()

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if a.Session != session {
		t.Errorf("expected agent to use provided session")
	}
}

func writeKubeconfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "kubeconfig-*.yaml")
	if err != nil {
		t.Fatalf("creating temp kubeconfig: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing kubeconfig: %v", err)
	}
	return f.Name()
}

func kubeconfigWithServers(reachableURL, unreachableURL string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: %s
  name: reachable-cluster
- cluster:
    server: %s
  name: unreachable-cluster
contexts:
- context:
    cluster: reachable-cluster
    user: test-user
  name: reachable-context
- context:
    cluster: unreachable-cluster
    user: test-user
  name: unreachable-context
current-context: reachable-context
users:
- name: test-user
  user: {}
`, reachableURL, unreachableURL)
}

func TestLoadKubeContextNames_MissingFile(t *testing.T) {
	names, err := loadKubeContextNames(context.Background(), "/does/not/exist/kubeconfig.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if names != nil {
		t.Fatalf("expected nil names for missing file, got: %v", names)
	}
}

func TestLoadKubeContextNames_MalformedYAML(t *testing.T) {
	path := writeKubeconfig(t, ":: this is not valid yaml ::")
	_, err := loadKubeContextNames(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

func TestLoadKubeContextNames_EmptyContexts(t *testing.T) {
	path := writeKubeconfig(t, "apiVersion: v1\nkind: Config\ncontexts: []\n")
	names, err := loadKubeContextNames(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no contexts, got: %v", names)
	}
}

func TestLoadKubeContextNames_ConnectivityCheck(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not in PATH, skipping connectivity test")
	}

	// reachable: a local HTTP server that responds 200 to /readyz
	reachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer reachable.Close()

	// unreachable: start and immediately close so connections are refused
	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachableURL := unreachable.URL
	unreachable.Close()

	path := writeKubeconfig(t, kubeconfigWithServers(reachable.URL, unreachableURL))

	names, err := loadKubeContextNames(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 1 || names[0] != "reachable-context" {
		t.Fatalf("expected [reachable-context], got: %v", names)
	}
}

func TestAgent_NewSession_NoDeadlock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mocks.NewMockClient(ctrl)
	mockChat := mocks.NewMockChat(ctrl)

	// Expect StartChat to be called for initial session and new session
	mockClient.EXPECT().StartChat(gomock.Any(), gomock.Any()).Return(mockChat).AnyTimes()

	// Expect Initialize to be called for initial session AND new session (and maybe more?)
	mockChat.EXPECT().Initialize(gomock.Any()).Return(nil).AnyTimes()
	// Expect SetFunctionDefinitions to be called for initial session only
	mockChat.EXPECT().SetFunctionDefinitions(gomock.Any()).Return(nil).Times(1)

	// Setup
	session := &api.Session{
		ID:               "initial-session",
		Name:             "Initial Session",
		ProviderID:       "p",
		ModelID:          "m",
		SlackUserID:      "U123",
		AgentState:       api.AgentStateIdle,
		CreatedAt:        time.Now(),
		LastModified:     time.Now(),
		ChatMessageStore: sessions.NewInMemoryChatStore(),
	}

	a := &Agent{
		SessionBackend: "memory",
		Input:          make(chan any),
		Output:         make(chan any),
		LLM:            mockClient,
		Session:        session,
		Model:          "m",
		Provider:       "p",
	}
	a.Tools.Init()

	// Init
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Create new session
	// This should not deadlock
	done := make(chan struct{})
	go func() {
		if _, err := a.NewSession(); err != nil {
			t.Errorf("NewSession failed: %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("NewSession timed out (potential deadlock)")
	}
}

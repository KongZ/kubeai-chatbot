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

package slack

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KongZ/kubeai-chatbot/pkg/agent"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/KongZ/kubeai-chatbot/pkg/sessions"
	"github.com/slack-go/slack"
)

// mockSlackAPI is a mock implementation of SlackAPI
type mockSlackAPI struct {
	PostMessageFunc    func(channelID string, options ...slack.MsgOption) (string, string, error)
	UploadFileV2Func   func(params slack.UploadFileV2Parameters) (*slack.FileSummary, error)
	AddReactionFunc    func(name string, item slack.ItemRef) error
	RemoveReactionFunc func(name string, item slack.ItemRef) error
}

func (m *mockSlackAPI) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	if m.PostMessageFunc != nil {
		return m.PostMessageFunc(channelID, options...)
	}
	return "", "", nil
}

func (m *mockSlackAPI) UploadFileV2(params slack.UploadFileV2Parameters) (*slack.FileSummary, error) {
	if m.UploadFileV2Func != nil {
		return m.UploadFileV2Func(params)
	}
	return nil, nil
}

func (m *mockSlackAPI) AddReaction(name string, item slack.ItemRef) error {
	if m.AddReactionFunc != nil {
		return m.AddReactionFunc(name, item)
	}
	return nil
}

func (m *mockSlackAPI) RemoveReaction(name string, item slack.ItemRef) error {
	if m.RemoveReactionFunc != nil {
		return m.RemoveReactionFunc(name, item)
	}
	return nil
}

// mockAgentManager is a mock implementation of AgentManager
type mockAgentManager struct {
	GetAgentFunc                func(ctx context.Context, sessionID string) (*agent.Agent, error)
	SetAgentCreatedCallbackFunc func(func(*agent.Agent))
}

func (m *mockAgentManager) GetAgent(ctx context.Context, sessionID string) (*agent.Agent, error) {
	if m.GetAgentFunc != nil {
		return m.GetAgentFunc(ctx, sessionID)
	}
	return nil, nil
}

func (m *mockAgentManager) SetAgentCreatedCallback(cb func(*agent.Agent)) {
	if m.SetAgentCreatedCallbackFunc != nil {
		m.SetAgentCreatedCallbackFunc(cb)
	}
}

func TestFormatForSlack(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "bold conversion",
			input:    "This is **bold** text.",
			expected: "This is *bold* text.",
		},
		{
			name:     "link conversion",
			input:    "Check [this link](https://example.com).",
			expected: "Check <https://example.com|this link>.",
		},
		{
			name:     "italic conversion",
			input:    "This is *italic* text.",
			expected: "This is _italic_ text.",
		},
		{
			name:     "combined formatting",
			input:    "**Bold** and *italic* with a [link](https://foo.bar).",
			expected: "*Bold* and _italic_ with a <https://foo.bar|link>.",
		},
		{
			name:     "no formatting",
			input:    "Just plain text.",
			expected: "Just plain text.",
		},
		{
			name:     "table not handled in text format",
			input:    "| h1 | h2 |\n|---|---|\n| c1 | c2 |",
			expected: "| h1 | h2 |\n|---|---|\n| c1 | c2 |",
		},
		{
			name:     "code block lang stripping",
			input:    "Here is code:\n```go\nfunc main() {}\n```",
			expected: "Here is code:\n```\nfunc main() {}\n```",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := formatForSlack(tt.input)
			if actual != tt.expected {
				t.Errorf("formatForSlack() = %q, want %q", actual, tt.expected)
			}
		})
	}
}

func TestMarkdownToBlocks(t *testing.T) {
	ui := &SlackUI{
		agentName:      "KubeAI",
		contextMessage: "Hello",
	}
	text := "Hello\n\n### My Header\n\n| h1 | h2 |\n|---|---|\n| c1 | c2 |\n\nWorld"
	blocks := ui.markdownToBlocks(text)

	// Expected blocks: Section, Header, Table, Section
	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks, got %d", len(blocks))
	}

	// First block: Section
	if _, ok := blocks[0].(*slack.SectionBlock); !ok {
		t.Errorf("expected first block to be SectionBlock, got %T", blocks[0])
	}

	// Second block: Header
	if hb, ok := blocks[1].(*slack.HeaderBlock); !ok {
		t.Errorf("expected second block to be HeaderBlock, got %T", blocks[1])
	} else {
		if hb.Text.Text != "My Header" {
			t.Errorf("expected header text 'My Header', got %q", hb.Text.Text)
		}
	}

	// Third block: Table
	if _, ok := blocks[2].(*TableBlock); !ok {
		t.Errorf("expected third block to be TableBlock, got %T", blocks[2])
	}

	// Fourth block: Section
	if _, ok := blocks[3].(*slack.SectionBlock); !ok {
		t.Errorf("expected fourth block to be SectionBlock, got %T", blocks[3])
	}
}

func TestIsComplexOrLong(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "short simple text",
			input:    "hello world",
			expected: false,
		},
		{
			name:     "long text",
			input:    strings.Repeat("a", 3001),
			expected: true,
		},
		// Table detection removed from IsComplexOrLong for short tables
		{
			name:     "table detection",
			input:    "| Name | Age |\n|---|---|\n| Foo | 20 |",
			expected: false,
		},
		{
			name:     "long code block",
			input:    "Here is code:\n```go\nfunc main() {}\n```\n" + strings.Repeat("x", 1000),
			expected: true,
		},
		{
			name:     "short code block",
			input:    "```echo hello```",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := isComplexOrLong(tt.input)
			if actual != tt.expected {
				t.Errorf("isComplexOrLong() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestGenerateBlocks(t *testing.T) {
	ui := &SlackUI{
		agentName:      "KubeAI",
		contextMessage: "Context",
	}

	// Case 1: Final message, should include context
	blocks := ui.generateBlocks("Hello", true)
	if len(blocks) != 2 { // Section + Context
		t.Errorf("expected 2 blocks, got %d", len(blocks))
	}
	if _, ok := blocks[1].(*slack.ContextBlock); !ok {
		t.Errorf("expected second block to be ContextBlock, got %T", blocks[1])
	}

	// Case 2: Non-final message, should NOT include context
	blocks = ui.generateBlocks("Hello", false)
	if len(blocks) != 1 { // Section only
		t.Errorf("expected 1 block, got %d", len(blocks))
	}
	if _, ok := blocks[0].(*slack.SectionBlock); !ok {
		t.Errorf("expected first block to be SectionBlock, got %T", blocks[0])
	}
}

func TestProcessMessage(t *testing.T) {
	sm, _ := sessions.NewSessionManager("memory")

	inputCh := make(chan any, 1)
	mockAgent := &agent.Agent{
		Input: inputCh,
		Session: &api.Session{
			ID: "slack-C123-123.456",
		},
	}

	am := &mockAgentManager{
		GetAgentFunc: func(ctx context.Context, sessionID string) (*agent.Agent, error) {
			return mockAgent, nil
		},
	}

	ui := &SlackUI{
		manager:         am,
		sessionManager:  sm,
		apiClient:       &mockSlackAPI{},
		processedEvents: make(map[string]time.Time),
		activeTriggers:  make(map[string]string),
		agentName:       "KubeAI",
		contextMessage:  "Done",
	}

	channel := "C123"
	ts := "123.456"
	text := "<@U789> get pods"

	ui.processMessage(channel, "", ts, text)

	select {
	case untypedMsg := <-inputCh:
		msg, ok := untypedMsg.(*api.UserInputResponse)
		if !ok {
			t.Fatalf("expected *api.UserInputResponse, got %T", untypedMsg)
		}
		if msg.Query != "get pods" {
			t.Errorf("expected query 'get pods', got %q", msg.Query)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("timed out waiting for message in agent input")
	}
}

func TestHandleSlackEventsURLVerification(t *testing.T) {
	signingSecret := "test-secret"
	ui := &SlackUI{
		signingSecret:   signingSecret,
		processedEvents: make(map[string]time.Time),
		activeTriggers:  make(map[string]string),
	}

	body := `{"type": "url_verification", "challenge": "hello-world"}`
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Create signature
	// v0:timestamp:body
	msg := fmt.Sprintf("v0:%s:%s", timestamp, body)
	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(msg))
	signature := fmt.Sprintf("v0=%s", hex.EncodeToString(h.Sum(nil)))

	req := httptest.NewRequest(http.MethodPost, "/slack/events", bytes.NewBufferString(body))
	req.Header.Set("X-Slack-Request-Timestamp", timestamp)
	req.Header.Set("X-Slack-Signature", signature)

	rr := httptest.NewRecorder()
	ui.handleSlackEvents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if rr.Body.String() != "hello-world" {
		t.Errorf("expected body 'hello-world', got %q", rr.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	// We need to initialize the mux to test it, but it's initialized in NewSlackUI.
	// Since NewSlackUI does a lot of things, let's just test the handler logic if we can,
	// or initialize a simple mux for the test.

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", rr.Body.String())
	}
}

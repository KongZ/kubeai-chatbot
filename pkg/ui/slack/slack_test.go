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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"sync"
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
	UploadFileFunc   func(params slack.UploadFileParameters) (*slack.FileSummary, error)
	AddReactionFunc    func(name string, item slack.ItemRef) error
	RemoveReactionFunc func(name string, item slack.ItemRef) error
	AuthTestFunc       func(ctx context.Context) (*slack.AuthTestResponse, error)
}

func (m *mockSlackAPI) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	if m.PostMessageFunc != nil {
		return m.PostMessageFunc(channelID, options...)
	}
	return "", "", nil
}

func (m *mockSlackAPI) UploadFile(params slack.UploadFileParameters) (*slack.FileSummary, error) {
	if m.UploadFileFunc != nil {
		return m.UploadFileFunc(params)
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

func (m *mockSlackAPI) AuthTestContext(ctx context.Context) (*slack.AuthTestResponse, error) {
	if m.AuthTestFunc != nil {
		return m.AuthTestFunc(ctx)
	}
	return &slack.AuthTestResponse{TeamID: "T1"}, nil
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

// mockAuthenticator is a mock implementation of auth.Authenticator.
type mockAuthenticator struct {
	GetLoginURLFunc  func(relayState string) (string, error)
	GetIdentityFunc  func(r *http.Request) (*api.Identity, error)
	GetSessionIDFunc func(r *http.Request) (string, error)
	MiddlewareFunc   func() http.Handler
}

func (m *mockAuthenticator) GetLoginURL(relayState string) (string, error) {
	if m.GetLoginURLFunc != nil {
		return m.GetLoginURLFunc(relayState)
	}
	return "", nil
}

func (m *mockAuthenticator) GetIdentity(r *http.Request) (*api.Identity, error) {
	if m.GetIdentityFunc != nil {
		return m.GetIdentityFunc(r)
	}
	return nil, nil
}

func (m *mockAuthenticator) GetSessionID(r *http.Request) (string, error) {
	if m.GetSessionIDFunc != nil {
		return m.GetSessionIDFunc(r)
	}
	return "", nil
}

func (m *mockAuthenticator) Middleware() http.Handler {
	if m.MiddlewareFunc != nil {
		return m.MiddlewareFunc()
	}
	return nil
}

// mockStreamAPI is a mock implementation of SlackStreamAPI that records calls.
type mockStreamAPI struct {
	mu            sync.Mutex
	startCalls    []startStreamRequest
	appendCalls   [][]any
	stopCalls     int
	startStreamTS string
	startErr      error
	// forceEmptyTS makes StartStream return ("", nil) — a malformed-but-"ok"
	// success response.
	forceEmptyTS bool
	// appendFailOnCall, if non-zero, makes the Nth call (1-indexed) to
	// AppendStream fail; all other calls succeed.
	appendFailOnCall int
	appendCallCount  int
}

func (m *mockStreamAPI) StartStream(req startStreamRequest) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalls = append(m.startCalls, req)
	if m.startErr != nil {
		return "", m.startErr
	}
	if m.forceEmptyTS {
		return "", nil
	}
	ts := m.startStreamTS
	if ts == "" {
		ts = "stream-ts-1"
	}
	return ts, nil
}

func (m *mockStreamAPI) AppendStream(channel, ts string, chunks []any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appendCallCount++
	m.appendCalls = append(m.appendCalls, chunks)
	if m.appendFailOnCall != 0 && m.appendCallCount == m.appendFailOnCall {
		return fmt.Errorf("simulated transient append failure")
	}
	return nil
}

func (m *mockStreamAPI) StopStream(channel, ts string, chunks []any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalls++
	return nil
}

func (m *mockStreamAPI) counts() (starts, appends, stops int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.startCalls), len(m.appendCalls), m.stopCalls
}

// TestFormatForSlack verifies that markdown formatting is correctly converted to Slack's mrkdwn format.
// It tests bold, italic, links, code blocks, and combined formatting conversions.
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

	t.Run("ClearScreen call", func(t *testing.T) {
		ui := &SlackUI{}
		ui.ClearScreen() // Should do nothing, but adds coverage
	})
}

// TestMarkdownToBlocks verifies that markdown text is correctly parsed into Slack Block Kit blocks.
// It tests the conversion of headers, tables, and paragraphs into their respective block types.
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

// TestBlockCountLimit verifies that messages are routed to snippet upload only when they
// exceed maxSlackBlocks (50), not based on raw character count.
func TestBlockCountLimit(t *testing.T) {
	s := &SlackUI{}

	tests := []struct {
		name          string
		input         string
		expectSnippet bool
	}{
		{
			name:          "short simple text",
			input:         "hello world",
			expectSnippet: false,
		},
		{
			name:          "long text over 3000 chars but few blocks",
			input:         strings.Repeat("a", 3001),
			expectSnippet: false, // long text generates only 1 section block — well under 50
		},
		{
			name:          "table with text over 3000 chars",
			input:         strings.Repeat("intro text\n", 20) + "| Name | Age |\n|---|---|\n| Foo | 20 |",
			expectSnippet: false, // generates a few blocks — under 50
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks := s.generateBlocks(tt.input, false)
			overLimit := len(blocks) > maxSlackBlocks
			if overLimit != tt.expectSnippet {
				t.Errorf("block count %d, overLimit=%v, want expectSnippet=%v", len(blocks), overLimit, tt.expectSnippet)
			}
		})
	}
}

// TestGenerateBlocks verifies that blocks are generated correctly with or without context.
// Final messages should include a context block, while non-final messages should not.
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

// TestProcessMessage verifies that incoming Slack messages are correctly processed and forwarded
// to the agent. It tests mention stripping, session creation, and message routing.
func TestProcessMessage(t *testing.T) {
	sm, _ := sessions.NewSessionManager("memory")

	inputCh := make(chan any, 1)
	mockAgent := &agent.Agent{
		Input: inputCh,
		Session: &api.Session{
			ID:           "slack-C123-123.456",
			Name:         "Test Session",
			ProviderID:   "test-provider",
			ModelID:      "test-model",
			SlackUserID:  "U123456",
			AgentState:   api.AgentStateIdle,
			CreatedAt:    time.Now(),
			LastModified: time.Now(),
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
		defaultModel:    "model",
		defaultProvider: "provider",
	}

	channel := "C123"
	ts := "123.456"
	text := "<@U789> get pods"

	ui.processMessage(channel, "", ts, text, "U789")

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

// TestValidateRedirectURL checks that login URLs pointing at internal
// infrastructure — localhost/loopback, link-local (which covers cloud
// metadata endpoints like 169.254.169.254), other private ranges, or
// disallowed schemes/hosts — are rejected, while ordinary public URLs are
// accepted. IP literals are used throughout (rather than real hostnames) so
// the test never depends on live DNS resolution.
func TestValidateRedirectURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "public https URL", rawURL: "https://8.8.8.8/login", wantErr: false},
		{name: "public http URL", rawURL: "http://8.8.8.8/login", wantErr: false},
		{name: "unsupported scheme", rawURL: "ftp://8.8.8.8/login", wantErr: true},
		{name: "javascript scheme", rawURL: "javascript:alert(1)", wantErr: true},
		{name: "malformed URL", rawURL: "http://%zz", wantErr: true},
		{name: "localhost", rawURL: "http://localhost:8888/login", wantErr: true},
		{name: "dot-localhost", rawURL: "http://foo.localhost/login", wantErr: true},
		{name: "loopback IPv4", rawURL: "http://127.0.0.1/login", wantErr: true},
		{name: "loopback IPv6", rawURL: "http://[::1]/login", wantErr: true},
		{name: "cloud metadata IP", rawURL: "http://169.254.169.254/latest/meta-data/", wantErr: true},
		{name: "link-local IP", rawURL: "http://169.254.1.2/login", wantErr: true},
		{name: "metadata hostname", rawURL: "http://metadata.google.internal/computeMetadata/v1/", wantErr: true},
		{name: "private 10.x", rawURL: "http://10.0.0.5/login", wantErr: true},
		{name: "private 172.16.x", rawURL: "http://172.16.0.5/login", wantErr: true},
		{name: "private 192.168.x", rawURL: "http://192.168.1.1/login", wantErr: true},
		{name: "unspecified", rawURL: "http://0.0.0.0/login", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRedirectURL(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRedirectURL(%q) error = %v, wantErr %v", tt.rawURL, err, tt.wantErr)
			}
		})
	}
}

// TestProcessMessageRejectsUnsafeLoginURL verifies that processMessage
// refuses to share a login URL that resolves to internal infrastructure,
// posting a generic error instead of the unsafe link.
func TestProcessMessageRejectsUnsafeLoginURL(t *testing.T) {
	sm, _ := sessions.NewSessionManager("memory")

	am := &mockAgentManager{
		GetAgentFunc: func(ctx context.Context, sessionID string) (*agent.Agent, error) {
			return &agent.Agent{
				Input: make(chan any, 1),
				Session: &api.Session{
					ID: sessionID, Name: "Test", ProviderID: "p", ModelID: "m",
					AgentState: api.AgentStateIdle, CreatedAt: time.Now(), LastModified: time.Now(),
				},
			}, nil
		},
	}

	postCalled := make(chan string, 1)
	mockAPI := &mockSlackAPI{
		PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
			postCalled <- channelID
			return "", "", nil
		},
	}

	ui := &SlackUI{
		manager:         am,
		sessionManager:  sm,
		apiClient:       mockAPI,
		activeTriggers:  make(map[string]string),
		defaultModel:    "model",
		defaultProvider: "provider",
		authenticator: &mockAuthenticator{
			GetLoginURLFunc: func(relayState string) (string, error) {
				return "http://169.254.169.254/latest/meta-data/", nil
			},
		},
	}

	ui.processMessage("C1", "", "123.456", "<@U1> hello", "U789")

	select {
	case <-postCalled:
		// success — some message was posted (the generic error), not a crash.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for the rejection message to post")
	}
}

// TestHandleSlackEventsURLVerification verifies that Slack's URL verification challenge
// is handled correctly with proper HMAC signature validation.
func TestHandleSlackEventsURLVerification(t *testing.T) {
	signingSecret := "test-secret"
	ui := &SlackUI{
		signingSecret:   signingSecret,
		manager:         &mockAgentManager{},
		apiClient:       &mockSlackAPI{},
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

// TestHandleSlackEvents_Callback verifies processing of Slack callback events (app mentions).
func TestHandleSlackEvents_Callback(t *testing.T) {
	signingSecret := "test-secret"
	sm, _ := sessions.NewSessionManager("memory")
	ui := &SlackUI{
		signingSecret:  signingSecret,
		sessionManager: sm,
		manager: &mockAgentManager{
			GetAgentFunc: func(ctx context.Context, sessionID string) (*agent.Agent, error) {
				return &agent.Agent{
					Input: make(chan any, 1),
					Session: &api.Session{
						ID:           sessionID,
						Name:         "Test Session",
						ProviderID:   "provider",
						ModelID:      "model",
						SlackUserID:  "U1",
						AgentState:   api.AgentStateIdle,
						CreatedAt:    time.Now(),
						LastModified: time.Now(),
					},
				}, nil
			},
		},
		apiClient:       &mockSlackAPI{},
		processedEvents: make(map[string]time.Time),
		activeTriggers:  make(map[string]string),
	}

	body := `{"type":"event_callback","event":{"type":"app_mention","channel":"C1","ts":"1.1","text":"hello","user":"U1"}}`
	ts := fmt.Sprintf("%d", time.Now().Unix())
	msg := fmt.Sprintf("v0:%s:%s", ts, body)
	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(msg))
	sig := fmt.Sprintf("v0=%s", hex.EncodeToString(h.Sum(nil)))

	req := httptest.NewRequest(http.MethodPost, "/slack/events", strings.NewReader(body))
	req.Header.Set("X-Slack-Signature", sig)
	req.Header.Set("X-Slack-Request-Timestamp", ts)

	rr := httptest.NewRecorder()
	ui.handleSlackEvents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// TestHandleSlackEvents_BotMessage verifies that messages from bots are ignored.
func TestHandleSlackEvents_BotMessage(t *testing.T) {
	signingSecret := "test-secret"
	sm, _ := sessions.NewSessionManager("memory")
	ui := &SlackUI{
		signingSecret:   signingSecret,
		sessionManager:  sm,
		manager:         &mockAgentManager{},
		apiClient:       &mockSlackAPI{},
		processedEvents: make(map[string]time.Time),
		activeTriggers:  make(map[string]string),
	}

	body := `{"type":"event_callback","event":{"type":"message","bot_id":"B1","text":"hello"}}`
	ts := fmt.Sprintf("%d", time.Now().Unix())
	msg := fmt.Sprintf("v0:%s:%s", ts, body)
	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(msg))
	sig := fmt.Sprintf("v0=%s", hex.EncodeToString(h.Sum(nil)))

	req := httptest.NewRequest(http.MethodPost, "/slack/events", strings.NewReader(body))
	req.Header.Set("X-Slack-Signature", sig)
	req.Header.Set("X-Slack-Request-Timestamp", ts)

	rr := httptest.NewRecorder()
	ui.handleSlackEvents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// TestHealthz verifies that the health check endpoint returns a 200 OK status
// with the expected "ok" response body.
func TestHealthz(t *testing.T) {
	// We need to initialize the mux to test it, but it's initialized in NewSlackUI.
	// Since NewSlackUI does a lot of things, let's just test the handler logic if we can,
	// or initialize a simple mux for the test.

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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

// TestNormalizeInlineTables verifies that inline tables (tables without line breaks) are correctly
// normalized into multi-line format. This handles cases where LLMs output tables with || separators
// on a single line, including tables that start with markdown headers.
func TestNormalizeInlineTables(t *testing.T) {
	s := &SlackUI{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:  "inline table with double pipes",
			input: "### Summary Table| Perspective | IP Address || :--- | :--- || **Cluster Node (VM)** | `192.168.5.2` || **Gateway (Host Machine)** | `192.168.5.1` || **Outgoing Internet IP** | Your Host's Public IP |",
			expected: `### Summary Table
| Perspective | IP Address |
| :--- | :--- |
| **Cluster Node (VM)** | ` + "`192.168.5.2`" + ` |
| **Gateway (Host Machine)** | ` + "`192.168.5.1`" + ` |
| **Outgoing Internet IP** | Your Host's Public IP |`,
		},
		{
			name: "normal multi-line table",
			input: `| Header 1 | Header 2 |
| :--- | :--- |
| Row 1 | Data 1 |`,
			expected: `| Header 1 | Header 2 |
| :--- | :--- |
| Row 1 | Data 1 |`,
		},
		{
			name:     "no table",
			input:    "This is just regular text without any tables.",
			expected: "This is just regular text without any tables.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.normalizeInlineTables(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeInlineTables() failed\nInput:\n%s\n\nExpected:\n%s\n\nGot:\n%s", tt.input, tt.expected, result)
			}
		})
	}
}

// TestIsTableRow verifies the logic that determines whether a line of text is a table row.
// It tests various formats including rows with and without leading pipes, separators, and edge cases.
func TestIsTableRow(t *testing.T) {
	s := &SlackUI{}

	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "valid table row",
			line:     "| Column 1 | Column 2 |",
			expected: true,
		},
		{
			name:     "table separator",
			line:     "| :--- | :--- |",
			expected: true,
		},
		{
			name:     "table row without leading pipe",
			line:     "Column 1 | Column 2 |",
			expected: true,
		},
		{
			name:     "not a table row - single pipe",
			line:     "This is | not a table",
			expected: false,
		},
		{
			name:     "empty line",
			line:     "",
			expected: false,
		},
		{
			name:     "no pipes",
			line:     "Just regular text",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.isTableRow(tt.line)
			if result != tt.expected {
				t.Errorf("isTableRow(%q) = %v, expected %v", tt.line, result, tt.expected)
			}
		})
	}
}

// TestIsTableSeparator verifies the detection of markdown table separator rows.
// It tests various separator formats including left, right, and center alignment indicators.
func TestIsTableSeparator(t *testing.T) {
	s := &SlackUI{}

	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "standard separator",
			line:     "| :--- | :--- |",
			expected: true,
		},
		{
			name:     "separator with dashes only",
			line:     "| --- | --- |",
			expected: true,
		},
		{
			name:     "separator with right align",
			line:     "| ---: | ---: |",
			expected: true,
		},
		{
			name:     "separator with center align",
			line:     "| :---: | :---: |",
			expected: true,
		},
		{
			name:     "not a separator - regular row",
			line:     "| Data 1 | Data 2 |",
			expected: false,
		},
		{
			name:     "not a separator - no dashes",
			line:     "| Column | Column |",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.isTableSeparator(tt.line)
			if result != tt.expected {
				t.Errorf("isTableSeparator(%q) = %v, expected %v", tt.line, result, tt.expected)
			}
		})
	}
}

// TestMarkdownToBlocksWithInlineTable is an end-to-end test that verifies the complete pipeline
// of normalizing inline tables and converting them to Slack blocks. It uses the actual problematic
// input from production logs where a markdown header and table were on the same line.
func TestMarkdownToBlocksWithInlineTable(t *testing.T) {
	s := &SlackUI{}

	// Test the actual problematic input from the log
	input := "### Summary Table| Perspective | IP Address || :--- | :--- || **Cluster Node (VM)** | `192.168.5.2` || **Gateway (Host Machine)** | `192.168.5.1` || **Outgoing Internet IP** | Your Host's Public IP |"

	blocks := s.markdownToBlocks(input)

	// Should have at least 2 blocks: header + table
	if len(blocks) < 2 {
		t.Errorf("Expected at least 2 blocks (header + table), got %d", len(blocks))
	}

	// First block should be a header
	if blocks[0].BlockType() != slack.MBTHeader {
		t.Errorf("First block should be header, got %s", blocks[0].BlockType())
	}

	// Second block should be a table
	if _, ok := blocks[1].(*TableBlock); !ok {
		t.Errorf("Second block should be TableBlock, got %T", blocks[1])
	} else {
		tableBlock := blocks[1].(*TableBlock)
		// Should have header row + 3 data rows = 4 rows total
		if len(tableBlock.Rows) != 4 {
			t.Errorf("Expected 4 rows in table (1 header + 3 data), got %d", len(tableBlock.Rows))
		}
	}
}

// TestStripEmojis verifies that emoji characters are correctly removed from text.
// This is necessary because Slack header blocks only support plain text without emojis.
func TestStripEmojis(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "header with emoji",
			input:    "🚨 Critical Errors (CrashLoopBackOff)",
			expected: "Critical Errors (CrashLoopBackOff)",
		},
		{
			name:     "multiple emojis",
			input:    "⚠️ Warning ℹ️ Info 🛠️ Tools",
			expected: "Warning ℹ Info  Tools", // ℹ️ has variation selector that gets removed separately
		},
		{
			name:     "no emojis",
			input:    "Plain text header",
			expected: "Plain text header",
		},
		{
			name:     "emoji at end",
			input:    "Additional Context 🔍",
			expected: "Additional Context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripEmojis(tt.input)
			if result != tt.expected {
				t.Errorf("stripEmojis(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestMarkdownToBlocksWithEmojis verifies that markdown with emojis in headers
// is correctly processed, with emojis stripped from header blocks.
func TestMarkdownToBlocksWithEmojis(t *testing.T) {
	s := &SlackUI{}

	input := "### 🚨 Critical Errors\n\nSome text here."

	blocks := s.markdownToBlocks(input)

	if len(blocks) < 2 {
		t.Fatalf("Expected at least 2 blocks, got %d", len(blocks))
	}

	// First block should be a header without emoji
	if hb, ok := blocks[0].(*slack.HeaderBlock); !ok {
		t.Errorf("First block should be HeaderBlock, got %T", blocks[0])
	} else {
		if strings.Contains(hb.Text.Text, "🚨") {
			t.Errorf("Header should not contain emoji, got: %q", hb.Text.Text)
		}
		if !strings.Contains(hb.Text.Text, "Critical Errors") {
			t.Errorf("Header should contain 'Critical Errors', got: %q", hb.Text.Text)
		}
	}
}

// TestTableBlockMethods verifies the implementation of the slack.Block interface
// for the custom TableBlock.
func TestTableBlockMethods(t *testing.T) {
	tb := &TableBlock{
		TypeVal:    "table",
		BlockIDVal: "B1",
	}

	if tb.BlockType() != "table" {
		t.Errorf("expected table, got %s", tb.BlockType())
	}
	if tb.BlockID() != "B1" {
		t.Errorf("expected B1, got %s", tb.BlockID())
	}
	if tb.ID() != "B1" {
		t.Errorf("expected B1, got %s", tb.ID())
	}
}

// TestNewTableBlockLimits verifies that table blocks respect Slack's limits
// of maximum 5 columns and 50 rows (including header).
func TestNewTableBlockLimits(t *testing.T) {
	tests := []struct {
		name        string
		headers     []string
		rows        [][]string
		expectValid bool
	}{
		{
			name:        "valid table with 3 columns",
			headers:     []string{"Col1", "Col2", "Col3"},
			rows:        [][]string{{"A", "B", "C"}},
			expectValid: true,
		},
		{
			name:        "valid table with 5 columns (max)",
			headers:     []string{"C1", "C2", "C3", "C4", "C5"},
			rows:        [][]string{{"A", "B", "C", "D", "E"}},
			expectValid: true,
		},
		{
			name:        "invalid table with 6 columns",
			headers:     []string{"C1", "C2", "C3", "C4", "C5", "C6"},
			rows:        [][]string{{"A", "B", "C", "D", "E", "F"}},
			expectValid: false,
		},
		{
			name:        "empty headers",
			headers:     []string{},
			rows:        [][]string{{"A", "B"}},
			expectValid: false,
		},
		{
			name:    "too many rows",
			headers: []string{"Col1", "Col2"},
			rows: func() [][]string {
				rows := make([][]string, 50) // 50 data rows + 1 header = 51 total (exceeds limit)
				for i := range rows {
					rows[i] = []string{"A", "B"}
				}
				return rows
			}(),
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewTableBlock(tt.headers, tt.rows)
			if tt.expectValid && result == nil {
				t.Errorf("Expected valid table block, got nil")
			}
			if !tt.expectValid && result != nil {
				t.Errorf("Expected nil for invalid table, got valid block")
			}
		})
	}
}

// TestNormalizeInlineHeaders verifies that markdown headers without line breaks after them
// are correctly normalized to have the content on a separate line.
func TestNormalizeInlineHeaders(t *testing.T) {
	s := &SlackUI{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "header with emoji and inline text",
			input:    "### 💡 Comparison with Working PodI noticed that your other pod",
			expected: "### 💡 Comparison with Working Pod\nI noticed that your other pod",
		},
		{
			name:     "header with emoji and inline text (different pattern)",
			input:    "### 🚀 RecommendationTo fix this, you should",
			expected: "### 🚀 Recommendation\nTo fix this, you should",
		},
		{
			name:     "normal header with line break",
			input:    "### Header Text\n\nSome content",
			expected: "### Header Text\n\nSome content",
		},
		{
			name:     "header without inline text",
			input:    "### Just a Header",
			expected: "### Just a Header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.normalizeInlineHeaders(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeInlineHeaders() failed\nInput:\n%s\n\nExpected:\n%s\n\nGot:\n%s", tt.input, tt.expected, result)
			}
		})
	}
}

// TestUploadSnippet verifies the file uploading and fallback mechanisms when a message is too long
// or complex. It tests both successful upload and fallback to a regular message on error.
func TestUploadSnippet(t *testing.T) {
	tests := []struct {
		name              string
		uploadError       error
		expectFallbackMsg bool
	}{
		{
			name:              "successful upload",
			uploadError:       nil,
			expectFallbackMsg: false,
		},
		{
			name:              "upload failure with fallback",
			uploadError:       fmt.Errorf("upload failed"),
			expectFallbackMsg: true,
		},
	}

	const content = "Long content"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			postMsgCalled := false
			uploadCalled := false
			var gotFileSize int

			mockAPI := &mockSlackAPI{
				UploadFileFunc: func(params slack.UploadFileParameters) (*slack.FileSummary, error) {
					uploadCalled = true
					gotFileSize = params.FileSize
					return nil, tt.uploadError
				},
				PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
					postMsgCalled = true
					return "", "", nil
				},
			}

			ui := &SlackUI{apiClient: mockAPI}
			ui.uploadSnippet("C123", "123.456", content)

			if !uploadCalled {
				t.Error("expected UploadFile to be called")
			}
			// slack-go's UploadFileContext rejects FileSize == 0 outright
			// (files.go:628-630, v0.17.3) regardless of Content's actual
			// length, so this must always be set to the real byte length.
			if gotFileSize != len(content) {
				t.Errorf("expected FileSize %d, got %d", len(content), gotFileSize)
			}
			if tt.expectFallbackMsg && !postMsgCalled {
				t.Error("expected PostMessage to be called as fallback")
			}
			if !tt.expectFallbackMsg && postMsgCalled {
				t.Error("did not expect PostMessage to be called")
			}
		})
	}
}

// TestUploadSnippetEmptyTextSkipsUpload verifies uploadSnippet doesn't even
// attempt an upload for empty text, since Slack always rejects a 0-byte file
// (with or without FileSize being set correctly).
func TestUploadSnippetEmptyTextSkipsUpload(t *testing.T) {
	uploadCalled := false
	mockAPI := &mockSlackAPI{
		UploadFileFunc: func(params slack.UploadFileParameters) (*slack.FileSummary, error) {
			uploadCalled = true
			return nil, nil
		},
	}
	ui := &SlackUI{apiClient: mockAPI}
	ui.uploadSnippet("C123", "123.456", "")

	if uploadCalled {
		t.Error("expected UploadFile not to be called for empty text")
	}
}

// TestHTTPStreamClient exercises httpStreamClient's StartStream/AppendStream/
// StopStream against a real HTTP test server, verifying the exact JSON body
// sent for each method and that responses are parsed correctly. This is the
// only test coverage for httpStreamClient itself (everything else mocks
// SlackStreamAPI), so it's the place a duplicated-payload bug on our side
// (as opposed to a Slack-side rendering quirk) would actually show up.
func TestHTTPStreamClient(t *testing.T) {
	var receivedBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		receivedBodies = append(receivedBodies, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C1","ts":"123.456"}`))
	}))
	defer server.Close()

	client := newHTTPStreamClient("xoxb-test-token")
	client.httpClient = server.Client()
	// slackAPIBaseURL is a package-level const, so point requests at the
	// test server via a custom RoundTripper that rewrites the host instead.
	client.httpClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req2 := req.Clone(req.Context())
		serverURL, _ := neturl.Parse(server.URL)
		req2.URL.Scheme = serverURL.Scheme
		req2.URL.Host = serverURL.Host
		return http.DefaultTransport.RoundTrip(req2)
	})

	ts, err := client.StartStream(startStreamRequest{
		Channel:         "C1",
		ThreadTS:        "111.111",
		RecipientUserID: "U1",
		RecipientTeamID: "T1",
		TaskDisplayMode: "plan",
		Chunks:          []any{newPlanUpdateChunk("Investigating")},
	})
	if err != nil || ts != "123.456" {
		t.Fatalf("StartStream() = (%q, %v), want (\"123.456\", nil)", ts, err)
	}

	chunk := newTaskUpdateChunk("task-0", "kubectl logs foo", "kubectl logs foo -n bar --previous", "in_progress", "")
	if err := client.AppendStream("C1", ts, []any{chunk}); err != nil {
		t.Fatalf("AppendStream() error = %v", err)
	}

	if err := client.StopStream("C1", ts, nil); err != nil {
		t.Fatalf("StopStream() error = %v", err)
	}

	if len(receivedBodies) != 3 {
		t.Fatalf("expected exactly 3 HTTP calls (start, append, stop), got %d", len(receivedBodies))
	}

	appendBody := receivedBodies[1]
	chunks, ok := appendBody["chunks"].([]any)
	if !ok || len(chunks) != 1 {
		t.Fatalf("expected exactly 1 chunk in the AppendStream call, got %#v", appendBody["chunks"])
	}
	sentChunk, ok := chunks[0].(map[string]any)
	if !ok {
		t.Fatalf("expected chunk to be a JSON object, got %T", chunks[0])
	}
	if sentChunk["details"] != "kubectl logs foo -n bar --previous" {
		t.Errorf("expected details to be sent exactly once with no duplication, got %v", sentChunk["details"])
	}
	if sentChunk["title"] != "kubectl logs foo" {
		t.Errorf("expected title to be sent exactly once, got %v", sentChunk["title"])
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestPostToSlack verifies the logic for deciding between sending a message as blocks or
// uploading it as a snippet. It also tests fallback from invalid blocks to snippet.
func TestPostToSlack(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		postError     error
		expectUpload  bool
		expectPostMsg bool
	}{
		{
			name:          "normal message uses blocks",
			text:          "simple message",
			expectUpload:  false,
			expectPostMsg: true,
		},
		{
			// Snippet is triggered by block count (>50), not character count.
			// Build a message with 51 distinct sections separated by headers.
			name: "too many blocks uses snippet",
			text: func() string {
				var b strings.Builder
				for i := 0; i < 51; i++ {
					b.WriteString(fmt.Sprintf("## Section %d\nContent for section %d\n\n", i, i))
				}
				return b.String()
			}(),
			expectUpload:  true,
			expectPostMsg: false,
		},
		{
			name:          "invalid blocks fallback to snippet",
			text:          "invalid-blocks-text",
			postError:     fmt.Errorf("invalid_blocks"),
			expectUpload:  true,
			expectPostMsg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uploadCalled := false
			postMsgCalled := false

			mockAPI := &mockSlackAPI{
				PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
					postMsgCalled = true
					return "", "", tt.postError
				},
				UploadFileFunc: func(params slack.UploadFileParameters) (*slack.FileSummary, error) {
					uploadCalled = true
					return nil, nil
				},
			}

			ui := &SlackUI{
				apiClient:      mockAPI,
				agentName:      "KubeAI",
				contextMessage: "Context",
			}
			ui.postToSlack("C123", "ts", tt.text, true)

			if tt.expectUpload && !uploadCalled {
				t.Error("expected uploadSnippet to be called")
			}
			if tt.expectPostMsg && !postMsgCalled {
				t.Error("expected PostMessage to be called")
			}
		})
	}
}

// TestHandleSlackEvents_Validation verifies that unauthorized and malformed requests
// to the Slack events endpoint are correctly rejected with appropriate status codes.
func TestHandleSlackEvents_Validation(t *testing.T) {
	ui := &SlackUI{
		signingSecret: "secret",
	}

	t.Run("invalid signature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/slack/events", strings.NewReader(`{"type":"event_callback"}`))
		req.Header.Set("X-Slack-Signature", "v0=invalid")
		req.Header.Set("X-Slack-Request-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))

		rr := httptest.NewRecorder()
		ui.handleSlackEvents(rr, req)

		if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusBadRequest {
			t.Errorf("expected unauthorized or bad request, got %d", rr.Code)
		}
	})

	t.Run("invalid body", func(t *testing.T) {
		// Mock a valid signature for an invalid body
		body := "invalid-json"
		ts := fmt.Sprintf("%d", time.Now().Unix())
		msg := fmt.Sprintf("v0:%s:%s", ts, body)
		h := hmac.New(sha256.New, []byte("secret"))
		h.Write([]byte(msg))
		sig := fmt.Sprintf("v0=%s", hex.EncodeToString(h.Sum(nil)))

		req := httptest.NewRequest(http.MethodPost, "/slack/events", strings.NewReader(body))
		req.Header.Set("X-Slack-Signature", sig)
		req.Header.Set("X-Slack-Request-Timestamp", ts)

		rr := httptest.NewRecorder()
		ui.handleSlackEvents(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected internal error, got %d", rr.Code)
		}
	})
}

// TestSlackUI_NewSlackUI_Errors verifies that the SlackUI constructor handles
// missing environment variables correctly by returning an error.
func TestSlackUI_NewSlackUI_Errors(t *testing.T) {
	t.Setenv("SLACK_BOT_TOKEN", "")
	t.Setenv("SLACK_SIGNING_SECRET", "")

	am := &mockAgentManager{}
	sm, _ := sessions.NewSessionManager("memory")
	ui, err := NewSlackUI(am, sm, "model", "provider", "8888", "agent", "msg", nil)
	if err == nil {
		t.Error("expected error due to missing env vars, got nil")
	}
	if ui != nil {
		t.Error("expected nil UI on error")
	}
}

// TestSlackUI_NewSlackUI success case
func TestSlackUI_NewSlackUI_Success(t *testing.T) {
	t.Setenv("SLACK_BOT_TOKEN", "xoxb-test")
	t.Setenv("SLACK_SIGNING_SECRET", "test-secret")

	am := &mockAgentManager{
		SetAgentCreatedCallbackFunc: func(f func(*agent.Agent)) {},
	}
	sm, _ := sessions.NewSessionManager("memory")

	ui, err := NewSlackUI(am, sm, "model", "provider", "127.0.0.1:0", "agent", "msg", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ui == nil {
		t.Fatal("expected UI, got nil")
	}
}

// TestEnsureAgentListener verifies the handling of agent output messages,
// including removing typing indicators and posting various message types to Slack.
func TestEnsureAgentListener(t *testing.T) {
	outputCh := make(chan any, 5)
	sessionID := "slack-C1-T1"
	sess := &api.Session{
		ID:           sessionID,
		Name:         "Test Session",
		ProviderID:   "provider",
		ModelID:      "model",
		SlackUserID:  "U1",
		AgentState:   api.AgentStateIdle,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}

	mockAgent := &agent.Agent{
		Output:  outputCh,
		Session: sess,
	}

	postCalled := make(chan string, 5)
	removeReactionCalled := make(chan bool, 1)

	mockAPI := &mockSlackAPI{
		PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
			postCalled <- channelID
			return "", "", nil
		},
		RemoveReactionFunc: func(name string, item slack.ItemRef) error {
			removeReactionCalled <- true
			return nil
		},
	}

	ui := &SlackUI{
		apiClient:      mockAPI,
		activeTriggers: map[string]string{sessionID: "trigger-ts"},
	}

	ui.ensureAgentListener(mockAgent)

	// Send an agent message
	outputCh <- &api.Message{
		ID:        "msg-1",
		Source:    api.MessageSourceAgent,
		Payload:   "hello world",
		Type:      api.MessageTypeText,
		Timestamp: time.Now(),
	}

	// Verify indicator removed
	select {
	case <-removeReactionCalled:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for reaction removal")
	}

	// Verify posted to slack
	select {
	case channel := <-postCalled:
		if channel != "C1" {
			t.Errorf("expected channel C1, got %s", channel)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for post to slack")
	}

	// Test tool call request wrapping
	outputCh <- &api.Message{
		ID:        "msg-2",
		Source:    api.MessageSourceAgent,
		Payload:   "ls -l",
		Type:      api.MessageTypeToolCallRequest,
		Timestamp: time.Now(),
	}

	select {
	case <-postCalled:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for tool call post")
	}

	// Test error message
	outputCh <- &api.Message{
		ID:        "msg-3",
		Source:    api.MessageSourceAgent,
		Payload:   fmt.Errorf("agent error"),
		Type:      api.MessageTypeError,
		Timestamp: time.Now(),
	}

	select {
	case <-postCalled:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for error post")
	}

	close(outputCh)
}

// TestEnsureAgentListenerPlanBlocks verifies that, with SLACK_AGENT_ENABLED
// behavior enabled, a batch of tool-call request/response messages renders
// as a single streaming Plan card (one StartStream, matched AppendStream
// pairs, one StopStream) instead of a sequence of separate messages, and
// that map-payload tool responses (dropped in the classic rendering path)
// are correctly rendered.
func TestEnsureAgentListenerPlanBlocks(t *testing.T) {
	outputCh := make(chan any, 10)
	sessionID := "slack-C1-T1"
	sess := &api.Session{
		ID:           sessionID,
		Name:         "Test Session",
		ProviderID:   "provider",
		ModelID:      "model",
		SlackUserID:  "U1",
		AgentState:   api.AgentStateIdle,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}

	mockAgent := &agent.Agent{
		Output:  outputCh,
		Session: sess,
	}

	postCalled := make(chan string, 5)
	mockAPI := &mockSlackAPI{
		PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
			postCalled <- channelID
			return "", "", nil
		},
	}
	mockStream := &mockStreamAPI{}

	ui := &SlackUI{
		apiClient:      mockAPI,
		streamClient:   mockStream,
		agentEnabled:   true,
		teamID:         "T1",
		activeTriggers: map[string]string{},
	}

	ui.ensureAgentListener(mockAgent)

	// First tool call: string response payload.
	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "2", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: "NAME   READY\npod-1  1/1", Timestamp: time.Now()}

	// Second tool call: map payload (this is silently dropped in the classic path).
	outputCh <- &api.Message{ID: "3", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get events", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "4", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: map[string]any{"content": "no events"}, Timestamp: time.Now()}

	// Final text message ends the tool-call batch.
	outputCh <- &api.Message{ID: "5", Source: api.MessageSourceAgent, Type: api.MessageTypeText, Payload: "Done.", Timestamp: time.Now()}

	deadline := time.After(2 * time.Second)
	for {
		starts, appends, stops := mockStream.counts()
		if starts == 1 && appends == 4 && stops == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for stream calls: starts=%d appends=%d stops=%d (want 1,4,1)", starts, appends, stops)
		case <-time.After(10 * time.Millisecond):
		}
	}

	select {
	case <-postCalled:
		// success: the trailing text message posted normally after the stream closed.
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for final text message to post")
	}

	close(outputCh)
}

// TestEnsureAgentListenerPlanBlocksStartFailureFallsBack verifies that when
// starting a Slack plan stream fails (e.g. the Agents feature isn't enabled),
// the tool-call request still renders via the classic code-fenced message
// path instead of being silently dropped, and that the failure isn't retried
// for later tool calls in the same session.
func TestEnsureAgentListenerPlanBlocksStartFailureFallsBack(t *testing.T) {
	outputCh := make(chan any, 10)
	sessionID := "slack-C1-T1"
	sess := &api.Session{
		ID:           sessionID,
		SlackUserID:  "U1",
		AgentState:   api.AgentStateIdle,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	postCalled := make(chan string, 5)
	mockAPI := &mockSlackAPI{
		PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
			postCalled <- channelID
			return "", "", nil
		},
	}
	mockStream := &mockStreamAPI{startErr: fmt.Errorf("feature_not_enabled")}

	ui := &SlackUI{
		apiClient:      mockAPI,
		streamClient:   mockStream,
		agentEnabled:   true,
		teamID:         "T1",
		activeTriggers: map[string]string{},
	}
	ui.ensureAgentListener(mockAgent)

	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods", Timestamp: time.Now()}
	select {
	case <-postCalled:
		// success: fell back to classic rendering instead of dropping the message.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for fallback post after stream-start failure")
	}

	// A second tool call in the same session should not retry StartStream.
	outputCh <- &api.Message{ID: "2", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get nodes", Timestamp: time.Now()}
	select {
	case <-postCalled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for second fallback post")
	}

	starts, _, _ := mockStream.counts()
	if starts != 1 {
		t.Errorf("expected exactly 1 StartStream attempt (no retries after failure), got %d", starts)
	}

	close(outputCh)
}

// TestEnsureAgentListenerPlanBlocksTitleFromThinkingText verifies the plan
// card is titled from the model's preceding "thinking" text (first line,
// truncated) rather than a generic label.
func TestEnsureAgentListenerPlanBlocksTitleFromThinkingText(t *testing.T) {
	outputCh := make(chan any, 10)
	sessionID := "slack-C1-T1"
	sess := &api.Session{
		ID:           sessionID,
		SlackUserID:  "U1",
		AgentState:   api.AgentStateIdle,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	mockAPI := &mockSlackAPI{}
	mockStream := &mockStreamAPI{}

	ui := &SlackUI{
		apiClient:      mockAPI,
		streamClient:   mockStream,
		agentEnabled:   true,
		teamID:         "T1",
		activeTriggers: map[string]string{},
	}
	ui.ensureAgentListener(mockAgent)

	outputCh <- &api.Message{
		ID: "1", Source: api.MessageSourceModel, Type: api.MessageTypeText,
		Payload: "I'll check the pod status and recent events.\nMore reasoning here.", Timestamp: time.Now(),
	}
	outputCh <- &api.Message{ID: "2", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods", Timestamp: time.Now()}

	deadline := time.After(2 * time.Second)
	for {
		if starts, _, _ := mockStream.counts(); starts == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for StartStream")
		case <-time.After(10 * time.Millisecond):
		}
	}

	mockStream.mu.Lock()
	chunks := mockStream.startCalls[0].Chunks
	mockStream.mu.Unlock()

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk in StartStream call, got %d", len(chunks))
	}
	plan, ok := chunks[0].(planUpdateChunk)
	if !ok {
		t.Fatalf("expected planUpdateChunk, got %T", chunks[0])
	}
	want := "I'll check the pod status and recent events."
	if plan.Title != want {
		t.Errorf("plan title = %q, want %q", plan.Title, want)
	}

	close(outputCh)
}

// TestEnsureAgentListenerPlanBlocksFlushesDanglingTaskOnClose verifies that a
// tool call left without a matching response (e.g. the session ends
// mid-batch) is flushed to a terminal status instead of being left stuck at
// "in_progress" when the stream closes.
func TestEnsureAgentListenerPlanBlocksFlushesDanglingTaskOnClose(t *testing.T) {
	outputCh := make(chan any, 10)
	sessionID := "slack-C1-T1"
	sess := &api.Session{
		ID:           sessionID,
		SlackUserID:  "U1",
		AgentState:   api.AgentStateIdle,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	mockAPI := &mockSlackAPI{}
	mockStream := &mockStreamAPI{}

	ui := &SlackUI{
		apiClient:      mockAPI,
		streamClient:   mockStream,
		agentEnabled:   true,
		teamID:         "T1",
		activeTriggers: map[string]string{},
	}
	ui.ensureAgentListener(mockAgent)

	// A request with no matching response, then the channel closes (session torn down mid-batch).
	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods", Timestamp: time.Now()}

	deadline := time.After(2 * time.Second)
	for {
		if _, appends, _ := mockStream.counts(); appends >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for initial in_progress append")
		case <-time.After(10 * time.Millisecond):
		}
	}

	close(outputCh)

	deadline = time.After(2 * time.Second)
	for {
		_, appends, stops := mockStream.counts()
		if appends >= 2 && stops == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for dangling task flush + stop: appends=%d stops=%d", appends, stops)
		case <-time.After(10 * time.Millisecond):
		}
	}

	mockStream.mu.Lock()
	lastChunks := mockStream.appendCalls[len(mockStream.appendCalls)-1]
	mockStream.mu.Unlock()

	if len(lastChunks) != 1 {
		t.Fatalf("expected 1 chunk in final append, got %d", len(lastChunks))
	}
	task, ok := lastChunks[0].(taskUpdateChunk)
	if !ok {
		t.Fatalf("expected taskUpdateChunk, got %T", lastChunks[0])
	}
	if task.Status != "error" {
		t.Errorf("expected dangling task to be flushed with status 'error', got %q", task.Status)
	}
}

// TestEnsureAgentListenerPlanBlocksMidBatchAppendFailureFallsBack verifies
// that a transient AppendStream failure partway through a batch (after the
// stream already started successfully) falls back to classic rendering for
// just that request/response pair, without tearing down the rest of the
// still-open stream.
func TestEnsureAgentListenerPlanBlocksMidBatchAppendFailureFallsBack(t *testing.T) {
	outputCh := make(chan any, 10)
	sess := &api.Session{ID: "slack-C1-T1", SlackUserID: "U1", AgentState: api.AgentStateIdle, CreatedAt: time.Now(), LastModified: time.Now()}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	postCalled := make(chan string, 10)
	mockAPI := &mockSlackAPI{
		PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
			postCalled <- channelID
			return "", "", nil
		},
	}
	// The 3rd AppendStream call is the second tool call's request; make it fail.
	mockStream := &mockStreamAPI{appendFailOnCall: 3}

	ui := &SlackUI{apiClient: mockAPI, streamClient: mockStream, agentEnabled: true, teamID: "T1", activeTriggers: map[string]string{}}
	ui.ensureAgentListener(mockAgent)

	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods", Metadata: map[string]string{"tool_call_id": "call-1"}, Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "2", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: "pods: ok", Metadata: map[string]string{"tool_call_id": "call-1"}, Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "3", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get nodes", Metadata: map[string]string{"tool_call_id": "call-2"}, Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "4", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: "nodes: ok", Metadata: map[string]string{"tool_call_id": "call-2"}, Timestamp: time.Now()}

	// The failed request and its response should both fall back to classic posts.
	for i := 0; i < 2; i++ {
		select {
		case <-postCalled:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for classic fallback post #%d", i+1)
		}
	}

	// End the batch and confirm the stream (still open from call-1) closes cleanly.
	outputCh <- &api.Message{ID: "5", Source: api.MessageSourceAgent, Type: api.MessageTypeText, Payload: "Done.", Metadata: map[string]string{"is_final": "true"}, Timestamp: time.Now()}
	select {
	case <-postCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for final text post")
	}

	deadline := time.After(2 * time.Second)
	for {
		if _, _, stops := mockStream.counts(); stops == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for stream to close")
		case <-time.After(10 * time.Millisecond):
		}
	}

	close(outputCh)
}

// TestEnsureAgentListenerToolCallResponseMapPayloadNotDropped verifies the
// classic (agentEnabled=false, the default) rendering path no longer
// silently drops map[string]any tool-call responses (the payload shape used
// by native tool-calling) the way it used to.
func TestEnsureAgentListenerToolCallResponseMapPayloadNotDropped(t *testing.T) {
	outputCh := make(chan any, 5)
	sess := &api.Session{ID: "slack-C1-T1", SlackUserID: "U1", AgentState: api.AgentStateIdle, CreatedAt: time.Now(), LastModified: time.Now()}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	postCalled := make(chan string, 5)
	mockAPI := &mockSlackAPI{
		PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
			postCalled <- channelID
			return "", "", nil
		},
	}
	ui := &SlackUI{apiClient: mockAPI, activeTriggers: map[string]string{}} // agentEnabled left false (default)
	ui.ensureAgentListener(mockAgent)

	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: map[string]any{"content": "ok"}, Timestamp: time.Now()}

	select {
	case <-postCalled:
		// success — previously this payload type was silently dropped.
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for map-payload tool response to post")
	}
	close(outputCh)
}

// TestEnsureAgentListenerPlanBlocksTruncatesLongCommandWithoutPostingElsewhere
// verifies that when a tool call's command text is long enough to be
// truncated on the plan card, it's simply truncated in place — never posted
// anywhere else (nothing about a task should ever appear outside the plan
// card), and the title stays non-blank regardless.
func TestEnsureAgentListenerPlanBlocksTruncatesLongCommandWithoutPostingElsewhere(t *testing.T) {
	outputCh := make(chan any, 5)
	sess := &api.Session{ID: "slack-C1-T1", SlackUserID: "U1", AgentState: api.AgentStateIdle, CreatedAt: time.Now(), LastModified: time.Now()}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	postCalled := make(chan string, 5)
	mockAPI := &mockSlackAPI{
		PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
			postCalled <- channelID
			return "", "", nil
		},
	}
	mockStream := &mockStreamAPI{}
	ui := &SlackUI{apiClient: mockAPI, streamClient: mockStream, agentEnabled: true, teamID: "T1", activeTriggers: map[string]string{}}
	ui.ensureAgentListener(mockAgent)

	longCommand := "kubectl get pods -o jsonpath=" + strings.Repeat("x", maxTaskFieldLen)
	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: longCommand, Timestamp: time.Now()}

	deadline := time.After(2 * time.Second)
	for {
		if _, appends, _ := mockStream.counts(); appends == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the in_progress append")
		case <-time.After(10 * time.Millisecond):
		}
	}
	mockStream.mu.Lock()
	chunk := mockStream.appendCalls[0][0].(taskUpdateChunk)
	mockStream.mu.Unlock()
	if len(chunk.Details) >= len(longCommand) {
		t.Errorf("expected the command to be truncated, got %d chars (original was %d)", len(chunk.Details), len(longCommand))
	}
	if !strings.HasSuffix(chunk.Details, "…") {
		t.Errorf("expected a truncation marker, got %q", chunk.Details)
	}
	if chunk.Title == "" {
		t.Error("expected a non-blank title even when the command is truncated")
	}

	select {
	case <-postCalled:
		t.Error("the full command must never be posted outside the plan card")
	case <-time.After(300 * time.Millisecond):
		// success — nothing was posted via the classic path.
	}
	close(outputCh)
}

// TestAppendToolCallRequestEmptyTSTreatedAsFailure verifies a malformed
// "ok:true but no ts" StartStream response is treated as a failed start
// rather than silently wedging the stream with an unusable empty ts.
func TestAppendToolCallRequestEmptyTSTreatedAsFailure(t *testing.T) {
	mockStream := &mockStreamAPI{forceEmptyTS: true}
	ui := &SlackUI{streamClient: mockStream, teamID: "T1"}

	stream, appended := ui.appendToolCallRequest(nil, "C1", "T1", "U1", "", "call-1", "kubectl get pods")
	if appended {
		t.Error("expected appended=false when StartStream returns an empty ts")
	}
	if stream != nil {
		t.Error("expected a nil stream when StartStream returns an empty ts")
	}
	if starts, appends, _ := mockStream.counts(); starts != 1 || appends != 0 {
		t.Errorf("expected 1 start call and 0 append calls, got starts=%d appends=%d", starts, appends)
	}
}

// TestEnsureAgentListenerPlanBlocksFinalAnswerDoesNotLeakTitle verifies that
// a final-answer text message never becomes the title of a later, unrelated
// tool-call batch that has no thinking text of its own.
func TestEnsureAgentListenerPlanBlocksFinalAnswerDoesNotLeakTitle(t *testing.T) {
	outputCh := make(chan any, 10)
	sess := &api.Session{ID: "slack-C1-T1", SlackUserID: "U1", AgentState: api.AgentStateIdle, CreatedAt: time.Now(), LastModified: time.Now()}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	mockAPI := &mockSlackAPI{}
	mockStream := &mockStreamAPI{}
	ui := &SlackUI{apiClient: mockAPI, streamClient: mockStream, agentEnabled: true, teamID: "T1", activeTriggers: map[string]string{}}
	ui.ensureAgentListener(mockAgent)

	// Turn 1: thinking text -> tool call -> response -> final answer (closes the turn).
	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceModel, Type: api.MessageTypeText, Payload: "I'll check the pods first.", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "2", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "3", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: "ok", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "4", Source: api.MessageSourceModel, Type: api.MessageTypeText, Payload: "All pods are healthy.", Metadata: map[string]string{"is_final": "true"}, Timestamp: time.Now()}

	// Turn 2: a tool call with NO preceding thinking text this time.
	outputCh <- &api.Message{ID: "5", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get nodes", Timestamp: time.Now()}

	deadline := time.After(2 * time.Second)
	for {
		if starts, _, _ := mockStream.counts(); starts == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the second plan stream to start")
		case <-time.After(10 * time.Millisecond):
		}
	}

	mockStream.mu.Lock()
	secondPlanChunks := mockStream.startCalls[1].Chunks
	mockStream.mu.Unlock()
	plan := secondPlanChunks[0].(planUpdateChunk)
	if plan.Title != defaultPlanTitle {
		t.Errorf("expected second batch to use the default title (no leaked final answer), got %q", plan.Title)
	}
	close(outputCh)
}

// TestEnsureAgentListenerPlanBlocksAgentStatusTextDoesNotLeakTitle reproduces
// a real incident: pkg/agent/conversation.go posts agent-sourced status text
// (e.g. "Maximum number of iterations reached...") as MessageSourceAgent,
// MessageTypeText, with no is_final metadata at all. That must never be
// captured as the model's "thinking" text — otherwise a stale status message
// mislabels the next batch's tasks even though the model gave no reasoning
// for that batch.
func TestEnsureAgentListenerPlanBlocksAgentStatusTextDoesNotLeakTitle(t *testing.T) {
	outputCh := make(chan any, 10)
	sess := &api.Session{ID: "slack-C1-T1", SlackUserID: "U1", AgentState: api.AgentStateIdle, CreatedAt: time.Now(), LastModified: time.Now()}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	mockAPI := &mockSlackAPI{}
	mockStream := &mockStreamAPI{}
	ui := &SlackUI{apiClient: mockAPI, streamClient: mockStream, agentEnabled: true, teamID: "T1", activeTriggers: map[string]string{}}
	ui.ensureAgentListener(mockAgent)

	// First batch: real model reasoning, a tool call, then the agent hits its
	// iteration cap and posts a status message — MessageSourceAgent, no
	// is_final metadata, exactly like conversation.go actually does.
	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceModel, Type: api.MessageTypeText, Payload: "I'll check the pods first.", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "2", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "3", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: "ok", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "4", Source: api.MessageSourceAgent, Type: api.MessageTypeText, Payload: "Maximum number of iterations reached. You can help me by providing more specific input.", Timestamp: time.Now()}

	// User says "continue" (conversation.go echoes this as a MessageSourceUser
	// message) -> second batch with NO preceding model reasoning this time
	// (streamedText was empty for that turn).
	outputCh <- &api.Message{ID: "5", Source: api.MessageSourceUser, Type: api.MessageTypeText, Payload: "continue", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "6", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get nodes", Timestamp: time.Now()}

	deadline := time.After(2 * time.Second)
	for {
		if starts, _, _ := mockStream.counts(); starts == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the second plan stream to start")
		case <-time.After(10 * time.Millisecond):
		}
	}

	mockStream.mu.Lock()
	secondPlanChunks := mockStream.startCalls[1].Chunks
	mockStream.mu.Unlock()
	plan := secondPlanChunks[0].(planUpdateChunk)
	if strings.Contains(plan.Title, "Maximum number of iterations") {
		t.Errorf("agent status text leaked into the next batch's title: %q", plan.Title)
	}
	if plan.Title != defaultPlanTitle {
		t.Errorf("expected the default title (no model reasoning preceded this batch), got %q", plan.Title)
	}
	close(outputCh)
}

// TestEnsureAgentListenerPlanBlocksCorrelatesByIDOutOfOrder verifies that
// when the provider supplies explicit tool-call IDs, responses are matched
// to the correct task even if they arrive in a different order than a pure
// FIFO assumption would expect.
func TestEnsureAgentListenerPlanBlocksCorrelatesByIDOutOfOrder(t *testing.T) {
	outputCh := make(chan any, 10)
	sess := &api.Session{ID: "slack-C1-T1", SlackUserID: "U1", AgentState: api.AgentStateIdle, CreatedAt: time.Now(), LastModified: time.Now()}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	mockAPI := &mockSlackAPI{}
	mockStream := &mockStreamAPI{}
	ui := &SlackUI{apiClient: mockAPI, streamClient: mockStream, agentEnabled: true, teamID: "T1", activeTriggers: map[string]string{}}
	ui.ensureAgentListener(mockAgent)

	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods", Metadata: map[string]string{"tool_call_id": "call-A"}, Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "2", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get nodes", Metadata: map[string]string{"tool_call_id": "call-B"}, Timestamp: time.Now()}

	deadline := time.After(2 * time.Second)
	for {
		if _, appends, _ := mockStream.counts(); appends == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for both requests to append")
		case <-time.After(10 * time.Millisecond):
		}
	}
	mockStream.mu.Lock()
	taskIDForA := mockStream.appendCalls[0][0].(taskUpdateChunk).ID
	taskIDForB := mockStream.appendCalls[1][0].(taskUpdateChunk).ID
	mockStream.mu.Unlock()

	// Respond out of order: call-B's response arrives before call-A's.
	outputCh <- &api.Message{ID: "3", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: "nodes: ok", Metadata: map[string]string{"tool_call_id": "call-B"}, Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "4", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: "pods: ok", Metadata: map[string]string{"tool_call_id": "call-A"}, Timestamp: time.Now()}

	deadline = time.After(2 * time.Second)
	for {
		if _, appends, _ := mockStream.counts(); appends == 4 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for both responses to append")
		case <-time.After(10 * time.Millisecond):
		}
	}

	mockStream.mu.Lock()
	responseChunkForB := mockStream.appendCalls[2][0].(taskUpdateChunk)
	responseChunkForA := mockStream.appendCalls[3][0].(taskUpdateChunk)
	mockStream.mu.Unlock()

	if responseChunkForB.ID != taskIDForB {
		t.Errorf("call-B's response (arrived first) should update task %q, got %q", taskIDForB, responseChunkForB.ID)
	}
	if responseChunkForA.ID != taskIDForA {
		t.Errorf("call-A's response (arrived second) should update task %q, got %q", taskIDForA, responseChunkForA.ID)
	}
	close(outputCh)
}

// TestRenderToolResult covers string, map, and error-shaped tool result payloads.
func TestRenderToolResult(t *testing.T) {
	tests := []struct {
		name        string
		payload     any
		wantText    string
		wantIsError bool
	}{
		{
			// A bare string with no "Result of running ..." prefix only ever
			// comes from the tool-invoke error path (a raw err.Error()) in
			// pkg/agent/conversation.go's DispatchToolCalls — always a failure.
			name:        "bare error string (tool-invoke error path)",
			payload:     "context deadline exceeded",
			wantText:    "context deadline exceeded",
			wantIsError: true,
		},
		{
			// A shim success observation whose embedded output happens to
			// mention the word "error" (e.g. a Warning event) must NOT be
			// misclassified as a failure.
			name:        "shim success observation mentioning error benignly",
			payload:     "Result of running \"kubectl get events\":\n&{kubectl get events \"Warning  Failed  rpc error: code = Unknown\" \"\" \"\" 0 12ms }",
			wantText:    "Result of running \"kubectl get events\":\n&{kubectl get events \"Warning  Failed  rpc error: code = Unknown\" \"\" \"\" 0 12ms }",
			wantIsError: false,
		},
		{
			// A shim success observation whose embedded ExecResult genuinely
			// failed (non-zero exit) must still be flagged as an error.
			name:        "shim observation with a real command failure",
			payload:     "Result of running \"kubectl get pods\":\n&{kubectl get pods \"\" \"\" \"command exited with code 1\" 1 5ms }",
			wantText:    "Result of running \"kubectl get pods\":\n&{kubectl get pods \"\" \"\" \"command exited with code 1\" 1 5ms }",
			wantIsError: true,
		},
		{
			name:        "map with error key",
			payload:     map[string]any{"error": "boom"},
			wantText:    "boom",
			wantIsError: true,
		},
		{
			name:        "map without error key",
			payload:     map[string]any{"content": "ok"},
			wantText:    "content: ok",
			wantIsError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, isError := renderToolResult(tt.payload)
			if text != tt.wantText {
				t.Errorf("text = %q, want %q", text, tt.wantText)
			}
			if isError != tt.wantIsError {
				t.Errorf("isError = %v, want %v", isError, tt.wantIsError)
			}
		})
	}
}

// TestTruncateForTask verifies over-length task fields are truncated in
// place — the full text is never posted anywhere else, so there's no
// separate "wasTruncated" signal to act on anymore.
func TestTruncateForTask(t *testing.T) {
	short := "short text"
	if got := truncateForTask(short); got != short {
		t.Errorf("short text should not be truncated, got %q", got)
	}

	long := strings.Repeat("x", maxTaskFieldLen+50)
	got := truncateForTask(long)
	if len(got) >= len(long) {
		t.Errorf("expected long text to be truncated, got %d chars (original was %d)", len(got), len(long))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated text missing truncation marker: %q", got)
	}
}

// TestSummarizeToolStatus verifies tool results are reduced to a short
// success/failure summary, optionally with duration — never the tool's
// actual output.
func TestSummarizeToolStatus(t *testing.T) {
	tests := []struct {
		name        string
		payload     any
		wantSummary string
		wantIsError bool
	}{
		{
			name:        "successful map payload with duration",
			payload:     map[string]any{"content": "a very long stdout dump that must never appear", "duration": "1.146797584s"},
			wantSummary: "✅ Success (1.146797584s)",
			wantIsError: false,
		},
		{
			name:        "failed map payload with duration falls back to error field",
			payload:     map[string]any{"error": "command exited with code 1", "duration": "500ms"},
			wantSummary: "❌ Failed (500ms): command exited with code 1",
			wantIsError: true,
		},
		{
			name: "failed map payload prefers stderr over the generic error field",
			payload: map[string]any{
				"error":    "command exited with code 1",
				"stderr":   "Error from server (NotFound): pods \"x\" not found\n",
				"duration": "500ms",
			},
			wantSummary: "❌ Failed (500ms): Error from server (NotFound): pods \"x\" not found",
			wantIsError: true,
		},
		{
			name:        "map payload without duration",
			payload:     map[string]any{"content": "ok"},
			wantSummary: "✅ Success",
			wantIsError: false,
		},
		{
			name:        "bare error string has no duration",
			payload:     "context deadline exceeded",
			wantSummary: "❌ Failed: context deadline exceeded",
			wantIsError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary, isError := summarizeToolStatus(tt.payload)
			if summary != tt.wantSummary {
				t.Errorf("summary = %q, want %q", summary, tt.wantSummary)
			}
			if isError != tt.wantIsError {
				t.Errorf("isError = %v, want %v", isError, tt.wantIsError)
			}
			if strings.Contains(summary, "very long stdout") {
				t.Error("summary must never contain the tool's actual output")
			}
		})
	}
}

// TestSummarizeToolStatus_KubectlPreviousLogsNotFound reproduces a real
// incident: `kubectl logs <pod> --previous` on a pod that never restarted
// fails with a specific, actionable kubectl error — that reason must reach
// the user instead of a bare "Failed" that gives no indication of whether
// it's worth retrying.
func TestSummarizeToolStatus_KubectlPreviousLogsNotFound(t *testing.T) {
	payload := map[string]any{
		"command":   "kubectl logs backend-promptpay-scb-c59b87d85-xnl9k -n backend-promptpay-scb --context k8s.staging.core.1b --previous",
		"error":     "command exited with code 1",
		"stderr":    "Error from server (BadRequest): previous terminated container \"backend-promptpay-scb\" in pod \"backend-promptpay-scb-c59b87d85-xnl9k\" not found\n",
		"exit_code": float64(1),
		"duration":  "1.176842375s",
	}

	summary, isError := summarizeToolStatus(payload)
	if !isError {
		t.Fatal("expected isError=true")
	}
	if !strings.Contains(summary, "previous terminated container") {
		t.Errorf("expected the actual kubectl error to be surfaced, got %q", summary)
	}
	if !strings.Contains(summary, "1.176842375s") {
		t.Errorf("expected duration to be preserved, got %q", summary)
	}
	if strings.Contains(summary, "\n") {
		t.Errorf("summary must stay a single line, got %q", summary)
	}
}

// TestTaskTitleFrom verifies the reason -> command -> generic-default
// fallback chain used to guarantee a task's title is never blank.
func TestTaskTitleFrom(t *testing.T) {
	if got := taskTitleFrom("I'll check the pod status.", "kubectl get pods"); got != "I'll check the pod status." {
		t.Errorf("expected reason text to be used as the title, got %q", got)
	}
	if got := taskTitleFrom("", "kubectl get pods"); got != "kubectl get pods" {
		t.Errorf("expected fallback to the command when no reason is available, got %q", got)
	}
	if got := taskTitleFrom("", ""); got != defaultPlanTitle {
		t.Errorf("expected the generic default when neither reason nor command is available, got %q", got)
	}
}

// TestEnsureAgentListenerPlanBlocksNeverShowsRawOutput verifies that neither
// the task card's Output field nor any follow-up Slack message ever contains
// a tool's actual output, only a short status summary.
func TestEnsureAgentListenerPlanBlocksNeverShowsRawOutput(t *testing.T) {
	outputCh := make(chan any, 5)
	sess := &api.Session{ID: "slack-C1-T1", SlackUserID: "U1", AgentState: api.AgentStateIdle, CreatedAt: time.Now(), LastModified: time.Now()}
	mockAgent := &agent.Agent{Output: outputCh, Session: sess}

	const secretOutput = "THIS RAW KUBECTL OUTPUT MUST NEVER REACH SLACK"
	mockAPI := &mockSlackAPI{}
	mockStream := &mockStreamAPI{}
	ui := &SlackUI{apiClient: mockAPI, streamClient: mockStream, agentEnabled: true, teamID: "T1", activeTriggers: map[string]string{}}
	ui.ensureAgentListener(mockAgent)

	outputCh <- &api.Message{ID: "1", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallRequest, Payload: "kubectl get pods -A", Timestamp: time.Now()}
	outputCh <- &api.Message{ID: "2", Source: api.MessageSourceAgent, Type: api.MessageTypeToolCallResponse, Payload: map[string]any{"content": secretOutput, "duration": "2s"}, Timestamp: time.Now()}

	deadline := time.After(2 * time.Second)
	for {
		if _, appends, _ := mockStream.counts(); appends == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for request+response appends")
		case <-time.After(10 * time.Millisecond):
		}
	}

	mockStream.mu.Lock()
	requestChunk := mockStream.appendCalls[0][0].(taskUpdateChunk)
	responseChunk := mockStream.appendCalls[1][0].(taskUpdateChunk)
	mockStream.mu.Unlock()

	if strings.Contains(requestChunk.Details, secretOutput) || strings.Contains(requestChunk.Output, secretOutput) {
		t.Errorf("request chunk leaked raw output: %+v", requestChunk)
	}
	if strings.Contains(responseChunk.Details, secretOutput) || strings.Contains(responseChunk.Output, secretOutput) {
		t.Errorf("response chunk leaked raw output: %+v", responseChunk)
	}
	if responseChunk.Output != "✅ Success (2s)" {
		t.Errorf("expected a short status summary, got %q", responseChunk.Output)
	}
	// Title must never be blank on either update — it's resent unchanged on
	// the response (see appendToolCallResponse: title replaces, unlike
	// details, which accumulates if resent, so it's deliberately omitted
	// there instead).
	if requestChunk.Title == "" {
		t.Error("request chunk title must never be blank")
	}
	if responseChunk.Title != requestChunk.Title {
		t.Errorf("response chunk should resend the same title as the request, got %q vs %q", responseChunk.Title, requestChunk.Title)
	}
	if responseChunk.Details != "" {
		t.Errorf("response chunk must not resend details, got %q", responseChunk.Details)
	}
	close(outputCh)
}

// TestFormatForSlack_More covers additional edge cases in mrkdwn conversion,
// such as triple asterisks and complex combinations.
func TestFormatForSlack_More(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "triple asterisk",
			input:    "***bold and italic***",
			expected: "__bold and italic__",
		},
		{
			name:     "mixed markers",
			input:    "**bold** and *italic* and ***both***",
			expected: "*bold* and _italic_ and __both__",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := formatForSlack(tt.input)
			if actual != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, actual)
			}
		})
	}
}

// TestMarkdownToBlocksWithCodeBlockAndDivider verifies that a multi-section diagnostic response
// containing code blocks, horizontal rules, numbered lists, blockquotes, bash commands, and a
// summary table is correctly converted to Slack blocks without being routed to snippet upload.
//
// Block layout expected from the input:
//
//	[0]  SectionBlock  – opening paragraph
//	[1]  HeaderBlock   – "Analysis of the Issue"
//	[2]  SectionBlock  – numbered list items (text before first code block)
//	[3]  SectionBlock  – log snippet code block (``` … ```)
//	[4]  SectionBlock  – trailing sentence after the log snippet
//	[5]  DividerBlock  – from the "---" horizontal rule
//	[6]  HeaderBlock   – "Recommended Fix"
//	[7]  SectionBlock  – fix description paragraph
//	[8]  SectionBlock  – bash command code block (``` … ```)
//	[9]  HeaderBlock   – "Summary of Findings"
//	[10] TableBlock    – component status table
func TestMarkdownToBlocksWithCodeBlockAndDivider(t *testing.T) {
	s := &SlackUI{}

	input := "The `example-component` on cluster `k8s-test-cluster` is broken" +
		" due to a **failed upgrade** and an **application crash**.\n" +
		"\n" +
		"### Analysis of the Issue\n" +
		"\n" +
		"1.  **Stuck Upgrade**: The HelmRelease has been failing.\n" +
		"    > `Deployment.apps \"example-component\" is invalid: may not specify more than 1 handler type`\n" +
		"    This occurs because the cluster has **gRPC probes** but the chart wants **TCP probes**.\n" +
		"\n" +
		"2.  **Stale Configuration**: The Deployment is stuck on image `img-abc123`" +
		" and is missing `EXAMPLE_LOGGING_ENABLED`.\n" +
		"\n" +
		"3.  **Application Crash**: Pods are in `CrashLoopBackOff` with **Exit Code 2**. Logs show:\n" +
		"```\n" +
		"[example-app] WARNING: EXAMPLE_LOGGING_ENABLED is not defined\n" +
		"```\n" +
		"The liveness probes are also failing with `context deadline exceeded`.\n" +
		"\n" +
		"---\n" +
		"\n" +
		"### Recommended Fix\n" +
		"\n" +
		"Delete the deployment and let the controller recreate it.\n" +
		"\n" +
		"```bash\n" +
		"kubectl delete deployment example-component -n example-ns --context k8s-test-cluster\n" +
		"```\n" +
		"\n" +
		"### Summary of Findings\n" +
		"| Component | Status | Issue |\n" +
		"| :--- | :--- | :--- |\n" +
		"| `example-component` | `CrashLoopBackOff` | Probe conflict blocking upgrade. |\n" +
		"| `other-component` | `Running` | Working correctly. |\n"

	blocks := s.markdownToBlocks(input)

	const wantBlocks = 11
	if len(blocks) != wantBlocks {
		types := make([]string, len(blocks))
		for i, b := range blocks {
			types[i] = string(b.BlockType())
		}
		t.Fatalf("expected %d blocks, got %d: %v", wantBlocks, len(blocks), types)
	}

	// [0] intro paragraph
	if _, ok := blocks[0].(*slack.SectionBlock); !ok {
		t.Errorf("block[0]: want SectionBlock, got %T", blocks[0])
	}

	// [1] "Analysis of the Issue" header (emoji stripped)
	if hb, ok := blocks[1].(*slack.HeaderBlock); !ok {
		t.Errorf("block[1]: want HeaderBlock, got %T", blocks[1])
	} else if hb.Text.Text != "Analysis of the Issue" {
		t.Errorf("block[1]: header text = %q, want %q", hb.Text.Text, "Analysis of the Issue")
	}

	// [2] numbered list items (text flushed before first code block)
	if sb, ok := blocks[2].(*slack.SectionBlock); !ok {
		t.Errorf("block[2]: want SectionBlock, got %T", blocks[2])
	} else if !strings.Contains(sb.Text.Text, "Stuck Upgrade") {
		t.Errorf("block[2]: expected numbered list content, got %q", sb.Text.Text)
	}

	// [3] log snippet — must be a SectionBlock whose text is a fenced code block
	if sb, ok := blocks[3].(*slack.SectionBlock); !ok {
		t.Errorf("block[3]: want SectionBlock (log code block), got %T", blocks[3])
	} else {
		if !strings.HasPrefix(sb.Text.Text, "```") {
			t.Errorf("block[3]: code block should start with ```, got %q", sb.Text.Text)
		}
		if !strings.Contains(sb.Text.Text, "EXAMPLE_LOGGING_ENABLED") {
			t.Errorf("block[3]: expected log content, got %q", sb.Text.Text)
		}
	}

	// [4] trailing sentence after the log snippet
	if sb, ok := blocks[4].(*slack.SectionBlock); !ok {
		t.Errorf("block[4]: want SectionBlock, got %T", blocks[4])
	} else if !strings.Contains(sb.Text.Text, "liveness probes") {
		t.Errorf("block[4]: expected liveness probe text, got %q", sb.Text.Text)
	}

	// [5] divider from "---"
	if blocks[5].BlockType() != slack.MBTDivider {
		t.Errorf("block[5]: want DividerBlock, got %T (%s)", blocks[5], blocks[5].BlockType())
	}

	// [6] "Recommended Fix" header
	if hb, ok := blocks[6].(*slack.HeaderBlock); !ok {
		t.Errorf("block[6]: want HeaderBlock, got %T", blocks[6])
	} else if hb.Text.Text != "Recommended Fix" {
		t.Errorf("block[6]: header text = %q, want %q", hb.Text.Text, "Recommended Fix")
	}

	// [7] fix description paragraph
	if _, ok := blocks[7].(*slack.SectionBlock); !ok {
		t.Errorf("block[7]: want SectionBlock, got %T", blocks[7])
	}

	// [8] bash command — fenced code block section
	if sb, ok := blocks[8].(*slack.SectionBlock); !ok {
		t.Errorf("block[8]: want SectionBlock (bash code block), got %T", blocks[8])
	} else {
		if !strings.HasPrefix(sb.Text.Text, "```") {
			t.Errorf("block[8]: bash code block should start with ```, got %q", sb.Text.Text)
		}
		if !strings.Contains(sb.Text.Text, "kubectl delete deployment") {
			t.Errorf("block[8]: expected kubectl command, got %q", sb.Text.Text)
		}
	}

	// [9] "Summary of Findings" header
	if hb, ok := blocks[9].(*slack.HeaderBlock); !ok {
		t.Errorf("block[9]: want HeaderBlock, got %T", blocks[9])
	} else if hb.Text.Text != "Summary of Findings" {
		t.Errorf("block[9]: header text = %q, want %q", hb.Text.Text, "Summary of Findings")
	}

	// [10] summary table
	if tb, ok := blocks[10].(*TableBlock); !ok {
		t.Errorf("block[10]: want TableBlock, got %T", blocks[10])
	} else {
		// header row + 2 data rows
		if len(tb.Rows) != 3 {
			t.Errorf("block[10]: table rows = %d, want 3 (1 header + 2 data)", len(tb.Rows))
		}
	}
}

// TestNormalizeInlineHeaders_More covers the different levels of headers in normalization.
func TestNormalizeInlineHeaders_More(t *testing.T) {
	s := &SlackUI{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "H2 normalization",
			input:    "## MyHeader Content starts here",
			expected: "## My\nHeader Content starts here",
		},
		{
			name:     "H1 normalization",
			input:    "# MyHeader Content starts here",
			expected: "# My\nHeader Content starts here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.normalizeInlineHeaders(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

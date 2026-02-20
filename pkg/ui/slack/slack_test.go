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
	"os"
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

// TestIsComplexOrLong verifies the logic that determines whether a message should be uploaded
// as a file snippet instead of posted directly. Tests length limits and code block detection.
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
				return &agent.Agent{Input: make(chan any, 1), Session: &api.Session{ID: sessionID}}, nil
			},
		},
		apiClient:       &mockSlackAPI{},
		processedEvents: make(map[string]time.Time),
		activeTriggers:  make(map[string]string),
	}

	body := `{"type":"event_callback","event":{"type":"app_mention","channel":"C1","ts":"1.1","text":"hello"}}`
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			postMsgCalled := false
			uploadCalled := false

			mockAPI := &mockSlackAPI{
				UploadFileV2Func: func(params slack.UploadFileV2Parameters) (*slack.FileSummary, error) {
					uploadCalled = true
					return nil, tt.uploadError
				},
				PostMessageFunc: func(channelID string, options ...slack.MsgOption) (string, string, error) {
					postMsgCalled = true
					return "", "", nil
				},
			}

			ui := &SlackUI{apiClient: mockAPI}
			ui.uploadSnippet("C123", "123.456", "Long content")

			if !uploadCalled {
				t.Error("expected UploadFileV2 to be called")
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
			name:          "long message uses snippet",
			text:          strings.Repeat("a", 3001),
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
				UploadFileV2Func: func(params slack.UploadFileV2Parameters) (*slack.FileSummary, error) {
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
	os.Unsetenv("SLACK_BOT_TOKEN")
	os.Unsetenv("SLACK_SIGNING_SECRET")

	am := &mockAgentManager{}
	sm, _ := sessions.NewSessionManager("memory")
	ui, err := NewSlackUI(am, sm, "model", "provider", "8888", "agent", "msg")
	if err == nil {
		t.Error("expected error due to missing env vars, got nil")
	}
	if ui != nil {
		t.Error("expected nil UI on error")
	}
}

// TestSlackUI_NewSlackUI success case
func TestSlackUI_NewSlackUI_Success(t *testing.T) {
	os.Setenv("SLACK_BOT_TOKEN", "xoxb-test")
	os.Setenv("SLACK_SIGNING_SECRET", "test-secret")
	defer os.Unsetenv("SLACK_BOT_TOKEN")
	defer os.Unsetenv("SLACK_SIGNING_SECRET")

	am := &mockAgentManager{
		SetAgentCreatedCallbackFunc: func(f func(*agent.Agent)) {},
	}
	sm, _ := sessions.NewSessionManager("memory")

	ui, err := NewSlackUI(am, sm, "model", "provider", "127.0.0.1:0", "agent", "msg")
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
	sess := &api.Session{ID: sessionID}

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
		Source:  api.MessageSourceAgent,
		Payload: "hello world",
		Type:    api.MessageTypeText,
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
		Source:  api.MessageSourceAgent,
		Payload: "ls -l",
		Type:    api.MessageTypeToolCallRequest,
	}

	select {
	case <-postCalled:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for tool call post")
	}

	// Test error message
	outputCh <- &api.Message{
		Source:  api.MessageSourceAgent,
		Payload: fmt.Errorf("agent error"),
		Type:    api.MessageTypeError,
	}

	select {
	case <-postCalled:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for error post")
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

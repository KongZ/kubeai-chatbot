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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/KongZ/kubeai-chatbot/pkg/agent"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/KongZ/kubeai-chatbot/pkg/sessions"
	"github.com/KongZ/kubeai-chatbot/pkg/ui"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"k8s.io/klog/v2"
)

// SlackAPI defines the interface for Slack client methods used by SlackUI
type SlackAPI interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
	UploadFileV2(params slack.UploadFileV2Parameters) (*slack.FileSummary, error)
	AddReaction(name string, item slack.ItemRef) error
	RemoveReaction(name string, item slack.ItemRef) error
}

// AgentManager defines the interface for agent management methods used by SlackUI
type AgentManager interface {
	GetAgent(ctx context.Context, sessionID string) (*agent.Agent, error)
	SetAgentCreatedCallback(func(*agent.Agent))
}

type SlackUI struct {
	httpServer         *http.Server
	httpServerListener net.Listener

	manager         AgentManager
	sessionManager  *sessions.SessionManager
	defaultModel    string
	defaultProvider string
	botToken        string
	signingSecret   string
	agentName       string
	contextMessage  string
	apiClient       SlackAPI

	mu              sync.Mutex
	processedEvents map[string]time.Time
	activeTriggers  map[string]string // sessionID -> user message ts
}

var _ ui.UI = &SlackUI{}

func NewSlackUI(manager AgentManager, sessionManager *sessions.SessionManager, defaultModel, defaultProvider, listenAddress, agentName, contextMessage string) (*SlackUI, error) {
	botToken := os.Getenv("SLACK_BOT_TOKEN")
	signingSecret := os.Getenv("SLACK_SIGNING_SECRET")
	if botToken == "" || signingSecret == "" {
		return nil, fmt.Errorf("SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET environment variable not set")
	}

	apiClient := slack.New(botToken)

	s := &SlackUI{
		manager:         manager,
		sessionManager:  sessionManager,
		defaultModel:    defaultModel,
		defaultProvider: defaultProvider,
		botToken:        botToken,
		signingSecret:   signingSecret,
		agentName:       agentName,
		contextMessage:  contextMessage,
		apiClient:       apiClient,
		processedEvents: make(map[string]time.Time),
		activeTriggers:  make(map[string]string),
	}

	// Register callback to listen to new agents
	manager.SetAgentCreatedCallback(func(a *agent.Agent) {
		s.ensureAgentListener(a)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/slack/events", s.handleSlackEvents)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	httpServer := &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("starting slack ui listener: %w", err)
	}

	endpoint := listener.Addr()
	s.httpServerListener = listener
	s.httpServer = httpServer

	fmt.Fprintf(os.Stdout, "listening on http://%s\n", endpoint)
	return s, nil
}

func (s *SlackUI) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(s.httpServerListener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (s *SlackUI) ClearScreen() {
	// Not applicable
}

func (s *SlackUI) handleSlackEvents(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sv, err := slack.NewSecretsVerifier(r.Header, s.signingSecret)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := sv.Write(body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := sv.Ensure(); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	eventsAPIEvent, err := slackevents.ParseEvent(json.RawMessage(body), slackevents.OptionNoVerifyToken())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if eventsAPIEvent.Type == slackevents.URLVerification {
		var r *slackevents.ChallengeResponse
		err := json.Unmarshal([]byte(body), &r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(r.Challenge)); err != nil {
			klog.Errorf("failed to write challenge response: %v", err)
		}
		return
	}

	if eventsAPIEvent.Type == slackevents.CallbackEvent {
		innerEvent := eventsAPIEvent.InnerEvent
		var channel, ts, threadTs, text string

		switch ev := innerEvent.Data.(type) {
		case *slackevents.AppMentionEvent:
			channel, ts, threadTs, text = ev.Channel, ev.TimeStamp, ev.ThreadTimeStamp, ev.Text
		case *slackevents.MessageEvent:
			// Ignore messages from bots to prevent loops
			if ev.BotID != "" || ev.SubType == "bot_message" {
				w.WriteHeader(http.StatusOK)
				return
			}
			channel, ts, threadTs, text = ev.Channel, ev.TimeStamp, ev.ThreadTimeStamp, ev.Text
		default:
			w.WriteHeader(http.StatusOK)
			return
		}

		// De-duplicate: Slack might send both app_mention and message events for the same mention
		// or retry if we are slow.
		msgID := fmt.Sprintf("%s:%s", channel, ts)
		s.mu.Lock()
		if _, ok := s.processedEvents[msgID]; ok {
			s.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}

		// Cleanup old entries (older than 10 mins) every 100 messages to avoid leak
		if len(s.processedEvents) > 100 {
			now := time.Now()
			for k, v := range s.processedEvents {
				if now.Sub(v) > 10*time.Minute {
					delete(s.processedEvents, k)
				}
			}
		}

		s.processedEvents[msgID] = time.Now()
		s.mu.Unlock()

		// Acknowledge immediately to Slack to avoid retries
		w.WriteHeader(http.StatusOK)

		// Process in background
		go s.processMessage(channel, threadTs, ts, text)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *SlackUI) processMessage(channel, threadTS, ts, text string) {
	// Clean text (remove bot mention if any)
	// Mentions look like <@U123456>
	processedText := text
	for {
		start := strings.Index(processedText, "<@")
		if start == -1 {
			break
		}
		end := strings.Index(processedText[start:], ">")
		if end == -1 {
			break
		}
		processedText = processedText[:start] + strings.TrimSpace(processedText[start+end+1:])
	}

	// If threadTS is empty, use ts (start of a new thread)
	effectiveThreadTS := threadTS
	if effectiveThreadTS == "" {
		effectiveThreadTS = ts
	}

	sessionID := fmt.Sprintf("slack-%s-%s", channel, effectiveThreadTS)
	ctx := context.Background()

	// Check if session exists
	_, err := s.sessionManager.FindSessionByID(sessionID)
	if err != nil {
		// Session not found, create new one
		meta := sessions.Metadata{
			ModelID:    s.defaultModel,
			ProviderID: s.defaultProvider,
		}
		session, err := s.sessionManager.NewSessionWithID(sessionID, meta)
		if err != nil {
			klog.Errorf("Failed to create session for Slack: %v", err)
			return
		}
		session.Name = "Slack Thread " + effectiveThreadTS
		if err := s.sessionManager.UpdateLastAccessed(session); err != nil {
			klog.Warningf("Failed to update session name: %v", err)
		}
	}

	// Get or create agent
	agent, err := s.manager.GetAgent(ctx, sessionID)
	if err != nil {
		klog.Errorf("Failed to get/create agent for Slack: %v", err)
		return
	}

	// Add typing indicator reaction
	s.mu.Lock()
	s.activeTriggers[sessionID] = ts
	s.mu.Unlock()
	if err := s.apiClient.AddReaction("ok_hand", slack.NewRefToMessage(channel, ts)); err != nil {
		klog.Warningf("Failed to add ok_hand reaction: %v", err)
	}

	// Send message to agent
	agent.Input <- &api.UserInputResponse{Query: processedText}
}

func (s *SlackUI) ensureAgentListener(a *agent.Agent) {
	// Extract channel and thread from session ID
	sessionID := a.Session.ID
	if !strings.HasPrefix(sessionID, "slack-") {
		// This agent is not managed by Slack UI
		return
	}

	parts := strings.SplitN(sessionID, "-", 3)
	if len(parts) < 3 {
		klog.Errorf("Invalid Slack session ID format: %s", sessionID)
		return
	}
	channel := parts[1]
	threadTS := parts[2]

	// Start a single goroutine for this agent's lifetime
	go func() {
		indicatorRemoved := false
		for msg := range a.Output {
			apiMsg, ok := msg.(*api.Message)
			if !ok {
				continue
			}

			// Remove typing indicator on first message from agent
			if !indicatorRemoved {
				s.mu.Lock()
				triggerTS, exists := s.activeTriggers[sessionID]
				if exists {
					delete(s.activeTriggers, sessionID)
					s.mu.Unlock()
					if err := s.apiClient.RemoveReaction("thinking_face", slack.NewRefToMessage(channel, triggerTS)); err != nil {
						klog.Warningf("Failed to remove thinking reaction: %v", err)
					}
				} else {
					s.mu.Unlock()
				}
				indicatorRemoved = true
			}

			// Only post agent or model messages to Slack
			if apiMsg.Source == api.MessageSourceAgent || apiMsg.Source == api.MessageSourceModel {
				if text, ok := apiMsg.Payload.(string); ok && text != ">>>" {
					if apiMsg.Type == api.MessageTypeToolCallRequest {
						// Wrap tool calls in code blocks for better visibility
						text = "```\n" + text + "\n```"
					}
					isFinal := false
					if apiMsg.Metadata != nil && apiMsg.Metadata["is_final"] == "true" {
						isFinal = true
					}
					s.postToSlack(channel, threadTS, text, isFinal)
				} else if choiceReq, ok := apiMsg.Payload.(*api.UserChoiceRequest); ok {
					prompt := choiceReq.Prompt
					// Attempt to identify and format command
					if strings.Contains(prompt, "kubectl") && !strings.Contains(prompt, "```") && !strings.Contains(prompt, "`") {
						// This is a naive heuristic but might help.
						// Better: let's try to split by "command:" or similar keywords if present.
						parts := strings.SplitN(prompt, "command:", 2)
						if len(parts) == 2 {
							pre := strings.TrimSpace(parts[0])
							cmd := strings.TrimSpace(parts[1])
							prompt = fmt.Sprintf("%s command:\n```%s```", pre, cmd)
						}
					}
					s.postToSlack(channel, threadTS, prompt, true)
				} else if errPayload, ok := apiMsg.Payload.(error); ok {
					s.postToSlack(channel, threadTS, "Error: "+errPayload.Error(), true)
				}
			}
		}
		klog.Infof("Slack listener for session %s terminated", sessionID)
	}()
}

func (s *SlackUI) postToSlack(channel, threadTS, text string, includeContext bool) {
	if isComplexOrLong(text) {
		s.uploadSnippet(channel, threadTS, text)
		return
	}

	blocks := s.generateBlocks(text, includeContext)

	// Debug logging of blocks (Trace-level: v=4)
	if klog.V(4).Enabled() {
		if blockJSON, err := json.Marshal(blocks); err == nil {
			klog.Infof("Posting to Slack channel %s: %s", channel, string(blockJSON))
		}
	}

	// Fallback text for notifications
	fallback := text
	if len(fallback) > 150 {
		fallback = fallback[:150] + "..."
	}

	_, _, err := s.apiClient.PostMessage(channel,
		slack.MsgOptionText(fallback, false),
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionTS(threadTS),
	)
	if err != nil {
		klog.Errorf("Failed to post message to Slack: %v", err)
	}
}

func (s *SlackUI) getContextBlock() slack.Block {
	contextText := fmt.Sprintf("%s: %s", s.agentName, s.contextMessage)
	return slack.NewContextBlock("",
		slack.NewTextBlockObject(slack.MarkdownType, contextText, false, false),
	)
}

func (s *SlackUI) generateBlocks(text string, includeContext bool) []slack.Block {
	blocks := s.markdownToBlocks(text)
	if includeContext {
		blocks = append(blocks, s.getContextBlock())
	}
	return blocks
}

func (s *SlackUI) markdownToBlocks(text string) []slack.Block {
	var blocks []slack.Block
	lines := strings.Split(text, "\n")

	var currentParagraph []string
	var tableLines []string
	inTable := false

	flushParagraph := func() {
		if len(currentParagraph) > 0 {
			paraText := strings.TrimSpace(strings.Join(currentParagraph, "\n"))
			if paraText != "" {
				blocks = append(blocks, slack.NewSectionBlock(
					slack.NewTextBlockObject(slack.MarkdownType, formatForSlack(paraText), false, false),
					nil, nil,
				))
			}
			currentParagraph = nil
		}
	}

	flushTable := func() {
		if len(tableLines) > 0 {
			headers, rows := s.parseMarkdownTable(tableLines)
			if (len(headers) > 0 || len(rows) > 0) && len(headers) <= 10 && len(rows) <= 10 {
				blocks = append(blocks, NewTableBlock(headers, rows))
			} else if len(headers) > 0 {
				// Fallback to code block if table is too big for native TableBlock
				// or if it's missing the separator (though parseMarkdownTable checks that)
				tableText := strings.Join(tableLines, "\n")
				blocks = append(blocks, slack.NewSectionBlock(
					slack.NewTextBlockObject(slack.MarkdownType, "```\n"+tableText+"\n```", false, false),
					nil, nil,
				))
			} else {
				// Not a valid table, treat as paragraph
				currentParagraph = append(currentParagraph, tableLines...)
			}
			tableLines = nil
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for headers (e.g., # Header, ## Header, ### Header)
		isHeader := strings.HasPrefix(trimmed, "# ") || strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ")

		if isHeader {
			flushParagraph()
			flushTable()
			headerText := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			blocks = append(blocks, slack.NewHeaderBlock(
				slack.NewTextBlockObject(slack.PlainTextType, headerText, false, false),
			))
			inTable = false
			continue
		}

		isTableRow := strings.HasPrefix(trimmed, "|") || (strings.Contains(trimmed, "|") && len(strings.Split(trimmed, "|")) > 2)

		if isTableRow {
			if !inTable {
				flushParagraph()
				inTable = true
			}
			tableLines = append(tableLines, line)
		} else {
			if inTable {
				// Check if we were just in a table
				// If strictly transitioning out, check if it was really a table (had separator)
				hasSeparator := false
				for _, tl := range tableLines {
					if strings.Contains(tl, "---") {
						hasSeparator = true
						break
					}
				}

				if hasSeparator {
					flushTable()
				} else {
					currentParagraph = append(currentParagraph, tableLines...)
					tableLines = nil
				}
				inTable = false
			}
			currentParagraph = append(currentParagraph, line)
		}
	}

	// Final flushes
	if inTable {
		hasSeparator := false
		for _, tl := range tableLines {
			if strings.Contains(tl, "---") {
				hasSeparator = true
				break
			}
		}
		if hasSeparator {
			flushTable()
		} else {
			currentParagraph = append(currentParagraph, tableLines...)
		}
	}
	flushParagraph()

	return blocks
}

func (s *SlackUI) parseMarkdownTable(lines []string) ([]string, [][]string) {
	var headers []string
	var rows [][]string

	seenSeparator := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "---") && (strings.HasPrefix(trimmed, "|") || strings.Contains(trimmed, "-|-")) {
			seenSeparator = true
			continue
		}

		// Split by | and clean up
		parts := strings.Split(line, "|")
		var cells []string
		for _, cell := range parts {
			c := strings.TrimSpace(cell)
			if c == "" && (cell == parts[0] || cell == parts[len(parts)-1]) {
				// skip the outer empty parts from | cell | cell |
				continue
			}
			cells = append(cells, c)
		}

		if len(cells) == 0 {
			continue
		}

		if headers == nil {
			headers = cells
		} else if seenSeparator {
			rows = append(rows, cells)
		} else {
			// This might be the header again if we haven't seen separator?
			// In standard MD, header is before separator.
			headers = cells
		}
	}

	if !seenSeparator {
		return nil, nil
	}

	return headers, rows
}

func (s *SlackUI) uploadSnippet(channel, threadTS, text string) {
	klog.Infof("Response too long or complex, uploading as snippet to channel %s", channel)

	params := slack.UploadFileV2Parameters{
		Channel:         channel,
		ThreadTimestamp: threadTS,
		Content:         text,
		Filename:        "response.md",
		Title:           "Kubectl AI Response",
		InitialComment:  "The result is too long, here is a snippet:",
	}

	_, err := s.apiClient.UploadFileV2(params)
	if err != nil {
		klog.Errorf("Failed to upload snippet to Slack: %v", err)
		// Fallback to regular message if upload fails, but truncated
		truncated := text
		if len(truncated) > 3900 {
			truncated = truncated[:3900] + "\n... (truncated)"
		}
		formatted := formatForSlack(truncated)
		if _, _, err := s.apiClient.PostMessage(channel, slack.MsgOptionText(formatted, false), slack.MsgOptionTS(threadTS)); err != nil {
			klog.Errorf("Failed to post fallback message to Slack: %v", err)
		}
	}
}

func formatForSlack(text string) string {
	// Simple Markdown to mrkdwn conversion

	// 1. Triple asterisks (Bold + Italic)
	reBoldItalic := regexp.MustCompile(`\*\*\*(.*?)\*\*\*`)
	text = reBoldItalic.ReplaceAllString(text, `*_${1}_*`)

	// 2. Double asterisks (Bold)
	// Use placeholder to avoid italic regex matching it
	reBold := regexp.MustCompile(`\*\*(.*?)\*\*`)
	text = reBold.ReplaceAllString(text, `@@@BOLD@@@${1}@@@BOLD@@@`)

	// 3. Single asterisk (Italic)
	reItalic := regexp.MustCompile(`\*([^\s\*].*?[^\s\*])\*`)
	text = reItalic.ReplaceAllString(text, `_${1}_`)

	// 4. Restore Bold
	text = strings.ReplaceAll(text, "@@@BOLD@@@", "*")

	// 5. Links: [text](url) -> <url|text>
	reLink := regexp.MustCompile(`\[(.*?)\]\((.*?)\)`)
	text = reLink.ReplaceAllString(text, `<${2}|${1}>`)

	// 6. Remove language identifier from code blocks: ```go -> ```
	reCodeBlockLang := regexp.MustCompile("```[a-zA-Z0-9+#-]+")
	text = reCodeBlockLang.ReplaceAllString(text, "```")

	return text
}

func isComplexOrLong(text string) bool {
	if len(text) > 3000 {
		return true
	}
	// Detect long code blocks
	if strings.Count(text, "```") >= 2 && len(text) > 1000 {
		return true
	}
	return false
}

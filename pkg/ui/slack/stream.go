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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

const slackAPIBaseURL = "https://slack.com/api"

// SlackStreamAPI defines the interface for Slack's streaming chat methods
// (chat.startStream / chat.appendStream / chat.stopStream). These render a
// batch of tool calls as a single updating "Plan" card instead of a
// sequence of separate messages. As of writing, slack-go/slack has no
// bindings for them, so httpStreamClient calls the Slack Web API directly.
type SlackStreamAPI interface {
	StartStream(req startStreamRequest) (ts string, err error)
	AppendStream(channel, ts string, chunks []any) error
	StopStream(channel, ts string, chunks []any) error
}

// pendingTask tracks one tool call awaiting a response on an open stream.
// toolCallID is the LLM's own tool-call ID (gollm.FunctionCall.ID, attached
// to the api.Message as metadata by pkg/agent/conversation.go) when the
// provider sets one; some providers/paths (Ollama, llama.cpp, the ReAct
// tool-use shim) never populate it, in which case it's empty.
//
// title is remembered and resent on the response update: confirmed by real
// usage that Slack's task_update "title" is a plain replace-on-update field
// that goes blank if omitted, unlike "details" (see below), which must NOT
// be resent — confirmed by real usage that repeating identical "details"
// text visibly duplicates it, implying Slack accumulates that field (e.g.
// as a list of entries) rather than replacing it.
type pendingTask struct {
	toolCallID string
	taskID     string
	title      string
}

// toolCallStream tracks an open Slack streaming message for one batch of
// tool calls. Responses are correlated to their request primarily by the
// explicit tool-call ID when the provider supplies one (robust even if
// dispatch is ever parallelized); when it's empty or doesn't match anything
// pending, it falls back to arrival order (FIFO), which is correct as long
// as tool dispatch stays strictly sequential (true today for every path).
type toolCallStream struct {
	channel      string
	ts           string
	pendingTasks []pendingTask
	nextTaskID   int
}

// takePendingTask removes and returns the pending task correlated with
// toolCallID, preferring an explicit ID match anywhere in the queue and
// falling back to the oldest pending entry otherwise. Returns false if there
// was nothing pending at all.
func (stream *toolCallStream) takePendingTask(toolCallID string) (pendingTask, bool) {
	if toolCallID != "" {
		for i, p := range stream.pendingTasks {
			if p.toolCallID == toolCallID {
				stream.pendingTasks = append(stream.pendingTasks[:i], stream.pendingTasks[i+1:]...)
				return p, true
			}
		}
	}
	if len(stream.pendingTasks) == 0 {
		return pendingTask{}, false
	}
	p := stream.pendingTasks[0]
	stream.pendingTasks = stream.pendingTasks[1:]
	return p, true
}

// startStreamRequest holds the parameters for chat.startStream.
type startStreamRequest struct {
	Channel         string
	ThreadTS        string
	RecipientUserID string
	RecipientTeamID string
	TaskDisplayMode string
	Chunks          []any
}

// markdownTextChunk is a "markdown_text" stream chunk.
type markdownTextChunk struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// planUpdateChunk is a "plan_update" stream chunk.
type planUpdateChunk struct {
	Type  string `json:"type"`
	Title string `json:"title"`
}

func newPlanUpdateChunk(title string) planUpdateChunk {
	return planUpdateChunk{Type: "plan_update", Title: title}
}

// maxPlanTitleLen is a defensive truncation limit for the plan card's title.
const maxPlanTitleLen = 200

// defaultPlanTitle is used when no preceding "thinking" text from the model
// is available to title the plan card with.
const defaultPlanTitle = "Execution plan"

// truncateRunes truncates s to at most limit runes (not bytes), so a
// multi-byte UTF-8 character is never split into an invalid trailing
// sequence the way a plain byte-index slice could.
func truncateRunes(s string, limit int) (head string, wasTruncated bool) {
	runes := []rune(s)
	if len(runes) <= limit {
		return s, false
	}
	return string(runes[:limit]), true
}

// firstLineTitle derives a short, single-line title from text (its first
// line, truncated), falling back to fallback when text has no usable
// content. Used to make sure a title is never left blank.
func firstLineTitle(text, fallback string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return fallback
	}
	if idx := strings.IndexAny(trimmed, "\r\n"); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}
	if trimmed == "" {
		return fallback
	}
	if head, truncated := truncateRunes(trimmed, maxPlanTitleLen); truncated {
		trimmed = strings.TrimSpace(head) + "…"
	}
	return trimmed
}

// planTitleFrom derives a short, single-line plan card title from the
// model's most recent "thinking"/plan text, falling back to a generic title
// when none is available.
func planTitleFrom(thinkingText string) string {
	return firstLineTitle(thinkingText, defaultPlanTitle)
}

// taskTitleFrom derives a task card's title from the model's reason for
// running this batch of tool calls (its most recent "thinking" text),
// falling back to the command itself — never blank — when no reason text is
// available. When falling back (no reason given), this deliberately does
// NOT repeat the full command — that's already shown in the task's details
// field, so showing it again as the title too is pure redundancy. Instead
// it uses a short action label (see shortCommandLabel).
func taskTitleFrom(reasonText, commandText string) string {
	if title := firstLineTitle(reasonText, ""); title != "" {
		return title
	}
	return firstLineTitle(shortCommandLabel(commandText), defaultPlanTitle)
}

// shortCommandLabel extracts a brief "<binary> <verb> <target>" label from a
// command line, e.g. "kubectl logs image-reflector-controller-749d57bbf9-nv66v"
// from "kubectl logs image-reflector-controller-749d57bbf9-nv66v -n flux-system
// --context k8s.staging.core --tail 500" — enough to identify the action at a
// glance without repeating flags/context that are already in the details
// field. Falls back to the full command if it can't confidently identify a
// verb/target (e.g. no recognizable structure).
func shortCommandLabel(commandText string) string {
	fields := strings.Fields(commandText)
	var nonFlags []string
	for _, f := range fields {
		if strings.HasPrefix(f, "-") {
			continue
		}
		nonFlags = append(nonFlags, f)
		if len(nonFlags) == 3 {
			break
		}
	}
	if len(nonFlags) == 0 {
		return commandText
	}
	return strings.Join(nonFlags, " ")
}

// taskUpdateChunk is a "task_update" stream chunk representing one tool
// call's status. Details holds the actual command (technical detail);
// Output is always a short status summary (see summarizeToolStatus) — the
// tool's actual output is never sent to Slack.
type taskUpdateChunk struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Title   string `json:"title,omitempty"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
	Output  string `json:"output,omitempty"`
}

// maxTaskFieldLen is a defensive truncation limit for task_update text
// fields. Slack's exact per-field limits for this new API aren't fully
// documented. Truncated content is simply dropped, never posted elsewhere —
// nothing about a task's command/output should ever appear outside the plan
// card itself.
const maxTaskFieldLen = 220

func truncateForTask(text string) string {
	head, truncated := truncateRunes(text, maxTaskFieldLen)
	if !truncated {
		return text
	}
	return head + "…"
}

// newTaskUpdateChunk builds a task_update chunk. title should already be
// finalized (see taskTitleFrom) and is never blank or further truncated
// here. details (the raw command) is truncated defensively; output is a
// short, pre-bounded status summary and is never truncated.
func newTaskUpdateChunk(id, title, details, status, output string) taskUpdateChunk {
	return taskUpdateChunk{
		Type:    "task_update",
		ID:      id,
		Title:   title,
		Status:  status,
		Details: truncateForTask(details),
		Output:  output,
	}
}

// shimObservationPrefix is the literal prefix pkg/agent/conversation.go's
// DispatchToolCalls uses when EnableToolUseShim is on and a tool call
// succeeds (`fmt.Sprintf("Result of running %q:\n%v", name, output)`). A
// string payload WITHOUT this prefix is always the tool-invoke error path
// (a bare `err.Error()`), which is unconditionally a failure.
const shimObservationPrefix = "Result of running "

// commandExitedMarker is the exact message pkg/tools/exec_helpers.go's
// runCommand sets on ExecResult.Error for a non-zero exit code, and is the
// one reliable failure signal recoverable from the shim's free-form %v text.
const commandExitedMarker = "command exited with code"

// renderToolResult converts a tool call response payload into displayable
// text and reports whether it represents an error. Payloads are either a
// plain string (the tool-use shim path, and the tool-invoke error path) or a
// map[string]any (produced by tools.ToolResultToMap for native tool-calling).
func renderToolResult(payload any) (text string, isError bool) {
	switch v := payload.(type) {
	case string:
		if !strings.HasPrefix(v, shimObservationPrefix) {
			// Not a shim success observation, so this can only be the bare
			// err.Error() posted on the tool-invoke error path — always a
			// failure regardless of its exact wording.
			return v, true
		}
		// A shim success observation embeds the tool's ExecResult via %v;
		// checking for an arbitrary "error" substring would misclassify any
		// successful output that merely mentions the word (e.g. a Warning
		// event or log line), so look for the specific marker exec_helpers.go
		// actually emits on a genuine command failure instead.
		return v, strings.Contains(v, commandExitedMarker)
	case map[string]any:
		if errVal, ok := v["error"]; ok {
			return fmt.Sprintf("%v", errVal), true
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for i, k := range keys {
			if i > 0 {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "%s: %v", k, v[k])
		}
		return b.String(), false
	default:
		return fmt.Sprintf("%v", v), false
	}
}

// maxFailureReasonLen bounds the failure reason summarizeToolStatus surfaces
// — long enough to be useful, short enough to never become another form of
// "raw output".
const maxFailureReasonLen = 150

// summarizeToolStatus converts a tool call response payload into a short
// status line — never the tool's actual (successful) output, which is never
// shown to users — plus whether it represents a failure. Duration, when the
// payload carries one (native tool-calling's map[string]any always does, via
// tools.ExecResult's "duration" field), is appended for context. On failure,
// a short, concrete reason is also included — an opaque "Failed" gives users
// (and the model, if it ever re-reads this) no way to tell whether something
// is worth retrying or investigating differently.
func summarizeToolStatus(payload any) (summary string, isError bool) {
	renderedText, isError := renderToolResult(payload)
	label := "✅ Success"
	if isError {
		label = "❌ Failed"
	}
	if duration := extractDuration(payload); duration != "" {
		label = fmt.Sprintf("%s (%s)", label, duration)
	}
	if !isError {
		return label, false
	}
	if reason := extractFailureReason(payload, renderedText); reason != "" {
		return fmt.Sprintf("%s: %s", label, reason), true
	}
	return label, true
}

// extractFailureReason returns a short, human-readable explanation for why a
// tool call failed — never the command's full stdout. For native
// tool-calling's map payload, tools.ExecResult's "stderr" (the command's own
// error message, e.g. "Error from server (NotFound): ...") is far more
// useful than its generic "error" field ("command exited with code 1"), so
// it's preferred when present.
func extractFailureReason(payload any, renderedText string) string {
	switch v := payload.(type) {
	case map[string]any:
		if stderr, ok := v["stderr"].(string); ok {
			if reason := firstLineTitle(stderr, ""); reason != "" {
				return truncateReason(reason)
			}
		}
		if errVal, ok := v["error"]; ok {
			return truncateReason(fmt.Sprintf("%v", errVal))
		}
		return ""
	case string:
		if strings.HasPrefix(v, shimObservationPrefix) {
			// This is the shim's raw %v-dumped ExecResult — not a clean,
			// presentable reason, just another form of "raw output".
			return ""
		}
		// A bare string here is always the tool-invoke error path (see
		// renderToolResult) — the text itself already IS the reason.
		return truncateReason(renderedText)
	default:
		return ""
	}
}

func truncateReason(s string) string {
	head, truncated := truncateRunes(strings.TrimSpace(s), maxFailureReasonLen)
	if truncated {
		return head + "…"
	}
	return head
}

// extractDuration pulls the "duration" field out of a native tool-calling
// map[string]any payload (produced from tools.ExecResult), if present.
func extractDuration(payload any) string {
	m, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	switch d := m["duration"].(type) {
	case string:
		return d
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", d)
	}
}

// appendChunks sends chunks to the stream's Slack message, logging and
// reporting failure so callers can fall back to classic rendering for just
// the message that failed to append, rather than silently losing it.
func (s *SlackUI) appendChunks(stream *toolCallStream, chunks []any) bool {
	if err := s.streamClient.AppendStream(stream.channel, stream.ts, chunks); err != nil {
		klog.Errorf("Failed to append task_update to Slack plan stream: %v", err)
		return false
	}
	return true
}

// appendToolCallRequest opens a Slack plan stream if one isn't already open
// for this batch, and appends an "in_progress" task_update for a new tool
// call request. planTitle should be the model's most recent "thinking" text
// — used both to title the plan card (see planTitleFrom) and, combined with
// commandText, to title this task (see taskTitleFrom) so it reads as the
// agent's reason for running this command rather than a generic label or
// (worse) being left blank. toolCallID is the LLM's tool-call ID (may be
// empty, see pendingTask) used to correlate the eventual response.
//
// Returns the (possibly newly created) stream and whether the request was
// successfully appended. When appended is false, the caller should render
// this message the classic way instead — if stream is also nil, starting a
// brand new stream failed entirely (the caller should stop retrying for this
// session); if stream is non-nil, only this one append failed transiently
// and the stream remains usable for subsequent tool calls in the batch.
func (s *SlackUI) appendToolCallRequest(stream *toolCallStream, channel, threadTS, slackUserID, planTitle, toolCallID, commandText string) (result *toolCallStream, appended bool) {
	if stream == nil {
		ts, err := s.streamClient.StartStream(startStreamRequest{
			Channel:         channel,
			ThreadTS:        threadTS,
			RecipientUserID: slackUserID,
			RecipientTeamID: s.teamID,
			TaskDisplayMode: "plan",
			Chunks:          []any{newPlanUpdateChunk(planTitleFrom(planTitle))},
		})
		if err != nil {
			klog.Errorf("Failed to start Slack plan stream: %v", err)
			return nil, false
		}
		if ts == "" {
			klog.Errorf("Slack chat.startStream succeeded but returned no message timestamp; treating as a failed start")
			return nil, false
		}
		stream = &toolCallStream{channel: channel, ts: ts}
	}

	taskID := fmt.Sprintf("task-%d", stream.nextTaskID)
	stream.nextTaskID++
	title := taskTitleFrom(planTitle, commandText)

	chunk := newTaskUpdateChunk(taskID, title, commandText, "in_progress", "")
	if !s.appendChunks(stream, []any{chunk}) {
		// This request was never actually shown on the card — don't track it
		// as pending, so its eventual response also falls back to classic
		// rendering instead of misapplying to some other pending task.
		return stream, false
	}
	// The command is truncated defensively in Details above if it's long,
	// but the full command is never posted anywhere else — nothing about a
	// task should ever appear outside the plan card itself.
	stream.pendingTasks = append(stream.pendingTasks, pendingTask{toolCallID: toolCallID, taskID: taskID, title: title})
	return stream, true
}

// appendToolCallResponse appends a "complete"/"error" task_update for the
// tool call correlated with toolCallID (see toolCallStream.takePendingTask),
// and reports whether the append succeeded.
//
// title is resent unchanged from the request update, but details is left
// empty. Confirmed by real usage (not just guessed): Slack's task_update
// "title" is a plain replace-on-update field — it goes blank if omitted from
// a later update, so it must be resent every time to stay visible once the
// task completes. "details" behaves the opposite way — resending identical
// text visibly duplicated it (looks like Slack accumulates that field, e.g.
// as a list of entries, rather than replacing it), so it must NOT be resent.
func (s *SlackUI) appendToolCallResponse(stream *toolCallStream, channel, threadTS, toolCallID string, payload any) bool {
	statusText, isError := summarizeToolStatus(payload)
	status := "complete"
	if isError {
		status = "error"
	}

	task, ok := stream.takePendingTask(toolCallID)
	if !ok {
		task = pendingTask{taskID: fmt.Sprintf("task-%d", stream.nextTaskID), title: defaultPlanTitle}
		stream.nextTaskID++
	}

	chunk := newTaskUpdateChunk(task.taskID, task.title, "", status, statusText)
	return s.appendChunks(stream, []any{chunk})
}

// closeToolCallStream finalizes a tool-call stream. Any tasks that never
// received a matching response (e.g. the session ended mid-batch, or the
// agent errored out before dispatching every pending call) are flushed to a
// terminal "error" status first, so no task card is left stuck showing
// "in_progress" forever.
func (s *SlackUI) closeToolCallStream(stream *toolCallStream) {
	for _, p := range stream.pendingTasks {
		// Same title/details treatment as appendToolCallResponse.
		chunk := newTaskUpdateChunk(p.taskID, p.title, "", "error", "Interrupted before a result was received.")
		s.appendChunks(stream, []any{chunk})
	}
	stream.pendingTasks = nil
	if err := s.streamClient.StopStream(stream.channel, stream.ts, nil); err != nil {
		klog.Errorf("Failed to stop Slack plan stream: %v", err)
	}
}

// httpStreamClient implements SlackStreamAPI via direct HTTP calls to the
// Slack Web API, since slack-go/slack does not yet support these methods.
type httpStreamClient struct {
	botToken   string
	httpClient *http.Client
}

func newHTTPStreamClient(botToken string) *httpStreamClient {
	return &httpStreamClient{
		botToken:   botToken,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type slackStreamAPIResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Channel string `json:"channel"`
	TS      string `json:"ts"`
}

func (c *httpStreamClient) call(method string, body map[string]any) (*slackStreamAPIResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request for %s: %w", method, err)
	}

	// Trace-level logging of the exact bytes sent, so a rendering anomaly
	// (e.g. duplicated text) can be root-caused as "we sent it twice" vs.
	// "Slack rendered one value as multiple items" — matches the existing
	// v=4 block-logging pattern in postToSlack.
	if klog.V(4).Enabled() {
		klog.Infof("Calling %s with body: %s", method, string(payload))
	}

	req, err := http.NewRequest(http.MethodPost, slackAPIBaseURL+"/"+method, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+c.botToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body for %s: %w", method, err)
	}
	if klog.V(4).Enabled() {
		klog.Infof("Response from %s: %s", method, string(respBody))
	}

	var result slackStreamAPIResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decoding response for %s: %w", method, err)
	}
	if !result.OK {
		return nil, fmt.Errorf("%s returned error: %s", method, result.Error)
	}
	return &result, nil
}

func (c *httpStreamClient) StartStream(req startStreamRequest) (string, error) {
	body := map[string]any{
		"channel":           req.Channel,
		"thread_ts":         req.ThreadTS,
		"task_display_mode": req.TaskDisplayMode,
	}
	if req.RecipientUserID != "" {
		body["recipient_user_id"] = req.RecipientUserID
	}
	if req.RecipientTeamID != "" {
		body["recipient_team_id"] = req.RecipientTeamID
	}
	if len(req.Chunks) > 0 {
		body["chunks"] = req.Chunks
	}
	result, err := c.call("chat.startStream", body)
	if err != nil {
		return "", err
	}
	return result.TS, nil
}

func (c *httpStreamClient) AppendStream(channel, ts string, chunks []any) error {
	_, err := c.call("chat.appendStream", map[string]any{
		"channel": channel,
		"ts":      ts,
		"chunks":  chunks,
	})
	return err
}

func (c *httpStreamClient) StopStream(channel, ts string, chunks []any) error {
	body := map[string]any{
		"channel": channel,
		"ts":      ts,
	}
	if len(chunks) > 0 {
		body["chunks"] = chunks
	}
	_, err := c.call("chat.stopStream", body)
	return err
}

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

package journal

import (
	"context"
	"io"
	"time"
)

type contextKey string

const (
	RecorderKey    contextKey = "journal-recorder"
	SlackUserIDKey contextKey = "slack-user-id"
)

type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	SlackUserID string    `json:"slack_user_id,omitempty"`
	Action      string    `json:"action"`
	Payload     any       `json:"payload,omitempty"`
}

// Action constants for journal events
const (
	ActionHTTPRequest  = "http_request"
	ActionHTTPResponse = "http_response"
	ActionHTTPError    = "http_error"
)

// Recorder is an interface for recording a structured log of the agent's actions and observations.
type Recorder interface {
	io.Closer

	// Write will add an event to the recorder.
	Write(ctx context.Context, event *Event) error
}

// RecorderFromContext extracts the recorder from the given context
func RecorderFromContext(ctx context.Context) Recorder {
	recorder, ok := ctx.Value(RecorderKey).(Recorder)
	if !ok {
		return &LogRecorder{}
	}
	return recorder
}

// ContextWithRecorder adds the recorder to the given context
func ContextWithRecorder(ctx context.Context, recorder Recorder) context.Context {
	return context.WithValue(ctx, RecorderKey, recorder)
}

// SlackUserIDFromContext extracts the slack user id from the given context
func SlackUserIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(SlackUserIDKey).(string)
	return id
}

// ContextWithSlackUserID adds the slack user id to the given context
func ContextWithSlackUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, SlackUserIDKey, id)
}

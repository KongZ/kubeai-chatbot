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

package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSession_Validate(t *testing.T) {
	sessionID := uuid.NewString()
	now := time.Now()

	tests := []struct {
		name    string
		session *Session
		wantErr bool
	}{
		{
			name: "Valid Session",
			session: &Session{
				ID:           sessionID,
				Name:         "Test Session",
				ProviderID:   "google",
				ModelID:      "gemini-1.5-pro",
				SlackUserID:  "U12345",
				AgentState:   AgentStateIdle,
				CreatedAt:    now,
				LastModified: now,
			},
			wantErr: false,
		},
		{
			name: "Valid non-UUID ID",
			session: &Session{
				ID:           "slack-C123-T456",
				Name:         "Test Session",
				ProviderID:   "google",
				ModelID:      "gemini-1.5-pro",
				SlackUserID:  "U12345",
				AgentState:   AgentStateIdle,
				CreatedAt:    now,
				LastModified: now,
			},
			wantErr: false,
		},
		{
			name: "Missing Name",
			session: &Session{
				ID:           sessionID,
				Name:         "",
				ProviderID:   "google",
				ModelID:      "gemini-1.5-pro",
				SlackUserID:  "U12345",
				AgentState:   AgentStateIdle,
				CreatedAt:    now,
				LastModified: now,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.session.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMessage_Validate(t *testing.T) {
	msgID := uuid.NewString()
	now := time.Now()

	tests := []struct {
		name    string
		message *Message
		wantErr bool
	}{
		{
			name: "Valid Message",
			message: &Message{
				ID:        msgID,
				Source:    MessageSourceUser,
				Type:      MessageTypeText,
				Payload:   "Hello",
				Timestamp: now,
			},
			wantErr: false,
		},
		{
			name: "Invalid Source",
			message: &Message{
				ID:        msgID,
				Source:    "invalid",
				Type:      MessageTypeText,
				Payload:   "Hello",
				Timestamp: now,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.message.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

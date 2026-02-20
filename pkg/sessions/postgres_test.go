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

package sessions

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

func TestPostgresStore_CreateSession(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	bundb := bun.NewDB(db, pgdialect.New())
	store := &PostgresStore{db: bundb}

	sessionID := "test-session"
	session := &api.Session{
		ID:           sessionID,
		Name:         "Test Session",
		ProviderID:   "test-provider",
		ModelID:      "test-model",
		AgentState:   api.AgentStateIdle,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}

	mock.ExpectExec("INSERT INTO .session_models.").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.CreateSession(session)
	require.NoError(t, err)
	assert.NotNil(t, session.ChatMessageStore)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStore_GetSession(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	bundb := bun.NewDB(db, pgdialect.New())
	store := &PostgresStore{db: bundb}

	sessionID := "test-session"
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "name", "provider_id", "model_id", "agent_state", "created_at", "last_modified"}).
		AddRow(sessionID, "Test Session", "test-provider", "test-model", string(api.AgentStateIdle), now, now)

	mock.ExpectQuery("SELECT .* FROM .session_models.").
		WillReturnRows(rows)

	session, err := store.GetSession(sessionID)
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, sessionID, session.ID)
	assert.Equal(t, "Test Session", session.Name)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresChatMessageStore_AddChatMessage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	bundb := bun.NewDB(db, pgdialect.New())
	sessionID := "test-session"
	chatStore := &PostgresChatMessageStore{
		db:        bundb,
		sessionID: sessionID,
	}

	msg := &api.Message{
		ID:        "msg-1",
		Source:    api.MessageSourceUser,
		Type:      api.MessageTypeText,
		Payload:   "hello",
		Timestamp: time.Now(),
		Metadata:  map[string]string{"foo": "bar"},
	}

	mock.ExpectExec("INSERT INTO .message_models.").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = chatStore.AddChatMessage(msg)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

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

package sessions

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/migrate"
	"github.com/uptrace/bun/schema"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var migrations = migrate.NewMigrations()

func init() {
	if err := migrations.Discover(migrationFS); err != nil {
		panic(err)
	}
}

type PostgresStore struct {
	db *bun.DB
}

type sessionModel struct {
	ID           string         `bun:"id,pk"`
	Name         string         `bun:"name"`
	ProviderID   string         `bun:"provider_id"`
	ModelID      string         `bun:"model_id"`
	SlackUserID  string         `bun:"slack_user_id"`
	AgentState   api.AgentState `bun:"agent_state"`
	CreatedAt    time.Time      `bun:"created_at"`
	LastModified time.Time      `bun:"last_modified"`
}

type messageModel struct {
	ID        string            `bun:"id,pk"`
	SessionID string            `bun:"session_id"`
	Source    api.MessageSource `bun:"source"`
	Type      api.MessageType   `bun:"type"`
	Payload   []byte            `bun:"payload"`
	Timestamp time.Time         `bun:"timestamp"`
	Metadata  map[string]string `bun:"metadata,type:jsonb"`
}

func newPostgresStore(db *sql.DB, dialect schema.Dialect) (*PostgresStore, error) {
	bundb := bun.NewDB(db, dialect)

	ctx := context.Background()
	migrator := migrate.NewMigrator(bundb, migrations)

	if err := migrator.Init(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize migrator: %w", err)
	}

	group, err := migrator.Migrate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if group.IsZero() {
		fmt.Println("database is up to date")
	} else {
		fmt.Printf("migrated to %s\n", group)
	}

	return &PostgresStore{db: bundb}, nil
}

func (p *PostgresStore) GetSession(id string) (*api.Session, error) {
	var model sessionModel
	err := p.db.NewSelect().
		Model(&model).
		Where("id = ?", id).
		Scan(context.Background())

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("session not found")
		}
		return nil, err
	}

	chatStore := &PostgresChatMessageStore{
		db:        p.db,
		sessionID: id,
	}

	return &api.Session{
		ID:               model.ID,
		Name:             model.Name,
		ProviderID:       model.ProviderID,
		ModelID:          model.ModelID,
		SlackUserID:      model.SlackUserID,
		AgentState:       model.AgentState,
		CreatedAt:        model.CreatedAt,
		LastModified:     model.LastModified,
		ChatMessageStore: chatStore,
	}, nil
}

func (p *PostgresStore) CreateSession(session *api.Session) error {
	if err := session.Validate(); err != nil {
		return fmt.Errorf("invalid session for creation: %w", err)
	}
	model := &sessionModel{
		ID:           session.ID,
		Name:         session.Name,
		ProviderID:   session.ProviderID,
		ModelID:      session.ModelID,
		SlackUserID:  session.SlackUserID,
		AgentState:   session.AgentState,
		CreatedAt:    session.CreatedAt,
		LastModified: session.LastModified,
	}

	_, err := p.db.NewInsert().Model(model).Exec(context.Background())
	if err != nil {
		return err
	}

	session.ChatMessageStore = &PostgresChatMessageStore{
		db:        p.db,
		sessionID: session.ID,
	}
	return nil
}

func (p *PostgresStore) UpdateSession(session *api.Session) error {
	if err := session.Validate(); err != nil {
		return fmt.Errorf("invalid session for update: %w", err)
	}
	model := &sessionModel{
		ID:           session.ID,
		Name:         session.Name,
		ProviderID:   session.ProviderID,
		ModelID:      session.ModelID,
		SlackUserID:  session.SlackUserID,
		AgentState:   session.AgentState,
		CreatedAt:    session.CreatedAt,
		LastModified: session.LastModified,
	}

	_, err := p.db.NewUpdate().
		Model(model).
		WherePK().
		Exec(context.Background())

	return err
}

func (p *PostgresStore) ListSessions() ([]*api.Session, error) {
	var models []sessionModel
	err := p.db.NewSelect().
		Model(&models).
		Order("last_modified DESC").
		Scan(context.Background())

	if err != nil {
		return nil, err
	}

	sessions := make([]*api.Session, len(models))
	for i, model := range models {
		sessions[i] = &api.Session{
			ID:           model.ID,
			Name:         model.Name,
			ProviderID:   model.ProviderID,
			ModelID:      model.ModelID,
			SlackUserID:  model.SlackUserID,
			AgentState:   model.AgentState,
			CreatedAt:    model.CreatedAt,
			LastModified: model.LastModified,
			ChatMessageStore: &PostgresChatMessageStore{
				db:        p.db,
				sessionID: model.ID,
			},
		}
	}

	return sessions, nil
}

func (p *PostgresStore) DeleteSession(id string) error {
	ctx := context.Background()
	_, err := p.db.NewDelete().
		Model((*messageModel)(nil)).
		Where("session_id = ?", id).
		Exec(ctx)
	if err != nil {
		return err
	}

	_, err = p.db.NewDelete().
		Model((*sessionModel)(nil)).
		Where("id = ?", id).
		Exec(ctx)

	return err
}

type PostgresChatMessageStore struct {
	db        *bun.DB
	sessionID string
}

func (s *PostgresChatMessageStore) AddChatMessage(record *api.Message) error {
	if err := record.Validate(); err != nil {
		return fmt.Errorf("invalid chat message: %w", err)
	}
	payload, err := json.Marshal(record.Payload)
	if err != nil {
		return err
	}

	model := &messageModel{
		ID:        record.ID,
		SessionID: s.sessionID,
		Source:    record.Source,
		Type:      record.Type,
		Payload:   payload,
		Timestamp: record.Timestamp,
		Metadata:  record.Metadata,
	}

	_, err = s.db.NewInsert().Model(model).Exec(context.Background())
	return err
}

func (s *PostgresChatMessageStore) SetChatMessages(newHistory []*api.Message) error {
	ctx := context.Background()
	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.NewDelete().
			Model((*messageModel)(nil)).
			Where("session_id = ?", s.sessionID).
			Exec(ctx)
		if err != nil {
			return err
		}

		for _, record := range newHistory {
			if err := record.Validate(); err != nil {
				return fmt.Errorf("invalid chat message in history: %w", err)
			}
			payload, err := json.Marshal(record.Payload)
			if err != nil {
				return err
			}

			model := &messageModel{
				ID:        record.ID,
				SessionID: s.sessionID,
				Source:    record.Source,
				Type:      record.Type,
				Payload:   payload,
				Timestamp: record.Timestamp,
				Metadata:  record.Metadata,
			}

			_, err = tx.NewInsert().Model(model).Exec(ctx)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return err
}

func (s *PostgresChatMessageStore) ChatMessages() []*api.Message {
	var models []messageModel
	err := s.db.NewSelect().
		Model(&models).
		Where("session_id = ?", s.sessionID).
		Order("timestamp ASC").
		Scan(context.Background())

	if err != nil {
		return nil
	}

	messages := make([]*api.Message, len(models))
	for i, model := range models {
		var payload any
		if len(model.Payload) > 0 {
			_ = json.Unmarshal(model.Payload, &payload)
		}

		messages[i] = &api.Message{
			ID:        model.ID,
			Source:    model.Source,
			Type:      model.Type,
			Payload:   payload,
			Timestamp: model.Timestamp,
			Metadata:  model.Metadata,
		}
	}

	return messages
}

func (s *PostgresChatMessageStore) ClearChatMessages() error {
	_, err := s.db.NewDelete().
		Model((*messageModel)(nil)).
		Where("session_id = ?", s.sessionID).
		Exec(context.Background())
	return err
}

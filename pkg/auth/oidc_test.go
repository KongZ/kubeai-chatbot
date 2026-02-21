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

package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOIDCAuthFlow(t *testing.T) {
	config := OIDCConfig{
		Enabled:     true,
		RoleField:   "groups",
		GroupsField: "groups",
		RoleMappings: map[string]string{
			"admin": "cluster-admin",
		},
	}
	o := &OIDCSP{
		Config: config,
		states: make(map[string]oidcState),
	}

	// Test GetSessionID mapping
	state := "test-state"
	sessionID := "test-session"
	o.mu.Lock()
	o.states[state] = oidcState{
		sessionID: sessionID,
		createdAt: time.Now(),
	}
	o.mu.Unlock()

	r, _ := http.NewRequest("GET", "/auth/callback?code=foo&state="+state, nil)
	retrievedSessionID, err := o.GetSessionID(r)
	assert.NoError(t, err)
	assert.Equal(t, sessionID, retrievedSessionID)

	// Verify state is removed after retrieval
	_, err = o.GetSessionID(r)
	assert.Error(t, err)

	// Test expired state
	stateExp := "expired-state"
	o.mu.Lock()
	o.states[stateExp] = oidcState{
		sessionID: sessionID,
		createdAt: time.Now().Add(-20 * time.Minute),
	}
	o.mu.Unlock()

	rExp, _ := http.NewRequest("GET", "/auth/callback?code=foo&state="+stateExp, nil)
	_, err = o.GetSessionID(rExp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC state expired")

	// Test mapping logic
	claims := map[string]any{
		"sub":    "test-user",
		"email":  "user@example.com",
		"groups": []any{"admin", "users"},
	}

	identity := o.mapClaimsToIdentity("user@example.com", claims)
	assert.NotNil(t, identity)
	assert.Equal(t, "user@example.com", identity.UserID)
	assert.Equal(t, "cluster-admin", identity.Role)
	assert.Equal(t, []string{"admin", "users"}, identity.Groups)
}

// We need to export mapClaimsToIdentity or test through GetIdentity with a mock server.
// For simplicity in this env, I'll add the mapping logic as a private method in oidc.go and test it.

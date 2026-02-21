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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOIDCMapUserIdentity(t *testing.T) {
	config := OIDCConfig{
		Enabled:   true,
		RoleField: "groups",
		RoleMappings: map[string]string{
			"admin": "cluster-admin",
		},
	}
	o := &OIDCSP{Config: config}

	// Mock claims
	claims := map[string]any{
		"sub":    "test-user",
		"email":  "user@example.com",
		"groups": []any{"admin", "users"},
	}

	// Helper to extract userID
	getUserID := func(c map[string]any) string {
		if email, ok := c["email"].(string); ok {
			return email
		}
		return c["sub"].(string)
	}

	identity := o.mapClaimsToIdentity(getUserID(claims), claims)
	assert.NotNil(t, identity)
	assert.Equal(t, "user@example.com", identity.UserID)
	assert.Equal(t, "cluster-admin", identity.Role)
	assert.Equal(t, "user@example.com", identity.Metadata["email"])
}

// We need to export mapClaimsToIdentity or test through GetIdentity with a mock server.
// For simplicity in this env, I'll add the mapping logic as a private method in oidc.go and test it.

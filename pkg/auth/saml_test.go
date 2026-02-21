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

	"github.com/crewjam/saml/samlsp"
	"github.com/stretchr/testify/assert"
)

func TestMapUserIdentity(t *testing.T) {
	config := SAMLConfig{
		Enabled:   true,
		RoleField: "groups",
		RoleMappings: map[string]string{
			"admin": "cluster-admin",
		},
	}
	s := &SAMLSP{Config: config}

	// Mock SAML session
	attributes := samlsp.Attributes{
		"email":  []string{"user@example.com"},
		"groups": []string{"admin", "users"},
	}
	claims := samlsp.JWTSessionClaims{
		Attributes: attributes,
	}
	claims.Subject = "test-user"

	identity, err := s.MapUserIdentity(claims)
	assert.NoError(t, err)
	assert.NotNil(t, identity)
	assert.Equal(t, "user@example.com", identity.UserID)
	assert.Equal(t, "cluster-admin", identity.Role)
	assert.Equal(t, "user@example.com", identity.Metadata["email"])
	assert.Equal(t, "admin", identity.Metadata["groups"])
}

func TestMapUserIdentity_NoMapping(t *testing.T) {
	config := SAMLConfig{
		Enabled:   true,
		RoleField: "role",
	}
	s := &SAMLSP{Config: config}

	attributes := samlsp.Attributes{
		"uid":  []string{"jdoe"},
		"role": []string{"developer"},
	}
	claims := samlsp.JWTSessionClaims{
		Attributes: attributes,
	}
	claims.Subject = "test-user"

	identity, err := s.MapUserIdentity(claims)
	assert.NoError(t, err)
	assert.Equal(t, "jdoe", identity.UserID)
	assert.Equal(t, "developer", identity.Role)
}

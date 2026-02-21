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
	"context"
	"fmt"
	"net/http"

	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"k8s.io/klog/v2"
)

// OIDCConfig holds configuration for OIDC authentication
type OIDCConfig struct {
	Enabled      bool
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	RoleField    string            // Field in ID token or userinfo to map to K8s role
	RoleMappings map[string]string // OIDC role value -> K8s role name
}

// OIDCSP handles OIDC authentication logic
type OIDCSP struct {
	Config   OIDCConfig
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
}

// NewOIDCSP creates a new OIDCSP instance
func NewOIDCSP(config OIDCConfig) (*OIDCSP, error) {
	if !config.Enabled {
		return nil, nil
	}

	provider, err := oidc.NewProvider(context.Background(), config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &OIDCSP{
		Config:   config,
		Provider: provider,
		Verifier: verifier,
	}, nil
}

// GetLoginURL returns the OIDC authorization URL
func (o *OIDCSP) GetLoginURL(relayState string) (string, error) {
	oauthConfig := o.oauth2Config()
	// Using relayState as oauth2 'state' to carry session ID
	return oauthConfig.AuthCodeURL(relayState), nil
}

// GetIdentity extracts and maps the user identity from an OIDC callback
func (o *OIDCSP) GetIdentity(r *http.Request) (*api.Identity, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("no OIDC code found in request")
	}

	oauthConfig := o.oauth2Config()
	token, err := oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		return nil, fmt.Errorf("exchanging OIDC code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := o.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verifying ID token: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing ID token claims: %w", err)
	}

	userID := idToken.Subject
	if email, ok := claims["email"].(string); ok {
		userID = email
	}

	identity := o.mapClaimsToIdentity(userID, claims)
	klog.V(2).Infof("OIDC Mapped user %s to K8s role %s", identity.UserID, identity.Role)
	return identity, nil
}

func (o *OIDCSP) mapClaimsToIdentity(userID string, claims map[string]any) *api.Identity {
	identity := &api.Identity{
		UserID:   userID,
		Metadata: make(map[string]string),
	}

	// Map role
	if o.Config.RoleField != "" {
		if roleVal, ok := claims[o.Config.RoleField].(string); ok {
			if k8sRole, mappingFound := o.Config.RoleMappings[roleVal]; mappingFound {
				identity.Role = k8sRole
			} else {
				identity.Role = roleVal
			}
		} else if roles, ok := claims[o.Config.RoleField].([]any); ok {
			// Handle groups/roles as list
			for _, r := range roles {
				if rStr, ok := r.(string); ok {
					if k8sRole, mappingFound := o.Config.RoleMappings[rStr]; mappingFound {
						identity.Role = k8sRole
						break // Take first match
					}
				}
			}
		}
	}

	// Metadata
	for k, v := range claims {
		identity.Metadata[k] = fmt.Sprintf("%v", v)
	}

	return identity
}

// Middleware returns nil for OIDC as it doesn't need persistent route middleware like SAML SP
func (o *OIDCSP) Middleware() http.Handler {
	return nil
}

func (o *OIDCSP) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.Config.ClientID,
		ClientSecret: o.Config.ClientSecret,
		Endpoint:     o.Provider.Endpoint(),
		RedirectURL:  o.Config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

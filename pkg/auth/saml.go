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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/crewjam/saml/samlsp"
	"k8s.io/klog/v2"
)

// SAMLConfig holds configuration for SAML authentication
type SAMLConfig struct {
	Enabled        bool
	IDPMetadataURL string
	EntityID       string
	RootURL        string
	KeyFile        string
	CertFile       string
	RoleField      string            // Field in SAML assertion to map to K8s role
	RoleMappings   map[string]string // SAML role value -> K8s role name
	GroupsField    string            // Field in SAML assertion to extract groups from
}

// SAMLSP handles SAML Service Provider logic
type SAMLSP struct {
	SP     *samlsp.Middleware
	Config SAMLConfig
}

// NewSAMLSP creates a new SAMLSP instance
func NewSAMLSP(config SAMLConfig) (*SAMLSP, error) {
	if !config.Enabled {
		return nil, nil
	}

	keyPair, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading key pair: %w", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	idpMetadataURL, err := url.Parse(config.IDPMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("parsing IDP metadata URL: %w", err)
	}

	rootURL, err := url.Parse(config.RootURL)
	if err != nil {
		return nil, fmt.Errorf("parsing root URL: %w", err)
	}

	httpClient := http.DefaultClient
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), httpClient, *idpMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetching IDP metadata: %w", err)
	}

	opts := samlsp.Options{
		URL:               *rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       idpMetadata,
		EntityID:          config.EntityID,
		AllowIDPInitiated: true,
	}

	middleware, err := samlsp.New(opts)
	if err != nil {
		return nil, fmt.Errorf("creating SAML middleware: %w", err)
	}

	return &SAMLSP{
		SP:     middleware,
		Config: config,
	}, nil
}

// MapUserIdentity maps SAML attributes to user identity information
func (s *SAMLSP) MapUserIdentity(session samlsp.Session) (*api.Identity, error) {
	claims, ok := session.(samlsp.JWTSessionClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected session type: %T", session)
	}

	assertion := claims.Attributes
	userID := claims.Subject

	// Extract email or subject as user ID if available
	if email := assertion.Get("email"); email != "" {
		userID = email
	} else if name := assertion.Get("uid"); name != "" {
		userID = name
	}

	identity := &api.Identity{
		UserID:   userID,
		Metadata: make(map[string]string),
	}

	// Dynamic mapping of roles
	if s.Config.RoleField != "" {
		roleVal := assertion.Get(s.Config.RoleField)
		if roleVal != "" {
			if k8sRole, ok := s.Config.RoleMappings[roleVal]; ok {
				identity.Role = k8sRole
			} else {
				// Default to the value itself if no explicit mapping
				identity.Role = roleVal
			}
		}
	}

	// Capture groups
	if s.Config.GroupsField != "" {
		groups := assertion[s.Config.GroupsField]
		if len(groups) > 0 {
			identity.Groups = groups
		}
	}

	// Capture all attributes for metadata
	for k := range assertion {
		identity.Metadata[k] = assertion.Get(k)
	}

	klog.V(2).Infof("Mapped user %s to K8s role %s", identity.UserID, identity.Role)
	return identity, nil
}

// GetLoginURL returns the redirect URL for SAML login
func (s *SAMLSP) GetLoginURL(relayState string) (string, error) {
	return fmt.Sprintf("%s/saml/login?RelayState=%s", s.Config.RootURL, url.QueryEscape(relayState)), nil
}

// GetIdentity extracts the mapped identity from an authenticated request
func (s *SAMLSP) GetIdentity(r *http.Request) (*api.Identity, error) {
	session, err := s.SP.Session.GetSession(r)
	if err != nil {
		return nil, fmt.Errorf("getting SAML session: %w", err)
	}
	if session == nil {
		return nil, nil
	}

	return s.MapUserIdentity(session)
}

// GetSessionID retrieves the RelayState which contains the session ID in SAML
func (s *SAMLSP) GetSessionID(r *http.Request) (string, error) {
	relayState := r.FormValue("RelayState")
	if relayState == "" {
		return "", fmt.Errorf("no RelayState found in SAML request")
	}
	return relayState, nil
}

// Middleware returns the SAML middleware handler
func (s *SAMLSP) Middleware() http.Handler {
	return s.SP
}

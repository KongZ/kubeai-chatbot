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

	"github.com/KongZ/kubeai-chatbot/pkg/api"
)

// Authenticator defines the interface for different authentication methods
type Authenticator interface {
	// GetLoginURL returns the URL to redirect the user to for login
	GetLoginURL(relayState string) (string, error)
	// GetIdentity extracts and maps the user identity from an authenticated request
	GetIdentity(r *http.Request) (*api.Identity, error)
	// Middleware returns an optional HTTP middleware for authentication routes
	Middleware() http.Handler
}

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

package mcp

import (
	"reflect"
	"testing"
)

func TestAuthEnvVarName(t *testing.T) {
	cases := map[string]string{
		"datadog":    "MCP_AUTH_DATADOG",
		"my-server":  "MCP_AUTH_MY_SERVER",
		"my.server":  "MCP_AUTH_MY_SERVER",
		"already_UP": "MCP_AUTH_ALREADY_UP",
		"srv2":       "MCP_AUTH_SRV2",
	}
	for in, want := range cases {
		if got := authEnvVarName(in); got != want {
			t.Errorf("authEnvVarName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseHeaderList(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "single header",
			raw:  "Authorization=Bearer abc123",
			want: map[string]string{"Authorization": "Bearer abc123"},
		},
		{
			name: "multiple headers",
			raw:  "DD_API_KEY=key1,DD_APPLICATION_KEY=key2", // gitleaks:allow
			want: map[string]string{"DD_API_KEY": "key1", "DD_APPLICATION_KEY": "key2"},
		},
		{
			name: "value containing equals sign",
			raw:  "Authorization=Bearer abc==",
			want: map[string]string{"Authorization": "Bearer abc=="},
		},
		{
			name: "whitespace around entries",
			raw:  " Authorization = Bearer abc123 , X-Api-Key = xyz ",
			want: map[string]string{"Authorization": "Bearer abc123", "X-Api-Key": "xyz"},
		},
		{
			name: "empty string",
			raw:  "",
			want: map[string]string{},
		},
		{
			name:    "missing equals sign",
			raw:     "Authorization",
			wantErr: true,
		},
		{
			name:    "empty key",
			raw:     "=value",
			wantErr: true,
		},
		{
			name:    "empty value",
			raw:     "Authorization=",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHeaderList(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseHeaderList(%q) expected error, got nil", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHeaderList(%q) unexpected error: %v", tt.raw, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseHeaderList(%q) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestLoadAuthHeaders(t *testing.T) {
	t.Run("unset env var returns no headers", func(t *testing.T) {
		headers, err := loadAuthHeaders("unused-server-name")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if headers != nil {
			t.Errorf("expected nil headers, got %#v", headers)
		}
	})

	t.Run("set env var is parsed", func(t *testing.T) {
		t.Setenv("MCP_AUTH_DATADOG", "DD_API_KEY=key1,DD_APPLICATION_KEY=key2") // gitleaks:allow
		headers, err := loadAuthHeaders("datadog")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := map[string]string{"DD_API_KEY": "key1", "DD_APPLICATION_KEY": "key2"}
		if !reflect.DeepEqual(headers, want) {
			t.Errorf("got %#v, want %#v", headers, want)
		}
	})

	t.Run("malformed env var returns an error", func(t *testing.T) {
		t.Setenv("MCP_AUTH_BROKEN", "not-a-valid-header")
		if _, err := loadAuthHeaders("broken"); err == nil {
			t.Fatal("expected error for malformed header entry, got nil")
		}
	})
}

func TestParseServersEnv(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		want    []serverConfig
		wantErr bool
	}{
		{
			name: "empty",
			env:  "",
			want: nil,
		},
		{
			name: "single server",
			env:  "datadog=http://localhost:8080",
			want: []serverConfig{{name: "datadog", url: "http://localhost:8080"}},
		},
		{
			name: "multiple servers",
			env:  "datadog=http://localhost:8080,pagerduty=http://localhost:8081",
			want: []serverConfig{
				{name: "datadog", url: "http://localhost:8080"},
				{name: "pagerduty", url: "http://localhost:8081"},
			},
		},
		{
			name:    "missing equals sign",
			env:     "datadog",
			wantErr: true,
		},
		{
			name:    "empty name",
			env:     "=http://localhost:8080",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseServersEnv(tt.env)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseServersEnv(%q) expected error, got nil", tt.env)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseServersEnv(%q) unexpected error: %v", tt.env, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseServersEnv(%q) = %#v, want %#v", tt.env, got, tt.want)
			}
		})
	}
}

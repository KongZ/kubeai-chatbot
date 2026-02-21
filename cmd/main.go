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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/KongZ/kubeai-chatbot/gollm"
	"github.com/KongZ/kubeai-chatbot/pkg/agent"
	"github.com/KongZ/kubeai-chatbot/pkg/auth"
	"github.com/KongZ/kubeai-chatbot/pkg/journal"
	"github.com/KongZ/kubeai-chatbot/pkg/sessions"
	"github.com/KongZ/kubeai-chatbot/pkg/tools"
	"github.com/KongZ/kubeai-chatbot/pkg/ui"
	"github.com/KongZ/kubeai-chatbot/pkg/ui/slack"
	"k8s.io/klog/v2"
)

// For GoReleaser
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		signal.Stop(make(chan os.Signal))
		cancel()
		klog.Flush()
		fmt.Fprintf(os.Stderr, "\nReceived signal, shutting down gracefully... (press Ctrl+C again to force)\n")
	}()

	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		cancel()
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// klog setup
	klogFlags := flag.NewFlagSet("klog", flag.ExitOnError)
	klog.InitFlags(klogFlags)

	// Set verbosity from LOG_LEVEL env var if present
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		if err := klogFlags.Set("v", logLevel); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to set klog verbosity from LOG_LEVEL=%s: %v\n", logLevel, err)
		}
	}

	klog.SetOutput(os.Stdout)
	defer klog.Flush()

	// Configuration from environment
	providerID := getEnv("LLM_PROVIDER", "gemini")
	modelID := getEnv("MODEL_ID", "gemini-3-flash-preview")
	listenAddress := getEnv("LISTEN_ADDRESS", "0.0.0.0:8888")
	kubeconfig := getEnv("KUBECONFIG", filepath.Join(os.Getenv("HOME"), ".kube", "config"))
	agentName := getEnv("AGENT_NAME", "kubeai")
	uiType := getEnv("UI_TYPE", "slack")
	sessionType := getEnv("SESSION_TYPE", "memory")
	automaticModifyResources := getBoolEnv("AUTOMATIC_MODIFY_RESOURCES", true)

	klog.Infof("Starting kubeai-chatbot (version: %s, commit: %s, date: %s)", version, commit, date)
	klog.Infof("Configuration: provider=%s, model=%s, listen=%s", providerID, modelID, listenAddress)

	// Initialize session manager
	sessionManager, err := sessions.NewSessionManager(sessionType)
	if err != nil {
		return fmt.Errorf("failed to create session manager: %w", err)
	}

	// Initialize journal recorder
	recorder := &journal.LogRecorder{}
	defer func() {
		if err := recorder.Close(); err != nil {
			klog.Errorf("error closing recorder: %v", err)
		}
	}()

	// Agent factory
	agentFactory := func(ctx context.Context) (*agent.Agent, error) {
		var client gollm.Client
		client, err = gollm.NewClient(ctx, providerID)
		if err != nil {
			return nil, fmt.Errorf("creating llm client: %w", err)
		}

		// Create a new Tools instance for each agent to avoid sharing state
		agentTools := tools.Tools{}
		agentTools.Init()

		return &agent.Agent{
			Model:                    modelID,
			Provider:                 providerID,
			Kubeconfig:               kubeconfig,
			LLM:                      client,
			MaxIterations:            20,
			Tools:                    agentTools,
			Recorder:                 recorder,
			SessionBackend:           sessionType,
			AgentName:                agentName,
			AutomaticModifyResources: automaticModifyResources,
		}, nil
	}

	agentManager := agent.NewAgentManager(agentFactory, sessionManager)
	defer func() {
		if err := agentManager.Close(); err != nil {
			klog.Errorf("error closing agent manager: %v", err)
		}
	}()

	var userInterface ui.UI
	switch ui.Type(uiType) {
	case ui.UITypeSlack:
		contextMessage := getEnv("SLACK_CONTEXT_MESSAGE", "I am an AI assistant here to help.")

		// Authentication configuration
		authMethod := strings.ToUpper(getEnv("AUTH_METHOD", "NONE"))
		var authenticator auth.Authenticator

		switch authMethod {
		case "SAML":
			samlConfig := auth.SAMLConfig{
				Enabled:        true,
				IDPMetadataURL: getEnv("SAML_IDP_METADATA_URL", ""),
				EntityID:       getEnv("SAML_ENTITY_ID", ""),
				RootURL:        getEnv("SAML_ROOT_URL", ""),
				KeyFile:        getEnv("SAML_KEY_FILE", ""),
				CertFile:       getEnv("SAML_CERT_FILE", ""),
				RoleField:      getEnv("SAML_ROLE_FIELD", ""),
				GroupsField:    getEnv("SAML_GROUPS_FIELD", ""),
			}
			samlConfig.RoleMappings = make(map[string]string)
			if mappingStr := getEnv("SAML_ROLE_MAPPINGS", ""); mappingStr != "" {
				for _, pair := range strings.Split(mappingStr, ",") {
					parts := strings.Split(pair, ":")
					if len(parts) == 2 {
						samlConfig.RoleMappings[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
			authenticator, err = auth.NewSAMLSP(samlConfig)

		case "OIDC":
			oidcConfig := auth.OIDCConfig{
				Enabled:      true,
				IssuerURL:    getEnv("OIDC_ISSUER_URL", ""),
				ClientID:     getEnv("OIDC_CLIENT_ID", ""),
				ClientSecret: getEnv("OIDC_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("OIDC_REDIRECT_URL", ""),
				RoleField:    getEnv("OIDC_ROLE_FIELD", ""),
				GroupsField:  getEnv("OIDC_GROUPS_FIELD", ""),
			}
			oidcConfig.RoleMappings = make(map[string]string)
			if mappingStr := getEnv("OIDC_ROLE_MAPPINGS", ""); mappingStr != "" {
				for _, pair := range strings.Split(mappingStr, ",") {
					parts := strings.Split(pair, ":")
					if len(parts) == 2 {
						oidcConfig.RoleMappings[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
			authenticator, err = auth.NewOIDCSP(oidcConfig)

		case "NONE":
			authenticator = nil
		default:
			return fmt.Errorf("unknown AUTH_METHOD: %s", authMethod)
		}

		if err != nil {
			return fmt.Errorf("initializing authenticator (%s): %w", authMethod, err)
		}

		userInterface, err = slack.NewSlackUI(agentManager, sessionManager, modelID, providerID, listenAddress, agentName, contextMessage, authenticator)
		if err != nil {
			return fmt.Errorf("creating slack UI: %w", err)
		}
	default:
		return fmt.Errorf("ui-type mode %q is not known", uiType)
	}
	err = userInterface.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("running UI: %w", err)
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		b, err := strconv.ParseBool(value)
		if err != nil {
			return defaultValue
		}
		return b
	}
	return defaultValue
}

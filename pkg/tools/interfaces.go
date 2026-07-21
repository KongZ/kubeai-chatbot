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

package tools

import (
	"context"

	"github.com/KongZ/kubeai-chatbot/gollm"
)

type Tool interface {
	// Name is the identifier for the tool; we pass this to the LLM.
	// The LLM uses this name when it wants to invoke the tool.
	// It should be meaningful and (we think) camel_case as (we think) that works better with most LLMs.
	Name() string

	// Description is an additional description that gives the LLM instructions on when to use the tool.
	Description() string

	// FunctionDefinition provides the full schema for the parameters to be used when invoking the tool.
	// The Description fields provides hints that the LLM may use to use the tool more effectively/correctly.
	FunctionDefinition() *gollm.FunctionDefinition

	// Run invokes the tool, the agent calls this when the LLM requests tool invocation.
	Run(ctx context.Context, args map[string]any) (any, error)

	// IsInteractive checks if a command is interactive
	// If the command is interactive, we need to handle it differently in the agent
	// Returns true if interactive, with an error explaining why it's interactive
	IsInteractive(args map[string]any) (bool, error)

	// CheckModifiesResource determines if the command modifies resources
	// This is used for permission checks before command execution
	// Returns "yes", "no", or "unknown"
	CheckModifiesResource(args map[string]any) string
}

// KubeContextExtractor is an optional capability a Tool may implement when
// its commands target a specific Kubernetes context (e.g. kubectl's
// --context flag). The agent loop uses this to detect a mid-query cluster
// switch and block it before execution, rather than relying solely on the
// system prompt's "one cluster per response" instruction being followed.
// Tools with no notion of a cluster context (or that couldn't parse one out
// of this particular call) return ok=false.
type KubeContextExtractor interface {
	ExtractKubeContext(args map[string]any) (kubeContext string, ok bool)
}

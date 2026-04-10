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
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/KongZ/kubeai-chatbot/gollm"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"mvdan.cc/sh/v3/syntax"
)

var (
	cachedBaseEnv     []string
	cachedBaseEnvOnce sync.Once
)

// baseEnviron returns a copy of the cached process environment.
// The base environment is captured once to avoid repeated os.Environ() syscalls.
func baseEnviron() []string {
	cachedBaseEnvOnce.Do(func() {
		cachedBaseEnv = os.Environ()
	})
	env := make([]string, len(cachedBaseEnv))
	copy(env, cachedBaseEnv)
	return env
}

type ExecResult struct {
	Command    string `json:"command"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Error      string `json:"error,omitempty"`
	ExitCode   int    `json:"exit_code"`
	Duration   string `json:"duration,omitempty"`
	StreamType string `json:"stream_type,omitempty"` // For streaming commands: "timeout", "watch", "logs", etc.
}

type Kubectl struct{}

func NewKubectlTool() *Kubectl {
	return &Kubectl{}
}

func (t *Kubectl) Name() string {
	return "kubectl"
}

func (t *Kubectl) Description() string {
	return `Executes a kubectl command against the user's Kubernetes cluster.`
}

func (t *Kubectl) FunctionDefinition() *gollm.FunctionDefinition {
	return cliToolFunctionDefinition(
		t.Name(),
		t.Description(),
		`The complete kubectl command to execute. Include the kubectl prefix.`,
		"a Kubernetes",
	)
}

func (t *Kubectl) Run(ctx context.Context, args map[string]any) (any, error) {
	kubeconfig := ctx.Value(KubeconfigKey).(string)

	command, ok := commandStringFromArgs(args)
	if !ok {
		return &ExecResult{Command: "", Error: "kubectl command not provided or is nil"}, nil
	}

	if err := validateKubectlCommand(command); err != nil {
		return &ExecResult{Command: command, Error: err.Error()}, nil
	}

	cmdArgs, errResult := parseCommandArgs(command)
	if errResult != nil {
		return errResult, nil
	}

	// Apply impersonation if identity is present
	if identity, ok := ctx.Value(IdentityKey).(*api.Identity); ok && identity != nil {
		if identity.Role != "" {
			cmdArgs = append(cmdArgs, "--as="+identity.Role)
		}
		for _, group := range identity.Groups {
			cmdArgs = append(cmdArgs, "--as-group="+group)
		}
	}

	env := baseEnviron()
	if kubeconfig != "" {
		expanded, err := ExpandShellVar(kubeconfig)
		if err != nil {
			return &ExecResult{Command: strings.Join(cmdArgs, " "), Error: err.Error()}, nil
		}
		env = append(env, "KUBECONFIG="+expanded)
	}

	return runCommand(ctx, cmdArgs, env), nil
}

func (t *Kubectl) IsInteractive(args map[string]any) (bool, error) {
	command, ok := commandStringFromArgs(args)
	if !ok {
		return false, nil
	}
	return IsInteractiveCommand(command)
}

func (t *Kubectl) CheckModifiesResource(args map[string]any) string {
	command, ok := args["command"].(string)
	if !ok {
		return "unknown"
	}

	return kubectlModifiesResource(command)
}

func validateKubectlCommand(command string) error {
	lowerCmd := strings.ToLower(command)
	if strings.Contains(lowerCmd, "secret") || strings.Contains(lowerCmd, "secrets") {
		return fmt.Errorf("retrieving or accessing Kubernetes secrets is strictly prohibited")
	}
	if strings.Contains(command, "kubectl edit") {
		return fmt.Errorf("interactive mode not supported for kubectl, please use non-interactive commands")
	}
	if strings.Contains(command, "kubectl port-forward") {
		return fmt.Errorf("port-forwarding is not allowed, please try some other alternative")
	}
	if isCompoundCommand(command) {
		return fmt.Errorf("compound commands with pipes (|), &&, ||, or ; are not allowed. Use a single standalone kubectl command instead")
	}
	return nil
}

// isCompoundCommand returns true if the shell-parsed command contains any pipe or
// chaining operators (|, &&, ||, ;). These are unsupported because the tool
// executes kubectl directly without a shell, so they would fail at runtime.
func isCompoundCommand(command string) bool {
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return false
	}
	// Semicolons produce multiple top-level Stmt nodes rather than a BinaryCmd.
	if len(file.Stmts) > 1 {
		return true
	}
	compound := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.BinaryCmd); ok {
			compound = true
			return false
		}
		return true
	})
	return compound
}

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
	"os/exec"
	"strings"
	"time"

	"github.com/KongZ/kubeai-chatbot/gollm"
)

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
	return &gollm.FunctionDefinition{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &gollm.Schema{
			Type: gollm.TypeObject,
			Properties: map[string]*gollm.Schema{
				"command": {
					Type:        gollm.TypeString,
					Description: `The complete kubectl command to execute. Include the kubectl prefix.`,
				},
				"modifies_resource": {
					Type: gollm.TypeString,
					Description: `Whether the command modifies a kubernetes resource.
Possible values:
- "yes" if the command modifies a resource
- "no" if the command does not modify a resource
- "unknown" if the command's effect on the resource is unknown`},
			},
		},
	}
}

func (t *Kubectl) Run(ctx context.Context, args map[string]any) (any, error) {
	kubeconfig := ctx.Value(KubeconfigKey).(string)

	commandVal, ok := args["command"]
	if !ok || commandVal == nil {
		return &ExecResult{Command: "", Error: "kubectl command not provided or is nil"}, nil
	}

	command, ok := commandVal.(string)
	if !ok {
		return &ExecResult{Command: "", Error: "kubectl command must be a string"}, nil
	}

	// Check for interactive commands
	if err := validateKubectlCommand(command); err != nil {
		return &ExecResult{Command: command, Error: err.Error()}, nil
	}

	// Prepare environment
	env := os.Environ()
	if kubeconfig != "" {
		kubeconfig, err := ExpandShellVar(kubeconfig)
		if err != nil {
			return &ExecResult{Command: command, Error: err.Error()}, nil
		}
		env = append(env, "KUBECONFIG="+kubeconfig)
	}

	// Execute command
	start := time.Now()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Env = env

	stdout, err := cmd.Output()
	duration := time.Since(start)

	result := &ExecResult{
		Command:  command,
		Stdout:   string(stdout),
		Duration: duration.String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.Stderr = string(exitErr.Stderr)
			result.ExitCode = exitErr.ExitCode()
			result.Error = fmt.Sprintf("command exited with code %d", exitErr.ExitCode())
		} else {
			result.Error = err.Error()
		}
	}

	return result, nil
}

func (t *Kubectl) IsInteractive(args map[string]any) (bool, error) {
	commandVal, ok := args["command"]
	if !ok || commandVal == nil {
		return false, nil
	}

	command, ok := commandVal.(string)
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
	return nil
}

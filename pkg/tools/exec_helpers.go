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

package tools

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/KongZ/kubeai-chatbot/gollm"
	"mvdan.cc/sh/v3/shell"
)

// commandStringFromArgs extracts the "command" string from a tool args map.
// Returns ("", false) if the key is absent, nil, or not a string.
func commandStringFromArgs(args map[string]any) (string, bool) {
	v, ok := args["command"]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// cliToolFunctionDefinition builds the standard FunctionDefinition for a CLI
// tool that takes a "command" string and a "modifies_resource" flag.
// commandDescription describes the expected format of the command argument.
// resourceLabel is inserted into the modifies_resource description (e.g. "a Kubernetes", "an AWS").
func cliToolFunctionDefinition(name, description, commandDescription, resourceLabel string) *gollm.FunctionDefinition {
	return &gollm.FunctionDefinition{
		Name:        name,
		Description: description,
		Parameters: &gollm.Schema{
			Type: gollm.TypeObject,
			Properties: map[string]*gollm.Schema{
				"command": {
					Type:        gollm.TypeString,
					Description: commandDescription,
				},
				"modifies_resource": modifiesResourceParamSchema(resourceLabel),
			},
		},
	}
}

// modifiesResourceParamSchema returns the standard modifies_resource parameter
// schema shared by CLI tools. resourceLabel is used in the description
// (e.g. "a Kubernetes", "an AWS").
func modifiesResourceParamSchema(resourceLabel string) *gollm.Schema {
	return &gollm.Schema{
		Type: gollm.TypeString,
		Description: fmt.Sprintf(`Whether the command modifies %s resource.
Possible values:
- "yes" if the command modifies a resource
- "no" if the command does not modify a resource
- "unknown" if the command's effect on the resource is unknown`, resourceLabel),
	}
}

// parseCommandArgs parses a raw command string into an argument slice using
// shell field-splitting rules (no shell execution). Returns a non-nil
// *ExecResult on parse failure or empty input.
func parseCommandArgs(command string) ([]string, *ExecResult) {
	cmdArgs, err := shell.Fields(command, nil)
	if err != nil {
		return nil, &ExecResult{Command: command, Error: fmt.Sprintf("parsing command: %v", err)}
	}
	if len(cmdArgs) == 0 {
		return nil, &ExecResult{Command: command, Error: "empty command"}
	}
	return cmdArgs, nil
}

// runCommand executes cmdArgs directly (no shell), captures stdout/stderr, and
// returns an ExecResult. The caller is responsible for building the environment.
func runCommand(ctx context.Context, cmdArgs []string, env []string) *ExecResult { //nolint:gosec // G204: callers pass a validated, whitelist-checked binary as cmdArgs[0]
	fullCommand := strings.Join(cmdArgs, " ")

	start := time.Now()
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env

	stdout, err := cmd.Output()
	duration := time.Since(start)

	result := &ExecResult{
		Command:  fullCommand,
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

	return result
}

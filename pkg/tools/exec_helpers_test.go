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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- commandStringFromArgs ---

func TestCommandStringFromArgs_Valid(t *testing.T) {
	s, ok := commandStringFromArgs(map[string]any{"command": "kubectl get pods"})
	assert.True(t, ok)
	assert.Equal(t, "kubectl get pods", s)
}

func TestCommandStringFromArgs_MissingKey(t *testing.T) {
	s, ok := commandStringFromArgs(map[string]any{})
	assert.False(t, ok)
	assert.Empty(t, s)
}

func TestCommandStringFromArgs_NilValue(t *testing.T) {
	s, ok := commandStringFromArgs(map[string]any{"command": nil})
	assert.False(t, ok)
	assert.Empty(t, s)
}

func TestCommandStringFromArgs_WrongType(t *testing.T) {
	s, ok := commandStringFromArgs(map[string]any{"command": 42})
	assert.False(t, ok)
	assert.Empty(t, s)
}

// --- cliToolFunctionDefinition ---

func TestCLIToolFunctionDefinition(t *testing.T) {
	fd := cliToolFunctionDefinition("mytool", "does stuff", "run mytool <cmd>", "a My")
	assert.Equal(t, "mytool", fd.Name)
	assert.Equal(t, "does stuff", fd.Description)
	require.NotNil(t, fd.Parameters)
	cmd := fd.Parameters.Properties["command"]
	require.NotNil(t, cmd)
	assert.Equal(t, "run mytool <cmd>", cmd.Description)
	mod := fd.Parameters.Properties["modifies_resource"]
	require.NotNil(t, mod)
	assert.Contains(t, mod.Description, "a My")
}

// --- modifiesResourceParamSchema ---

func TestModifiesResourceParamSchema_ContainsLabel(t *testing.T) {
	schema := modifiesResourceParamSchema("a Kubernetes")
	assert.Contains(t, schema.Description, "a Kubernetes")

	schema2 := modifiesResourceParamSchema("an AWS")
	assert.Contains(t, schema2.Description, "an AWS")
}

func TestModifiesResourceParamSchema_ContainsValues(t *testing.T) {
	schema := modifiesResourceParamSchema("a Kubernetes")
	assert.Contains(t, schema.Description, `"yes"`)
	assert.Contains(t, schema.Description, `"no"`)
	assert.Contains(t, schema.Description, `"unknown"`)
}

// --- parseCommandArgs ---

func TestParseCommandArgs_Valid(t *testing.T) {
	args, errResult := parseCommandArgs("kubectl get pods -n default")
	require.Nil(t, errResult)
	assert.Equal(t, []string{"kubectl", "get", "pods", "-n", "default"}, args)
}

func TestParseCommandArgs_SingleWord(t *testing.T) {
	args, errResult := parseCommandArgs("kubectl")
	require.Nil(t, errResult)
	assert.Equal(t, []string{"kubectl"}, args)
}

func TestParseCommandArgs_Empty(t *testing.T) {
	args, errResult := parseCommandArgs("")
	assert.Nil(t, args)
	require.NotNil(t, errResult)
	assert.NotEmpty(t, errResult.Error)
}

func TestParseCommandArgs_Whitespace(t *testing.T) {
	args, errResult := parseCommandArgs("   ")
	assert.Nil(t, args)
	require.NotNil(t, errResult)
	assert.NotEmpty(t, errResult.Error)
}

func TestParseCommandArgs_PreservesQuotedArgs(t *testing.T) {
	args, errResult := parseCommandArgs(`kubectl get pods -l "app=my-app"`)
	require.Nil(t, errResult)
	assert.Contains(t, args, "app=my-app")
}

// --- runCommand ---

func TestRunCommand_Success(t *testing.T) {
	result := runCommand(context.Background(), []string{"echo", "hello"}, nil)
	assert.Empty(t, result.Error)
	assert.Equal(t, 0, result.ExitCode)
	assert.True(t, strings.Contains(result.Stdout, "hello"))
	assert.NotEmpty(t, result.Duration)
}

func TestRunCommand_NonZeroExit(t *testing.T) {
	result := runCommand(context.Background(), []string{"false"}, nil)
	assert.NotEmpty(t, result.Error)
	assert.NotEqual(t, 0, result.ExitCode)
}

func TestRunCommand_CommandNotFound(t *testing.T) {
	result := runCommand(context.Background(), []string{"this-binary-does-not-exist-xyz"}, nil)
	assert.NotEmpty(t, result.Error)
}

func TestRunCommand_FullCommandInResult(t *testing.T) {
	result := runCommand(context.Background(), []string{"echo", "hello", "world"}, nil)
	assert.Equal(t, "echo hello world", result.Command)
}

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compile-time assertion: AWSDevOpsAgent must implement ToolWithWaitMessage.
var _ ToolWithWaitMessage = (*AWSDevOpsAgent)(nil)

func TestAWSDevOpsAgentName(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	assert.Equal(t, "aws_devops_agent", tool.Name())
}

func TestAWSDevOpsAgentWaitMessage_NotEmpty(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	assert.NotEmpty(t, tool.WaitMessage())
}

func TestAWSDevOpsAgentIsInteractive(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	interactive, err := tool.IsInteractive(map[string]any{"message": "help me"})
	assert.False(t, interactive)
	assert.NoError(t, err)
}

func TestAWSDevOpsAgentIsInteractive_NoArgs(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	interactive, err := tool.IsInteractive(map[string]any{})
	assert.False(t, interactive)
	assert.NoError(t, err)
}

func TestAWSDevOpsAgentCheckModifiesResource(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	assert.Equal(t, "no", tool.CheckModifiesResource(map[string]any{}))
	assert.Equal(t, "no", tool.CheckModifiesResource(map[string]any{"message": "anything"}))
}

func TestAWSDevOpsAgentFunctionDefinition(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	def := tool.FunctionDefinition()
	assert.Equal(t, "aws_devops_agent", def.Name)
	require.NotNil(t, def.Parameters)
	_, hasMessage := def.Parameters.Properties["message"]
	assert.True(t, hasMessage, "schema should have a 'message' property")
	assert.Contains(t, def.Parameters.Required, "message")
}

// --- Run: input validation ---

func TestAWSDevOpsAgentRun_MissingMessage(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	result, err := tool.Run(context.Background(), map[string]any{})
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.NotEmpty(t, execResult.Error)
}

func TestAWSDevOpsAgentRun_EmptyMessage(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	result, err := tool.Run(context.Background(), map[string]any{"message": ""})
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.NotEmpty(t, execResult.Error)
}

func TestAWSDevOpsAgentRun_WhitespaceMessage(t *testing.T) {
	tool := NewAWSDevOpsAgentTool()
	result, err := tool.Run(context.Background(), map[string]any{"message": "   "})
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.NotEmpty(t, execResult.Error)
}

func TestAWSDevOpsAgentRun_MissingSpaceID(t *testing.T) {
	t.Setenv("AWS_DEVOPS_AGENT_SPACE_ID", "")
	tool := NewAWSDevOpsAgentTool()
	result, err := tool.Run(context.Background(), map[string]any{"message": "help"})
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.Contains(t, execResult.Error, "AWS_DEVOPS_AGENT_SPACE_ID")
}

// --- Run: command shape ---

// TestAWSDevOpsAgentRun_CreateChat_CommandShape verifies that create-chat is invoked
// with the correct flags. The command will fail without real AWS credentials but the
// ExecResult.Command field is always populated before execution.
func TestAWSDevOpsAgentRun_CreateChat_CommandShape(t *testing.T) {
	t.Setenv("AWS_DEVOPS_AGENT_SPACE_ID", "test-space-id")
	tool := NewAWSDevOpsAgentTool()
	result, err := tool.Run(context.Background(), map[string]any{"message": "test question"})
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	// create-chat either succeeds (real AWS) or fails (no credentials) — either way
	// the Command field reflects the first step that was attempted.
	assert.Contains(t, execResult.Command, "aws devops-agent create-chat")
	assert.Contains(t, execResult.Command, "--agent-space-id test-space-id")
}

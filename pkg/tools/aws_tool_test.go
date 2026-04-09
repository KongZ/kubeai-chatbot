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
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipIfNoAWS(t *testing.T) {
	if _, err := exec.LookPath("aws"); err != nil {
		t.Skip("aws binary not found in PATH, skipping test")
	}
}

func TestAWSRun_ValidCommand(t *testing.T) {
	skipIfNoAWS(t)
	tool := NewAWSTool()
	ctx := context.Background()
	args := map[string]any{"command": "aws --version"}
	result, err := tool.Run(ctx, args)
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.Equal(t, "aws --version", execResult.Command)
}

func TestAWSRun_BlocksSecretsManager(t *testing.T) {
	tool := NewAWSTool()
	ctx := context.Background()
	args := map[string]any{"command": "aws secretsmanager get-secret-value --secret-id my-secret"}
	result, err := tool.Run(ctx, args)
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.NotEmpty(t, execResult.Error)
	assert.Contains(t, execResult.Error, "not allowed")
}

func TestAWSRun_BlocksSSMGetParameter(t *testing.T) {
	tool := NewAWSTool()
	ctx := context.Background()
	args := map[string]any{"command": "aws ssm get-parameter --name /my/param"}
	result, err := tool.Run(ctx, args)
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.NotEmpty(t, execResult.Error)
	assert.Contains(t, execResult.Error, "not allowed")
}

func TestAWSRun_BlocksKMSDecrypt(t *testing.T) {
	tool := NewAWSTool()
	ctx := context.Background()
	args := map[string]any{"command": "aws kms decrypt --ciphertext-blob fileb://cipher.txt"}
	result, err := tool.Run(ctx, args)
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.NotEmpty(t, execResult.Error)
	assert.Contains(t, execResult.Error, "not allowed")
}

func TestAWSRun_BlocksCompoundCommand(t *testing.T) {
	tool := NewAWSTool()
	ctx := context.Background()
	args := map[string]any{"command": "aws ec2 describe-instances | grep running"}
	result, err := tool.Run(ctx, args)
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.NotEmpty(t, execResult.Error)
	assert.Contains(t, execResult.Error, "not allowed")
}

func TestAWSRun_MissingCommand(t *testing.T) {
	tool := NewAWSTool()
	result, err := tool.Run(context.Background(), map[string]any{})
	require.NoError(t, err)
	execResult := result.(*ExecResult)
	assert.NotEmpty(t, execResult.Error)
}

// --- awsModifiesResource ---

func TestAWSModifiesResource(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"aws ec2 describe-instances", "no"},
		{"aws ec2 list-instances", "no"},
		{"aws eks describe-cluster --name my-cluster", "no"},
		{"aws s3 ls s3://my-bucket", "no"},
		{"aws ec2 create-instance", "yes"},
		{"aws ec2 delete-security-group --group-id sg-123", "yes"},
		{"aws ec2 start-instances --instance-ids i-123", "yes"},
		{"aws ec2 stop-instances --instance-ids i-123", "yes"},
		{"aws ec2 terminate-instances --instance-ids i-123", "yes"},
		{"aws s3 put-object --bucket b --key k", "yes"},
		{"aws elb modify-load-balancer-attributes", "yes"},
		{"aws ec2 run-instances", "yes"},
		{"aws", "unknown"},
		{"aws ec2", "unknown"},
		{"aws ec2 some-unknown-subcommand", "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.command, func(t *testing.T) {
			got := awsModifiesResource(tc.command)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAWSCheckModifiesResource(t *testing.T) {
	tool := NewAWSTool()
	assert.Equal(t, "no", tool.CheckModifiesResource(map[string]any{"command": "aws ec2 describe-instances"}))
	assert.Equal(t, "yes", tool.CheckModifiesResource(map[string]any{"command": "aws ec2 terminate-instances --instance-ids i-123"}))
	assert.Equal(t, "unknown", tool.CheckModifiesResource(map[string]any{}))
}

// --- IsInteractive ---

func TestAWSIsInteractive_Configure(t *testing.T) {
	tool := NewAWSTool()
	interactive, err := tool.IsInteractive(map[string]any{"command": "aws configure"})
	assert.True(t, interactive)
	assert.Error(t, err)
}

func TestAWSIsInteractive_SSOLogin(t *testing.T) {
	tool := NewAWSTool()
	interactive, err := tool.IsInteractive(map[string]any{"command": "aws sso login"})
	assert.True(t, interactive)
	assert.Error(t, err)
}

func TestAWSIsInteractive_CompoundCommand(t *testing.T) {
	tool := NewAWSTool()
	interactive, err := tool.IsInteractive(map[string]any{"command": "aws ec2 describe-instances && echo done"})
	assert.True(t, interactive)
	assert.Error(t, err)
}

func TestAWSIsInteractive_NormalCommand(t *testing.T) {
	tool := NewAWSTool()
	interactive, err := tool.IsInteractive(map[string]any{"command": "aws ec2 describe-instances --region ap-southeast-1"})
	assert.False(t, interactive)
	assert.NoError(t, err)
}

// --- validateAWSCommand ---

func TestValidateAWSCommand_BlocksIAMCreateAccessKey(t *testing.T) {
	err := validateAWSCommand("aws iam create-access-key --user-name myuser")
	assert.Error(t, err)
}

func TestValidateAWSCommand_BlocksSTSAssumeRole(t *testing.T) {
	err := validateAWSCommand("aws sts assume-role --role-arn arn:aws:iam::123:role/MyRole --role-session-name test")
	assert.Error(t, err)
}

func TestValidateAWSCommand_AllowsDescribe(t *testing.T) {
	err := validateAWSCommand("aws ec2 describe-instances --region ap-southeast-1")
	assert.NoError(t, err)
}

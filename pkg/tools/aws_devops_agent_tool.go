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
	"encoding/json"
	"os"
	"strings"

	"github.com/KongZ/kubeai-chatbot/gollm"
)

type AWSDevOpsAgent struct{}

func NewAWSDevOpsAgentTool() *AWSDevOpsAgent {
	return &AWSDevOpsAgent{}
}

func (t *AWSDevOpsAgent) Name() string {
	return "aws_devops_agent"
}

func (t *AWSDevOpsAgent) Description() string {
	return `Slow, expensive tool — use sparingly. Consults AWS DevOps Agent for advice on AWS-specific topics only.

ONLY call this tool when ALL of the following are true:
- The user's question is explicitly about an AWS service (e.g. EKS node groups, EC2, ALB/NLB, IAM, RDS, S3, VPC, CloudWatch, Route53).
- The aws CLI tool cannot answer it with a single describe/list/get command.
- You have already attempted to gather relevant information with kubectl or aws tools and still cannot resolve the issue.

Do NOT call this tool when:
- The question is about Kubernetes resources, workloads, or configurations (use kubectl instead).
- The question can be answered by running a standard aws CLI read command (use the aws tool instead).
- The question is about application-level issues (logs, crashes, misconfigurations) with no clear AWS infrastructure component.
- You have not yet tried kubectl first, or the aws tool first if it is available.`
}

func (t *AWSDevOpsAgent) FunctionDefinition() *gollm.FunctionDefinition {
	return &gollm.FunctionDefinition{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &gollm.Schema{
			Type: gollm.TypeObject,
			Properties: map[string]*gollm.Schema{
				"message": {
					Type: gollm.TypeString,
					Description: `The question or problem description to send to AWS DevOps Agent.
Include relevant context: error messages, resource names, region, what kubectl/aws commands
you already ran, and what they returned.`,
				},
			},
			Required: []string{"message"},
		},
	}
}

func (t *AWSDevOpsAgent) Run(ctx context.Context, args map[string]any) (any, error) {
	message, ok := args["message"].(string)
	if !ok || strings.TrimSpace(message) == "" {
		return &ExecResult{Command: "", Error: "message not provided or is empty"}, nil
	}

	agentSpaceID := os.Getenv("AWS_DEVOPS_AGENT_SPACE_ID")
	if agentSpaceID == "" {
		return &ExecResult{Command: "", Error: "AWS_DEVOPS_AGENT_SPACE_ID environment variable is not set"}, nil
	}

	// Step 1: create a chat session and obtain an executionId.
	createResult := runCommand(ctx, []string{
		"aws", "devops-agent", "create-chat",
		"--agent-space-id", agentSpaceID,
	}, baseEnviron())
	if createResult.Error != "" {
		return createResult, nil
	}

	// Parse the executionId from the create-chat JSON response.
	var createResponse struct {
		ExecutionID string `json:"executionId"`
	}
	if err := json.Unmarshal([]byte(createResult.Stdout), &createResponse); err != nil || createResponse.ExecutionID == "" {
		return &ExecResult{
			Command: createResult.Command,
			Stdout:  createResult.Stdout,
			Stderr:  createResult.Stderr,
			Error:   "failed to parse executionId from create-chat response",
		}, nil
	}

	// Step 2: send the message to the active chat session.
	return runCommand(ctx, []string{
		"aws", "devops-agent", "send-message",
		"--agent-space-id", agentSpaceID,
		"--execution-id", createResponse.ExecutionID,
		"--content", message,
	}, baseEnviron()), nil
}

func (t *AWSDevOpsAgent) WaitMessage() string {
	return "Consulting AWS DevOps Agent — this may take a moment, please wait..."
}

func (t *AWSDevOpsAgent) IsInteractive(_ map[string]any) (bool, error) {
	return false, nil
}

func (t *AWSDevOpsAgent) CheckModifiesResource(_ map[string]any) string {
	return "no"
}

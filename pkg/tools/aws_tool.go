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
	"strings"

	"github.com/KongZ/kubeai-chatbot/gollm"
)

type AWS struct{}

func NewAWSTool() *AWS {
	return &AWS{}
}

func (t *AWS) Name() string {
	return "aws"
}

func (t *AWS) Description() string {
	return `Executes an AWS CLI command to query or manage AWS resources. Use this tool when the user asks about AWS infrastructure such as EKS clusters, EC2 instances, load balancers (ELB/ALB/NLB), RDS databases, S3 buckets, IAM roles and policies, CloudWatch metrics and logs, Route53, VPCs, security groups, or any other AWS service. Do not use this tool to retrieve secrets or credentials.`
}

func (t *AWS) FunctionDefinition() *gollm.FunctionDefinition {
	return &gollm.FunctionDefinition{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &gollm.Schema{
			Type: gollm.TypeObject,
			Properties: map[string]*gollm.Schema{
				"command": {
					Type:        gollm.TypeString,
					Description: `The complete AWS CLI command to execute. Include the aws prefix (e.g. "aws ec2 describe-instances --region ap-southeast-1").`,
				},
				"modifies_resource": modifiesResourceParamSchema("an AWS"),
			},
		},
	}
}

func (t *AWS) Run(ctx context.Context, args map[string]any) (any, error) {
	command, ok := commandStringFromArgs(args)
	if !ok {
		return &ExecResult{Command: "", Error: "aws command not provided or is nil"}, nil
	}

	if err := validateAWSCommand(command); err != nil {
		return &ExecResult{Command: command, Error: err.Error()}, nil
	}

	cmdArgs, errResult := parseCommandArgs(command)
	if errResult != nil {
		return errResult, nil
	}

	return runCommand(ctx, cmdArgs, baseEnviron()), nil
}

func (t *AWS) IsInteractive(args map[string]any) (bool, error) {
	command, ok := commandStringFromArgs(args)
	if !ok {
		return false, nil
	}

	lower := strings.ToLower(command)
	if strings.Contains(lower, "aws configure") || strings.Contains(lower, "aws sso login") {
		return true, fmt.Errorf("interactive AWS commands are not supported")
	}
	if isCompoundCommand(command) {
		return true, fmt.Errorf("compound commands with pipes (|), &&, ||, or ; are not allowed. Use a single standalone aws command instead")
	}
	return false, nil
}

func (t *AWS) CheckModifiesResource(args map[string]any) string {
	command, ok := args["command"].(string)
	if !ok {
		return "unknown"
	}
	return awsModifiesResource(command)
}

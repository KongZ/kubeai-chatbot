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
	"fmt"
	"strings"
)

var (
	awsReadOnlyPrefixes = []string{
		"describe", "list", "get", "ls", "show", "view", "filter",
	}

	awsWritePrefixes = []string{
		"create", "delete", "update", "put", "attach", "detach", "modify",
		"run", "start", "stop", "terminate", "publish", "send", "invoke",
		"reboot", "deregister", "register",
	}

	// blockedAWSPhrases are service+subcommand pairs that expose secrets or credentials.
	blockedAWSPhrases = []string{
		"secretsmanager get-secret-value",
		"ssm get-parameter",
		"ssm get-parameters",
		"kms decrypt",
		"kms generate-data-key",
		"iam create-access-key",
		"sts assume-role",
	}
)

func validateAWSCommand(command string) error {
	lower := strings.ToLower(command)
	for _, phrase := range blockedAWSPhrases {
		if strings.Contains(lower, phrase) {
			return fmt.Errorf("aws command %q is not allowed: retrieving secrets or credentials is prohibited", phrase)
		}
	}
	if isCompoundCommand(command) {
		return fmt.Errorf("compound commands with pipes (|), &&, ||, or ; are not allowed. Use a single standalone aws command instead")
	}
	return nil
}

// awsModifiesResource classifies an AWS CLI command as read-only, write, or unknown.
// It looks for the subcommand (the word after the service, e.g. "describe-instances"
// in "aws ec2 describe-instances") and matches it against known prefixes.
func awsModifiesResource(command string) string {
	words := strings.Fields(command)
	// Expect at least: aws <service> <subcommand>
	if len(words) < 3 {
		return "unknown"
	}

	// words[0] == "aws", words[1] == service, words[2] == subcommand
	subcommand := strings.ToLower(words[2])

	for _, prefix := range awsWritePrefixes {
		if strings.HasPrefix(subcommand, prefix) {
			return "yes"
		}
	}

	for _, prefix := range awsReadOnlyPrefixes {
		if strings.HasPrefix(subcommand, prefix) {
			return "no"
		}
	}

	return "unknown"
}

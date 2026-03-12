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
	"github.com/KongZ/kubeai-chatbot/pkg/mcp"
)

// MCPTool wraps a single MCP server tool as a kubeai Tool.
// The tool name is prefixed with "mcp_<serverName>_" to avoid collisions.
type MCPTool struct {
	discovered *mcp.DiscoveredTool
	toolName   string // pre-computed: "mcp_<server>_<tool>"
}

// NewMCPTool creates a Tool adapter for the given discovered MCP tool.
func NewMCPTool(d *mcp.DiscoveredTool) *MCPTool {
	// Sanitise names: replace non-alphanumeric chars with underscore
	serverPart := sanitiseName(d.Server.Name())
	toolPart := sanitiseName(d.Def.Name)
	return &MCPTool{
		discovered: d,
		toolName:   fmt.Sprintf("mcp_%s_%s", serverPart, toolPart),
	}
}

func sanitiseName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

func (t *MCPTool) Name() string {
	return t.toolName
}

func (t *MCPTool) Description() string {
	return t.discovered.Def.Description
}

func (t *MCPTool) FunctionDefinition() *gollm.FunctionDefinition {
	return &gollm.FunctionDefinition{
		Name:        t.toolName,
		Description: t.discovered.Def.Description,
		Parameters:  convertSchema(t.discovered.Def.InputSchema),
	}
}

func (t *MCPTool) Run(ctx context.Context, args map[string]any) (any, error) {
	result, err := t.discovered.Server.CallTool(ctx, t.discovered.Def.Name, args)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (t *MCPTool) IsInteractive(_ map[string]any) (bool, error) {
	return false, nil
}

func (t *MCPTool) CheckModifiesResource(_ map[string]any) string {
	return "unknown"
}

// convertSchema converts a JSON-Schema map (as returned by MCP tools/list) into
// a *gollm.Schema. Unknown or missing type fields default to TypeObject.
func convertSchema(raw map[string]any) *gollm.Schema {
	if raw == nil {
		return &gollm.Schema{Type: gollm.TypeObject}
	}

	s := &gollm.Schema{}

	if t, ok := raw["type"].(string); ok {
		switch t {
		case "string":
			s.Type = gollm.TypeString
		case "boolean":
			s.Type = gollm.TypeBoolean
		case "number":
			s.Type = gollm.TypeNumber
		case "integer":
			s.Type = gollm.TypeInteger
		case "array":
			s.Type = gollm.TypeArray
		default:
			s.Type = gollm.TypeObject
		}
	} else {
		s.Type = gollm.TypeObject
	}

	if desc, ok := raw["description"].(string); ok {
		s.Description = desc
	}

	if props, ok := raw["properties"].(map[string]any); ok {
		s.Properties = make(map[string]*gollm.Schema, len(props))
		for k, v := range props {
			if propMap, ok := v.(map[string]any); ok {
				s.Properties[k] = convertSchema(propMap)
			}
		}
	}

	if items, ok := raw["items"].(map[string]any); ok {
		s.Items = convertSchema(items)
	}

	if req, ok := raw["required"].([]any); ok {
		for _, r := range req {
			if rs, ok := r.(string); ok {
				s.Required = append(s.Required, rs)
			}
		}
	}

	return s
}

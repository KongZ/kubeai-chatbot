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

package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"k8s.io/klog/v2"
)

// DiscoveredTool pairs an MCP server client with one of its tools.
type DiscoveredTool struct {
	Server *Client
	Def    ToolDef
}

// Manager connects to multiple MCP servers and aggregates their tools.
type Manager struct {
	servers   []*Client
	discovered []*DiscoveredTool
}

// NewManager parses serversEnv, connects to each MCP server, discovers tools,
// and returns a ready Manager.
//
// serversEnv format: "name1=http://localhost:8090,name2=http://localhost:8091"
// Servers that fail to connect are skipped with a warning (non-fatal).
func NewManager(ctx context.Context, serversEnv string) (*Manager, error) {
	configs, err := parseServersEnv(serversEnv)
	if err != nil {
		return nil, fmt.Errorf("parsing MCP_SERVERS: %w", err)
	}

	m := &Manager{}

	for _, cfg := range configs {
		client := NewClient(cfg.name, cfg.url)

		if err := client.Initialize(ctx); err != nil {
			klog.Warningf("MCP server %q (%s) failed to initialize: %v — skipping", cfg.name, cfg.url, err)
			continue
		}

		tools, err := client.ListTools(ctx)
		if err != nil {
			klog.Warningf("MCP server %q: failed to list tools: %v — skipping", cfg.name, err)
			continue
		}

		m.servers = append(m.servers, client)
		for i := range tools {
			m.discovered = append(m.discovered, &DiscoveredTool{
				Server: client,
				Def:    tools[i],
			})
		}

		klog.Infof("MCP server %q: connected, discovered %d tool(s)", cfg.name, len(tools))
	}

	return m, nil
}

// DiscoveredTools returns all tools discovered across all connected MCP servers.
func (m *Manager) DiscoveredTools() []*DiscoveredTool {
	return m.discovered
}

// MCPStatus builds an api.MCPStatus snapshot reflecting current connection state.
func (m *Manager) MCPStatus() *api.MCPStatus {
	status := &api.MCPStatus{
		ClientEnabled:  true,
		TotalServers:   len(m.servers),
		ConnectedCount: len(m.servers),
		TotalTools:     len(m.discovered),
	}

	for _, srv := range m.servers {
		info := api.ServerConnectionInfo{
			Name:        srv.Name(),
			IsConnected: true,
		}
		for _, dt := range m.discovered {
			if dt.Server == srv {
				info.AvailableTools = append(info.AvailableTools, api.MCPTool{
					Name:        dt.Def.Name,
					Description: dt.Def.Description,
					Server:      srv.Name(),
				})
			}
		}
		status.ServerInfoList = append(status.ServerInfoList, info)
	}

	return status
}

type serverConfig struct {
	name string
	url  string
}

// parseServersEnv parses "name1=url1,name2=url2" into a slice of serverConfig.
func parseServersEnv(env string) ([]serverConfig, error) {
	env = strings.TrimSpace(env)
	if env == "" {
		return nil, nil
	}

	var configs []serverConfig
	for _, entry := range strings.Split(env, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idx := strings.IndexByte(entry, '=')
		if idx <= 0 {
			return nil, fmt.Errorf("invalid entry %q: expected name=url format", entry)
		}
		name := strings.TrimSpace(entry[:idx])
		url := strings.TrimSpace(entry[idx+1:])
		if name == "" || url == "" {
			return nil, fmt.Errorf("invalid entry %q: name and url must not be empty", entry)
		}
		configs = append(configs, serverConfig{name: name, url: url})
	}

	return configs, nil
}

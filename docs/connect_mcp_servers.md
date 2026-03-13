# MCP Server Integration

KubeAI Chatbot supports [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers as sidecars in the same pod. MCP servers expose tools that the AI agent can call — extending the agent's capabilities beyond Kubernetes (e.g., querying metrics, creating tickets, searching documentation).

## How It Works

  1. Deploy one or more MCP servers as **sidecar containers** in the same pod using `additionalContainers`.
  2. Configure `MCP_SERVERS` so KubeAI knows where to reach each server (`name=http://localhost:<port>`).
  3. At startup, KubeAI connects to each MCP server, discovers its tools, and registers them alongside the built-in `kubectl` tool.
  4. The LLM sees MCP tools prefixed with `mcp_<serverName>_` and can call them naturally in response to user queries.

---

## Helm Configuration

### `additionalContainers`

Add sidecar containers to the pod using the `additionalContainers` value. Each entry is a full Kubernetes container spec.

```yaml
  additionalContainers:
    - name: my-mcp-server
      image: my-org/my-mcp-server:latest
      ports:
        - containerPort: 8090
      env:
        - name: SOME_VAR
          value: "some-value"
```

### `MCP_SERVERS` Environment Variable

Tell KubeAI which MCP servers to connect to at startup. The format is a comma-separated list of `name=url` pairs:

```yaml
env:
  MCP_SERVERS: "fetcher=http://localhost:8090,slack=http://localhost:8091"
```

  - **`name`** — an identifier for the server; tool names will be prefixed `mcp_<name>_<tool>`
  - **`url`** — the base URL of the MCP server's HTTP endpoint (usually `http://localhost:<port>`)

If `MCP_SERVERS` is empty or unset, KubeAI starts normally without any MCP tools.

If a server is unreachable at startup, KubeAI logs a warning and continues — MCP is non-fatal.

---

## Example: Datadog MCP Server

The [Datadog MCP server](https://github.com/DataDog/datadog-mcp-server) exposes Datadog metrics, monitors, dashboards, and logs as MCP tools. Deploying it as a sidecar lets the agent answer questions like "show me CPU usage for the api-service pod over the last hour" by querying Datadog directly.

### `values.yaml`

```yaml
env:
  ## Kubernetes
  KUBECONFIG: "/etc/kubeconfig/config"
  MODIFY_RESOURCES: "none"

  ## LLM Provider
  LLM_PROVIDER: "gemini"
  MODEL_ID: "gemini-2.0-flash"

  ## MCP Servers
  ## Connect to the Datadog MCP server running as a sidecar on localhost:8080
  MCP_SERVERS: "datadog=http://localhost:8080"

additionalContainers:
  - name: datadog-mcp
    image: datadog/datadog-mcp-server:latest
    ports:
      - name: mcp
        containerPort: 8080
        protocol: TCP
    env:
      - name: DD_API_KEY
        valueFrom:
          secretKeyRef:
            name: datadog-credentials
            key: api-key
      - name: DD_APP_KEY
        valueFrom:
          secretKeyRef:
            name: datadog-credentials
            key: app-key
      - name: DD_SITE
        value: "datadoghq.com"
      - name: PORT
        value: "8080"
    resources:
      requests:
        cpu: "50m"
        memory: "64Mi"
      limits:
        cpu: "200m"
        memory: "256Mi"
```

### Create the Datadog credentials Secret

```bash
kubectl create secret generic datadog-credentials \
  --namespace kubeai \
  --from-literal=api-key=<YOUR_DD_API_KEY> \
  --from-literal=app-key=<YOUR_DD_APP_KEY>
```

### What the agent can do with Datadog tools

Once connected, the agent discovers Datadog tools prefixed with `mcp_datadog_`. Example interactions:

| User query                                                     | MCP tool called             |
| -------------------------------------------------------------- | --------------------------- |
| "Show CPU usage for the web deployment over the last hour"     | `mcp_datadog_query_metrics` |
| "Are there any triggered monitors for the production cluster?" | `mcp_datadog_list_monitors` |
| "Get recent error logs from the payment service"               | `mcp_datadog_query_logs`    |
| "Show the latency dashboard for the API"                       | `mcp_datadog_get_dashboard` |

---

## Multiple MCP Servers

You can connect to multiple MCP servers simultaneously:

```yaml
env:
  MCP_SERVERS: "datadog=http://localhost:8080,pagerduty=http://localhost:8081"

additionalContainers:
  - name: datadog-mcp
    image: datadog/datadog-mcp-server:latest
    ports:
      - containerPort: 8080
    env:
      - name: DD_API_KEY
        valueFrom:
          secretKeyRef:
            name: datadog-credentials
            key: api-key
      - name: DD_APP_KEY
        valueFrom:
          secretKeyRef:
            name: datadog-credentials
            key: app-key
      - name: PORT
        value: "8080"

  - name: pagerduty-mcp
    image: my-org/pagerduty-mcp-server:latest
    ports:
      - containerPort: 8081
    env:
      - name: PD_API_KEY
        valueFrom:
          secretKeyRef:
            name: pagerduty-credentials
            key: api-key
      - name: PORT
        value: "8081"
```

Tool names across servers are namespaced by server name, so there are no collisions:

  - `mcp_datadog_query_metrics`
  - `mcp_pagerduty_list_incidents`

---

## How the Agent Recognizes and Uses New Tools

When KubeAI starts, it calls `tools/list` on each MCP server. Each server returns a list of tool definitions in JSON Schema format. KubeAI registers these alongside the built-in `kubectl` tool and passes the full list to the LLM in every conversation.

### Tool discovery (what KubeAI receives from the server)

```json
{
  "tools": [
    {
      "name": "query_metrics",
      "description": "Query time-series metrics from Datadog using a DQL expression.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "query":     { "type": "string", "description": "Datadog metrics query (e.g. avg:system.cpu.user{*})" },
          "from_time": { "type": "string", "description": "Start of time range in ISO 8601 format" },
          "to_time":   { "type": "string", "description": "End of time range in ISO 8601 format" }
        },
        "required": ["query", "from_time", "to_time"]
      }
    }
  ]
}
```

KubeAI prefixes the tool name with `mcp_<serverName>_` before registering it, so this becomes `mcp_datadog_query_metrics`.

### What the LLM sees

The LLM receives all registered tools — built-in and MCP — as part of its system context. It reads each tool's `name` and `description` to understand what is available, then decides autonomously which tool to call based on the user's query.

### Example conversation

**User:** "What is the average CPU usage of the `payment-service` deployment over the last 30 minutes?"

**Agent reasoning (internal):**
The user is asking about metrics that are not available via `kubectl`. The `mcp_datadog_query_metrics` tool description says it can query time-series metrics from Datadog. The agent constructs a call:

```json
{
  "tool": "mcp_datadog_query_metrics",
  "input": {
    "query":     "avg:system.cpu.user{kube_deployment:payment-service}",
    "from_time": "2026-03-12T10:30:00Z",
    "to_time":   "2026-03-12T11:00:00Z"
  }
}
```

**MCP server response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "Average CPU: 0.42 cores (42%) over the requested window.\nPeak: 0.81 cores at 10:47 UTC."
    }
  ]
}
```

**Agent reply to user:**
> The `payment-service` deployment averaged **42% CPU** over the last 30 minutes, with a peak of **81%** at 10:47 UTC. This spike may be worth investigating — would you like me to check for any related Kubernetes events or triggered monitors?

### Key points

  - **No code changes required.** Adding a new MCP server automatically exposes its tools to the agent. The LLM learns what each tool does from its `description` and `inputSchema` — the more descriptive these are, the better the agent will use them.
  - **The agent combines tools.** The agent can call `kubectl` and MCP tools in the same conversation turn, correlating data from multiple sources before replying.
  - **Tool errors are surfaced naturally.** If a tool call fails, the error text is returned to the LLM, which will explain the problem to the user and may suggest alternatives.

---

## Implementing a Custom MCP Server

Any HTTP server that implements the [MCP Streamable HTTP transport](https://modelcontextprotocol.io/docs/concepts/transports#streamable-http) works as a sidecar. The server must handle:

| Method   | Endpoint              | Description                                        |
| -------- | --------------------- | -------------------------------------------------- |
| `POST /` | JSON-RPC `initialize` | Handshake — return server info and capabilities    |
| `POST /` | JSON-RPC `tools/list` | Return available tool definitions with JSON Schema |
| `POST /` | JSON-RPC `tools/call` | Execute a tool and return `content[].text` result  |

KubeAI connects to the URL specified in `MCP_SERVERS` and sends all JSON-RPC requests as `POST` to that URL.

---

## Troubleshooting

  **Tools not appearing:**

  - Check KubeAI logs at startup for `"Loaded N tools from MCP server <name>"` or warning messages.
  - Verify the MCP server container is running: `kubectl logs <pod> -c <mcp-container-name>`
  - Confirm the port in `MCP_SERVERS` matches the `containerPort` in `additionalContainers`.

  **MCP server crashes:**

  - MCP failures are non-fatal. KubeAI continues without MCP tools and logs a warning.
  - Fix the sidecar and restart the pod to reconnect.

  **Tool calls failing:**

  - MCP tool errors are returned to the agent as error text, which the LLM will surface to the user.
  - Check the MCP server's own logs for the underlying cause.

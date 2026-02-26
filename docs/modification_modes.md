# Modification Modes

KubeAI Chatbot supports three resource modification modes, controlled by the `MODIFY_RESOURCES` environment variable. The mode determines how the agent behaves when a task requires a `kubectl` command that creates, updates, or deletes Kubernetes resources.

> [!IMPORTANT]
> Regardless of the modification mode, the agent will **never** read or list Kubernetes Secrets. This restriction is hardcoded and cannot be overridden.

## Modes

### `none` — Read-Only (Default)

```yaml
env:
  MODIFY_RESOURCES: "none"
```

The agent operates in **read-only mode**. It can freely execute read commands (`get`, `describe`, `logs`, `top`, `events`, etc.) but will never execute a write command through its tools.

When a task requires a resource modification, the agent will:

  1. Gather the necessary context using read-only tools.
  2. Provide the exact `kubectl` command(s) the user should run manually.
  3. Explain what each command does and why.

**Best for**: Teams that want AI-assisted diagnostics and guidance without allowing the bot to change anything in the cluster.

---

### `allow` — Confirm Before Modifying

```yaml
env:
  MODIFY_RESOURCES: "allow"
```

The agent can execute write commands, but only after **explicit user confirmation**. When the agent plans a write operation, the system pauses and presents the user with a confirmation prompt listing the command(s) about to be run. The user must approve before anything is executed.

Read-only commands (`get`, `describe`, `logs`, etc.) run immediately without any confirmation.

**Best for**: Teams that want the convenience of automated execution but with a human-in-the-loop for any destructive or modifying actions.

---

### `auto` — Automatic Modification

```yaml
env:
  MODIFY_RESOURCES: "auto"
```

The agent can execute both read and write commands automatically, without requesting user confirmation. The agent will:

  1. Gather context first using read-only tools.
  2. Briefly announce what it is about to do and why.
  3. Execute the modification immediately.

The agent will still ask for user input when genuinely required (e.g., a required value such as a namespace or image tag is not specified).

**Best for**: Trusted internal tooling or teams with high confidence in the agent's behaviour who want to minimise confirmation prompts.

---

## Comparison

| Feature                             | `none`   |        `allow`         |  `auto`  |
| :---------------------------------- | :------: | :--------------------: | :------: |
| Read commands (get, describe, logs) | ✅ Auto  |        ✅ Auto         | ✅ Auto  |
| Write commands (apply, delete, …)   | ❌ Never | ✅ After user confirms | ✅ Auto  |
| Provides commands for manual run    | ✅ Yes   |           —            |     —    |
| User confirmation dialog            |    —     |         ✅ Yes         |  ❌ No   |
| Minimises user interaction          |    —     |           —            |  ✅ Yes  |
| Kubernetes Secrets access           | ❌ Never |        ❌ Never        | ❌ Never |

---

## Helm Values

Set the mode via `values.yaml`:

```yaml
env:
  MODIFY_RESOURCES: "none"  # Options: none, allow, auto
```

Or override at install time:

```bash
helm install kubeai-chatbot ./charts/kubeai-chatbot \
  --set env.SLACK_BOT_TOKEN="xoxb-..." \
  --set env.SLACK_SIGNING_SECRET="..." \
  --set env.GEMINI_API_KEY="..." \
  --set env.MODIFY_RESOURCES="allow"
```

---

## RBAC Alignment

The modification mode should be aligned with the Kubernetes RBAC permissions granted to the bot's service account. The Helm chart provides a `rbac.allowWrite` value to control this:

```yaml
rbac:
  create: true
  allowWrite: false  # Set to true when using allow or auto mode
```

| `MODIFY_RESOURCES` | Recommended `rbac.allowWrite` |
| :----------------- | :---------------------------: |
| `none`             |            `false`            |
| `allow`            |            `true`             |
| `auto`             |            `true`             |

> [!WARNING]
> Setting `MODIFY_RESOURCES: "allow"` or `"auto"` while `rbac.allowWrite: false` will result in permission errors when the agent attempts write operations. Conversely, granting write RBAC while using `MODIFY_RESOURCES: "none"` is safe but unnecessarily permissive.

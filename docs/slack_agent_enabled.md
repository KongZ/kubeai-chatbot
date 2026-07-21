# Slack Agent Mode (`SLACK_AGENT_ENABLED`, experimental)

Slack Agent Mode changes how KubeAI Chatbot shows its work in Slack. Instead of posting a separate
message for every command it runs, it renders the whole batch as a single, live-updating "plan"
card — using Slack's newer streaming task/plan API (`task_display_mode: "plan"`).

> [!WARNING]
> This feature is **experimental**. It depends on a Slack platform capability that rolled out
> through 2025-2026 and is not yet supported by the `slack-go/slack` Go client this project
> depends on — the integration talks to Slack's Web API directly over HTTPS instead. Expect rough
> edges, and check the prerequisite below before enabling it.

## Why you'd want this

When this is off (the default), a question that takes five `kubectl` commands to answer produces
five separate messages in the channel, back to back. That's harder to scan, and if one step fails
partway through, it's easy to miss.

With Agent Mode on, the same investigation shows up as one card with a checklist of steps:

  - **Less noise** — one message updates in place instead of a scrolling wall of separate posts.
  - **Easier to follow along** — anyone in the channel, technical or not, can glance at the card and
    see what the bot is doing and how far it's gotten, like a task list.
  - **Failures are visible, not silent** — a step that fails is marked with a short reason (e.g.
    `pod "x" not found`) instead of disappearing into a wall of text.

This only changes how tool calls are *displayed*. It doesn't change what the agent does, how it
decides to run commands, or any of the write-confirmation behavior described in
[Modification Modes](modification_modes.md) — those work exactly the same whether this is on or
off.

## How to set up

### Prerequisites

Slack positions its **Agents** app feature as tied to paid plans (Pro, Business+, Enterprise), and
enabling that toggle is Slack's officially documented way to unlock `task_display_mode: "plan"`. In
practice, this integration has been confirmed working — the live-updating plan card, not the
fallback — on a **free-tier** workspace with the **Agents** toggle left **off**. Slack doesn't
document the exact access rules for this newer API, so treat a paid plan and the Agents toggle as
*not* a confirmed hard requirement rather than a strict gate.

The simplest path is: just enable `SLACK_AGENT_ENABLED` (below) and check the logs (see
[Verifying it's working](#verifying-its-working)). Only if you see the streaming call fail, try:

1. Enable the **Agents** feature: go to [api.slack.com/apps](https://api.slack.com/apps) → select
   the KubeAI app → find **Agents** in the left sidebar → enable it. This automatically adds the
   `assistant:write` OAuth scope to the app (in addition to the `chat:write` scope already in
   `docs/slack_app_manifest.yaml`).
2. **Reinstall the app to your workspace** afterwards (App Settings → Install App) — enabling the
   feature changes the app's OAuth scopes, and scope changes always require reinstalling to take
   effect, the same as any other new permission.
3. Confirm with a workspace admin that the app shows up as agent-enabled under
   **Admin → Apps and workflows → (select the app) → App Settings**, where an "AI agent
   experience" setting should appear and be set to Enabled.
4. If none of the above resolves it, the workspace's plan may genuinely be the blocker — Slack
   doesn't expose a read-only API to check this ahead of time.

### Enable it

```yaml
env:
  SLACK_AGENT_ENABLED: "true"
```

Or via Helm:

```bash
helm install kubeai-chatbot ./charts/kubeai-chatbot \
  --set env.SLACK_BOT_TOKEN="xoxb-..." \
  --set env.SLACK_SIGNING_SECRET="..." \
  --set env.SLACK_AGENT_ENABLED="true"
```

If `SLACK_AGENT_ENABLED` is on but the bot's Slack token check fails on startup (e.g. a bad token),
KubeAI Chatbot logs a warning and falls back to classic message-per-step rendering automatically —
it never fails to answer just because this feature can't start.

## What it looks like

  - Each task's title is drawn from the model's own explanation for that step (e.g. "I'll check the
    pod status and recent events") rather than the bare command, so the card reads like a plan, not
    a command log. If the model didn't explain that particular step, the title falls back to a
    short label like "kubectl logs image-reflector-controller-...". The title stays visible for the
    whole life of the task, including after it completes.
  - A task's output is a short status line, never the raw command output — `✅ Success (1.15s)` on
    success, or `❌ Failed (1.15s): <reason>` on failure. The reason is the most actionable detail
    available (e.g. `Error from server (NotFound): pods "x" not found`), never the full command
    output. This applies whether Agent Mode is on or off.
  - The command itself is shown once, in the task's details, and truncated if it's very long — it's
    never repeated or posted anywhere outside its own card.
  - Every task always reaches a finished state. If something interrupts the bot mid-batch (e.g. the
    session is torn down), any still-running task is marked as failed with an "interrupted" note
    rather than being left stuck showing "in progress" forever.

## Verifying it's working

Since there's no advance API check, the practical way to confirm everything is wired up:

1. Deploy with `SLACK_AGENT_ENABLED: "true"`.
2. Ask the bot a question that triggers at least one command.
3. Watch the bot's logs:
   - No `Failed to start Slack plan stream` / `Failed to append task_update` errors, and the
     commands appear in Slack as a single updating card → it's working.
   - A `Failed to start Slack plan stream: ... error: <code>` log line → the Agents feature isn't
     enabled for the app, the app wasn't reinstalled after enabling it, or the workspace plan
     doesn't support it. The bot still answers normally either way — it just falls back to posting
     each step as its own message (the pre-existing behavior).

## Limitations

  - If Slack does reject the streaming call for your workspace, there's no way for the bot to work
    around that on your behalf — see the troubleshooting steps under
    [Prerequisites](#prerequisites).
  - Calls Slack's Web API directly via `net/http` rather than through `slack-go/slack`, since that
    library doesn't yet have bindings for the streaming methods — if Slack changes this API, this
    integration may need updating ahead of a library upgrade.

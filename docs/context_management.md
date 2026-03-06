# Context Management (`LLM_MAX_HISTORY_ITEMS`)

## The problem

Every message in a conversation — user questions, model responses, and `kubectl` tool outputs — is kept in memory and sent to the LLM with every new request. In a long session, especially one that runs commands with large output (e.g. `kubectl logs`, `kubectl get ... -o yaml`, `kubectl describe`), the accumulated **token count** can exceed Gemini's 1,048,576-token context limit:

```log
Error 400: The input token count exceeds the maximum number of tokens allowed 1048576.
```

There are two independent ways a session can hit this limit:

  1. **Many exchanges** — many user questions over a long session accumulate history items
  2. **Large outputs in a single exchange** — a single investigation that runs many `kubectl logs` / `-o yaml` commands can exhaust the token budget within one question, regardless of how many prior exchanges there are

`LLM_MAX_HISTORY_ITEMS` directly addresses (1). It has limited effect on (2) — see [Token size vs. item count](#token-size-vs-item-count) below.

## How `LLM_MAX_HISTORY_ITEMS` works

Setting `LLM_MAX_HISTORY_ITEMS` to a positive integer caps the number of history entries that are included in each API request. Older entries are dropped from the **front** of the history (oldest first) to stay within the configured limit.

### History item accounting

Each autonomous tool call by the model adds **2 history items**: one for the model's function-call request and one for the tool result sent back. For a user question that triggers N sequential tool calls:

```shell
Items = 2  (user question + first model response)
      + N × 2  (each tool-call request + its result)
      + 2  (final tool results + model's concluding answer)
      = 4 + 2N
```

| Scenario                             | Tool calls | History items |
| ------------------------------------ | ---------- | ------------- |
| Simple Q&A (no tools)                | 0          | 2             |
| Single command (`kubectl get pods`)  | 1          | 6             |
| Short investigation (3 commands)     | 3          | 10            |
| Moderate investigation (10 commands) | 10         | 24            |
| Deep investigation (26 commands)     | 26         | 54            |

A real-world diagnosis session that compared two clusters — running `kubectl get deployments`, `kubectl logs`, `kubectl describe canary`, `kubectl get deployment -o yaml`, and `kubectl get events` across both clusters (26 commands total) — produced **54 history items** and hit the token limit even with `LLM_MAX_HISTORY_ITEMS=100`.

### Token size vs. item count

`LLM_MAX_HISTORY_ITEMS` counts history entries, not tokens. A single investigation can hit the token limit while staying well under the item cap:

| Command type              | Typical token count |
| ------------------------- | ------------------- |
| `kubectl get pods`        | ~500–2,000          |
| `kubectl get events`      | ~1,000–5,000        |
| `kubectl describe`        | ~2,000–8,000        |
| `kubectl get ... -o yaml` | ~3,000–15,000       |
| `kubectl logs` (busy pod) | ~10,000–50,000+     |

For the 26-command investigation above:

  - 7 × `kubectl logs`: up to ~350,000 tokens
  - 2 × `kubectl get deployment -o yaml`: ~10,000–20,000 tokens
  - Other commands: ~20,000–40,000 tokens
  - **Total tool output alone: ~380,000–410,000+ tokens** — plus model reasoning, system prompt, and prior history

Even with `LLM_MAX_HISTORY_ITEMS=100`, the session produced only 54 items (well below the cap), so no trimming occurred, and the token budget was exhausted by output size.

### Trimming behavior

When the history length exceeds `LLM_MAX_HISTORY_ITEMS` before a request:

  1. The oldest **pairs** of entries (tool-call request + result) are removed first, so the alternating user/model sequence is always preserved.
  2. The bot notifies the user and continues automatically:
    > *Note: Some earlier conversation history has been truncated to stay within the model's context limit. Older context may not be available.*

### Automatic recovery from context-length errors

Even without `LLM_MAX_HISTORY_ITEMS` set, the bot automatically recovers if the model returns a context-length error at request time:

  1. The failed request (user message and any partial model response) is rolled back from history.
  2. The oldest **half** of the remaining history is dropped (pairs are removed together to keep user/model alternation intact).
  3. The same user message is retried automatically — no user action is needed.
  4. The bot notifies the user that older messages were dropped:
    > *Note: The conversation history was too long. Older messages have been dropped so the conversation can continue.*
  5. If the history is already too short to trim further (≤ 2 entries), or if the **current exchange alone** exceeds the token limit (e.g. a single investigation with enormous log outputs), recovery gives up and the bot shows a terminal error:
    > *The conversation is too long to continue. You can start a new conversation, or type `clear` to reset this thread.*

> **Note:** Auto-recovery can only drop **prior** history. If a single user question generates enough large tool outputs to exhaust the token budget on its own, no amount of history trimming will resolve it. In this case, start a fresh session (`clear`) and use more targeted commands (e.g. `--tail=100` to limit log output, or fetch specific fields rather than `-o yaml`).

## Sizing guide

| `LLM_MAX_HISTORY_ITEMS` | Q&A-only exchanges | Q + 1 tool call | Q + 10 tool calls              | Q + 26 tool calls |
| ----------------------- | ------------------ | --------------- | ------------------------------ | ----------------- |
| `10`                    | ~5                 | ~1              | <1 (trimmed mid-investigation) | <1                |
| `20`                    | ~10                | ~3              | ~1                             | <1                |
| `50`                    | ~25                | ~8              | ~2                             | ~1                |
| `100`                   | ~50                | ~16             | ~4                             | ~2                |
| `0` (default)           | unlimited          | unlimited       | unlimited                      | unlimited         |

**Recommendation:**

| Usage pattern                                              | Recommended value |
| ---------------------------------------------------------- | ----------------- |
| Mainly Q&A, simple commands                                | `50`              |
| Regular investigations (up to ~10 tool calls per question) | `20–30`           |
| Deep investigations (10+ tool calls, logs, yaml)           | `10–20`           |

For deep investigations, a **lower** cap is more useful: it aggressively drops earlier exchanges, leaving more token budget for the current (large) investigation. However, if a single question generates so many large outputs that it hits the limit by itself, the item cap cannot help — the auto-recovery mechanism and starting a more targeted session are the only remedies.

For very output-heavy commands, consider limiting output size at the command level:

  - `kubectl logs --tail=100` instead of full log output
  - `kubectl get ... -o jsonpath=...` to fetch specific fields instead of full YAML

## Example: what gets trimmed

Suppose `LLM_MAX_HISTORY_ITEMS=20` and the agent runs 8 sequential tool calls for a user question (20 history items). When the next question arrives:

```log
History before trim (20 items from prior exchange):
  [ 0] user:    "Why is the canary failing?"
  [ 1] model:   (calls kubectl get canary -o yaml)
  [ 2] user:    (tool result: canary yaml)
  [ 3] model:   (calls kubectl get events)
  [ 4] user:    (tool result: events)
  [ 5] model:   (calls kubectl logs flagger)
  [ 6] user:    (tool result: flagger logs)
  [ 7] model:   (calls kubectl describe canary)
  [ 8] user:    (tool result: describe output)
  [ 9] model:   (calls kubectl get pods)
  [10] user:    (tool result: pods)
  [11] model:   (calls kubectl get deployment -o yaml)
  [12] user:    (tool result: yaml)
  [13] model:   (calls kubectl get events -n apm-gateway)
  [14] user:    (tool result: events)
  [15] model:   (calls kubectl top pods)
  [16] user:    (tool result: top)
  [17] model:   "Analysis: the canary is stuck because..."
  [18] user:    "Follow up question"     ← new question about to be sent
  ...

trimHistory() drops items [0]–[3] (oldest 2 pairs) to stay under 20.
```

The LLM loses the initial question and first tool exchange but retains the most recent context.

## Configuration

**Environment variable:**

```shell
LLM_MAX_HISTORY_ITEMS=20
```

**Helm (`values.yaml`):**

```yaml
env:
  LLM_MAX_HISTORY_ITEMS: "20"
```

**Note:** This setting currently applies to the **Gemini** and **Vertex AI** providers only. Other providers (`openai`, `bedrock`, etc.) manage their own context windows and are not affected.

## MaxIterations

The agent also has a `MaxIterations` limit (default: **20 agentic loop iterations**) that caps the total number of back-and-forth rounds between the model and tools. This is a separate control:

  - Each round can include **multiple tool calls** in a single model response (the model can request many tools at once), so 26 tool calls might complete in as few as 2–3 iterations.
  - `MaxIterations` prevents runaway loops but does not directly limit the token count from tool outputs.

# Context Management (`LLM_MAX_HISTORY_ITEMS`)

## The problem

Every message in a conversation — user questions, model responses, and `kubectl` tool outputs — is kept in memory and sent to the LLM with every new request. In a long session, especially one that runs commands with large output (e.g. `kubectl get pods -A`, `kubectl logs`, `kubectl describe`), the accumulated token count can exceed Gemini's 1,048,576-token context limit:

```log
Error 400: The input token count exceeds the maximum number of tokens allowed 1048576.
```

## How `LLM_MAX_HISTORY_ITEMS` works

Setting `LLM_MAX_HISTORY_ITEMS` to a positive integer caps the number of history entries that are included in each API request. Older entries are dropped from the **front** of the history (oldest first) to stay within the configured limit.

### History item accounting

Each interaction adds items to the conversation history in the following pattern:

| Event                         | History items added | Running total |
| ----------------------------- | ------------------- | ------------- |
| User asks a question          | 1                   | 1             |
| Model answers (no tools)      | 1                   | 2             |
| Model calls a tool            | 1                   | 3             |
| Tool result returned to model | 1                   | 4             |
| Model calls a second tool     | 1                   | 5             |
| Second tool result returned   | 1                   | 6             |
| Model gives final answer      | 1                   | 7             |

In practice:

  - **Simple Q&A** (no tools): **2 items** per exchange
  - **Question + 1 `kubectl` call**: **4 items** per exchange
  - **Question + 3 `kubectl` calls** (typical deep investigation): **8 items** per exchange

### Trimming behavior

When the history length exceeds `LLM_MAX_HISTORY_ITEMS` before a request:

  1. The oldest **pairs** of entries (user + model) are removed first, so the alternating user/model sequence is always preserved.
  2. The bot sends a Slack notification to the user:
    > *Note: Some earlier conversation history has been truncated to stay within the model's context limit. Older context may not be available.*
  3. If the history is still too large even after trimming (e.g. a single message is enormous), the bot tells the user:
    > *The conversation history is too large to process, even after truncating older messages. Please start a new session by typing `clear`.*

## Sizing guide

| `LLM_MAX_HISTORY_ITEMS` | Simple Q&A exchanges | Q + 1 tool call | Q + 3 tool calls (complex) |
| ----------------------- | -------------------- | --------------- | -------------------------- |
| `20`                    | ~10                  | ~5              | ~2                         |
| `50`                    | ~25                  | ~12             | ~6                         |
| `100`                   | ~50                  | ~25             | ~12                        |
| `0` (default)           | unlimited            | unlimited       | unlimited                  |

**Recommendation: start with `50`.**

This covers roughly 12 questions that each trigger a single `kubectl` call — enough for a typical investigation session — while staying comfortably below the context limit even when commands return verbose output like `kubectl describe` or `kubectl logs`.

If your users frequently run long, multi-step investigations (e.g. diagnosing a failing deployment by inspecting pods, events, and logs in one session), raise the value to `100` and monitor for token limit errors. If they hit the limit even with `100`, ask users to type `clear` to start a fresh session.

## Example: what gets trimmed

Suppose `LLM_MAX_HISTORY_ITEMS=10` and a user has had 3 full exchanges (each with one tool call = 4 items = 12 items total). When the 4th question arrives:

```log
History before trim (12 items):
  [0] user:  "Why is my pod crashing?"           ← oldest, trimmed
  [1] model: (calls kubectl describe pod)        ← oldest, trimmed
  [2] user:  (tool result: describe output)      ← trimmed
  [3] model: "Your pod is OOMKilled"             ← trimmed
  [4] user:  "How do I fix it?"
  [5] model: (calls kubectl get limitrange)
  [6] user:  (tool result: limitrange output)
  [7] model: "Increase the memory limit"
  [8] user:  "Can you apply the fix?"
  [9] model: (calls kubectl patch deployment)
 [10] user:  (tool result: patched)
 [11] model: "Done, deployment updated"

History after trim (10 items, oldest 2 pairs removed):
  [4]–[11] are kept; [0]–[3] are dropped.
```

The LLM loses the very first exchange but retains the most recent context needed to continue the conversation.

## Configuration

**Environment variable:**

```shell
LLM_MAX_HISTORY_ITEMS=50
```

**Helm (`values.yaml`):**

```yaml
env:
  LLM_MAX_HISTORY_ITEMS: "50"
```

**Note:** This setting currently applies to the **Gemini** and **Vertex AI** providers only. Other providers (`openai`, `bedrock`, etc.) manage their own context windows and are not affected.

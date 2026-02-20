# System Architecture

KubeAI Chatbot is designed as a standalone Go application that bridges Slack conversations with Kubernetes cluster management using Large Language Models (LLMs).

## Component Overview

The following diagram illustrates the high-level components and their interactions:

```mermaid
graph TD
  User([Slack User])
  Slack[Slack API / Workspace]
  App[KubeAI Chatbot App]
  LLM[LLM Provider - Gemini/OpenAI]
  K8s[Kubernetes Cluster]

  User <--> Slack
  Slack <--> App
  App <--> LLM
  App <--> K8s
```

## Internal Architecture

The application is organized into several key modules:

```mermaid
graph TB
  subgraph "KubeAI Chatbot Application"
    UI[Slack UI Module]
    Mgr[Agent Manager]
    Agent[Agent Session Loop]
    Tools[Tool Executor]
    Store[(Session Store)]
  end

  UI <--> Mgr
  Mgr <--> Agent
  Agent <--> Tools
  Agent <--> Store

  UI -- "Events/Messages" --> Slack
  Agent <--> LLM
  Tools <--> K8s
```

### Core Modules

1. **Slack UI (`pkg/ui/slack`)**:
  * Handles incoming Slack events (mentions, messages).
  * Manages event de-duplication and immediate acknowledgment.
  * Transforms Markdown responses into Slack-native **Blocks** (including native TableBlocks).
  * Handles long responses by uploading snippets.

2. **Agent Manager (`pkg/agent`)**:
  * Orchestrates the lifecycle of AI Agents.
  * Maps Slack channels and thread timestamps to persistent session IDs.
  * Ensures clean startup and shutdown of agent loops.
  * Maintains the state machine for a single conversation.
  * Interacts with the LLM to process queries and determine tool usage.
  * Enforces safety rules (e.g., preventing secret retrieval or unauthorized modifications).

3. **Tool Executor (`pkg/tools`)**:
  * Wrapper around `kubectl` and other potential utilities.
  * Validates commands before execution for security and correctness.

4. **Session Store (`pkg/sessions`)**:
  * Provides persistence for session metadata using the local filesystem or memory.

5. **Journal (`pkg/journal`)**:
  * Provides journaling for chat history using the local filesystem or standard output.

## Request Flow

When a user mentions the bot in Slack, the following sequence occurs:

```mermaid
sequenceDiagram
  participant U as Slack User
  participant S as Slack API
  participant UI as Slack UI
  participant Ag as KubeAI Chatbot
  participant L as LLM (Gemini)
  participant K as Kubernetes

  U->>S: @KubeAI Get my pods
  S->>UI: POST /slack/events
  UI-->>S: 200 OK (Immediate Ack)

  rect rgb(240, 240, 240)
  Note over UI,Ag: Background Processing
  UI->>Ag: Process Query
  Ag->>L: Context + Query
  L-->>Ag: I need to run 'kubectl get pods'
  Ag->>Ag: Confirm with security constraints
  Ag->>K: Execute 'kubectl get pods'
  K-->>Ag: Pod list data
  Ag->>L: Execution Result
  L-->>Ag: Here are your pods
  Ag->>UI: Final Response
  UI->>S: Post Message
  S->>U: Display Response
  end
```

# Session Storage in KubeAI Chatbot

The KubeAI Chatbot maintains user session state to enable context-aware, multi-turn conversations and to track Agent status. This document describes what data is stored during a session, the different storage backends available, and when and how to configure them.

## What Data is Stored in a Session?

A Session object (`api.Session`) tracks the following core information:

  - **ID & Name**: Unique identifier for the session and a human-readable name.
  - **ProviderID & ModelID**: The AI models and providers used for this session (e.g., Gemini, OpenAI).
  - **SlackUserID**: The Slack user to whom the session belongs.
  - **Messages**: The complete history of the chat, containing `user`, `agent`, or `model` messages (`api.Message` records).
  - **AgentState**: The current status of the AI agent handling the session (e.g., `idle`, `waiting-for-input`, `running`, `done`).
  - **MCPStatus**: Context regarding connected Model Context Protocol (MCP) servers and tools.
  - **UserIdentity**: The authenticated user's identity information, including K8s roles and groups, used for impersonation and RBAC when executing actions.
  - **Timestamps**: `CreatedAt` and `LastModified` time.

## Session Storage Types and Setup

The platform supports three distinct session storage types, each fulfilling different use cases and scaling requirements. Storage backends are configured in the Helm chart (`values.yaml`) via the `env` section, utilizing the `SESSION_TYPE` and `DATABASE_URL` environment variables.

### 1. Memory (`memory`)

An entirely in-memory data store.

  - **Characteristics**: Fast, no external dependencies, entirely volatile.
  - **When to Use**: Local testing, active development, or CI/CD testing where persistence between restarts is strictly not required. If the chatbot container restarts, all session history is immediately lost.
  - **Setup**:

    ```yaml
    env:
      SESSION_TYPE: "memory"
    ```

### 2. Filesystem (`filesystem`)

Stores sessions locally as files on the container's disk (specifically under `~/.kubeai/sessions/`).

  - **Characteristics**: Simple persistent storage. Survives application crashes if backed by a persistent volume, but is not concurrent-safe across multiple replicas.
  - **When to Use**: Small, single-replica Kubernetes deployments or Docker standalone setups. Perfect when you need memory persistence but don't want the operational overhead of running a full Postgres database.
  - **Setup**:

    ```yaml
    env:
      SESSION_TYPE: "filesystem"
    ```

  **Note on Kubernetes:** Because the filesystem backend writes to `~/.kubeai/sessions/`, you must mount a Kubernetes `PersistentVolumeClaim` (PVC) to the home directory or `/home/kubeai/.kubeai/sessions` (depending on the container's user) if you want the data to survive pod recreation and node migrations.

### 3. Postgres (`postgres`)

A robust, relational database backend storing sessions in PostgreSQL.

  - **Characteristics**: Highly available, persistent, safely handles concurrent read/writes.
  - **When to Use**: Production deployments, High Availability (HA) setups with `replicaCount > 1`, or multi-cluster environments. If you want true scalability and reliability, you must use Postgres.
  - **Setup**:

    To use the PostgreSQL backend, specify `postgres` as the session type and provide a connection string using the `DATABASE_URL` variable:

    ```yaml
    env:
      SESSION_TYPE: "postgres"
      DATABASE_URL: "postgres://username:password@postgres-host:5432/kubeaidb?sslmode=disable"
    ```

  In production, you should inject the `DATABASE_URL` securely via Kubernetes Secrets or use [piggy](https://github.com/KongZ/piggy) if you are using AWS Secret Manager instead of writing it directly in plain text in the `values.yaml` file.

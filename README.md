# KubeAI Chatbot

A powerful Slack chatbot for Kubernetes cluster management, powered by AI. It allows you to interact with your clusters using natural language, execute commands, and explore resources through a conversational interface.

![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-Apache%202.0-D22128?style=flat)
![Platform](https://img.shields.io/badge/Platform-Slack-4A154B?style=flat&logo=slack)

## ✨ Features

- **Natural Language K8s**: Manage your clusters by simply chatting in Slack.
- **AI-Powered Command Generation**: Automatically generates and executes `kubectl` commands based on your requests.
- **Slack Native UI**:
    - **Built for Slack**: Converts conversations into Slack's built-in style.
    - **Tool Visibility**: Automatically wraps command descriptions in code blocks for clarity.
    - **Snippet Support**: Automatically uploads long responses as text snippets to keep channels clean.
- **Enterprise Safety Controls**:
    - **Zero-Trust Secrets**: Strict, hard-coded blocking of any attempts to retrieve or list Kubernetes secrets.
    - **Modification Guard**: Prevent accidental resource modifications with the `AUTOMATIC_MODIFY_RESOURCES` safety switch.
- **Multi-Cloud Ready**: Support for GKE (with auth plugin), EKS, and standard clusters.

## 🚀 Quick Start

### 1. Prerequisites
- **Go 1.24** or later.
- **Kubernetes Cluster** with valid `kubeconfig`.
- **Slack App** configured with `app_mention` and `message.channels` event subscriptions.

### 2. Slack App Configuration
The easiest way to set up your Slack app is using the provided manifest:
1. Go to [api.slack.com/apps](https://api.slack.com/apps).
2. Create a new app **From a manifest**.
3. Copy the contents of [`docs/slack_app_manifest.yaml`](docs/slack_app_manifest.yaml) and paste it into the editor.
4. Update the `request_url` to your hosted environment's `/slack/events` endpoint.

### 3. Installation

#### Using Helm (Recommended)
```bash
helm install kubeai-chatbot ./charts/kubeai-chartbot \
  --set env.SLACK_BOT_TOKEN="xoxb-..." \
  --set env.SLACK_SIGNING_SECRET="..." \
  --set env.GEMINI_API_KEY="..."
```

#### Running Locally
```bash
# Set credentials
export SLACK_BOT_TOKEN="xoxb-..."
export SLACK_SIGNING_SECRET="..."
export GEMINI_API_KEY="..."

# Build and Run
go build -o kubeai-chatbot ./cmd
./kubeai-chatbot
```

## ⚙️ Configuration

| Variable                     | Description                                       | Default                  |
| :--------------------------- | :------------------------------------------------ | :----------------------- |
| `SLACK_BOT_TOKEN`            | Slack Bot User OAuth Token                        | Required                 |
| `SLACK_SIGNING_SECRET`       | Slack app Signing Secret                          | Required                 |
| `GEMINI_API_KEY`             | Google AI API Key                                 | Required                 |
| `AUTOMATIC_MODIFY_RESOURCES` | Enable/Disable AI's ability to run write commands | `false`                  |
| `LLM_PROVIDER`               | LLM service provider (`gemini`, `openai`)         | `gemini`                 |
| `MODEL_ID`                   | Specific LLM model to use                         | `gemini-3-flash-preview` |
| `KUBECONFIG`                 | Path to your kubeconfig file                      | `$HOME/.kube/config`     |
| `LISTEN_ADDRESS`             | Address for the bot to listen on                  | `0.0.0.0:8888`           |

## 🛡️ Safety & Security

KubeAI Chatbot is built with safety as a priority:
- **Immutable Secrets**: The bot is hard-coded to refuse any request involving `kubectl secrets`. This prevention happens at both the LLM prompt level and the tool execution validator.
- **Confirmation Flow**: By default, `AUTOMATIC_MODIFY_RESOURCES` is set to `false`. The bot will generate resource-modifying commands but will not execute them, instead providing the command for you to run manually.

## 📜 Credits & Licensing

This project is a derivative work based on [kubectl-ai](https://github.com/GoogleCloudPlatform/kubectl-ai), originally developed by Google LLC.

- **Original Project**: [kubectl-ai](https://github.com/GoogleCloudPlatform/kubectl-ai)
- **License**: [Apache License 2.0](LICENSE)
- **Attribution**: See the [NOTICE](NOTICE) file for detailed derivative work modifications and attributions.

---
Copyright 2026 KongZ.

# kubeai-chatbot

A Slack chatbot for Kubernetes cluster management, powered by AI.

## Features

- Natural language interaction with Kubernetes clusters via Slack
- AI-powered command generation and execution
- Session management for threaded conversations
- Support for multiple LLM providers (Gemini, OpenAI, etc.)

## Prerequisites

- Go 1.21 or later
- Kubernetes cluster with kubeconfig
- Slack workspace with bot token and signing secret
- LLM API credentials (e.g., Google AI API key for Gemini)

## Configuration

Set the following environment variables:

```bash
# Required: Slack credentials
export SLACK_BOT_TOKEN="xoxb-your-bot-token"
export SLACK_SIGNING_SECRET="your-signing-secret"

# Required: LLM provider credentials (example for Gemini)
export GOOGLE_API_KEY="your-api-key"

# Optional: Configuration
export LLM_PROVIDER="gemini"              # Default: gemini
export MODEL_ID="gemini-2.0-flash-exp"    # Default: gemini-2.0-flash-exp
export LISTEN_ADDRESS="0.0.0.0:8888"      # Default: 0.0.0.0:8888
export KUBECONFIG="$HOME/.kube/config"    # Default: $HOME/.kube/config
export AGENT_NAME="kubeai"                # Default: kubeai
```

## Building

```bash
go build -o kubeai-chatbot ./cmd
```

## Running

```bash
./kubeai-chatbot
```

The bot will start listening on the configured address (default: `0.0.0.0:8888`). Configure your Slack app's Event Subscriptions to point to `http://your-server:8888/slack/events`.

## Slack App Setup

1. Create a new Slack app at https://api.slack.com/apps
2. Enable Event Subscriptions and set the Request URL to `http://your-server:8888/slack/events`
3. Subscribe to bot events: `app_mention`, `message.channels`
4. Install the app to your workspace
5. Copy the Bot User OAuth Token and Signing Secret to your environment variables

## Docker

Build the Docker image:

```bash
docker build -t kubeai-chatbot .
```

Run the container:

```bash
docker run -d \
  -e SLACK_BOT_TOKEN="xoxb-your-token" \
  -e SLACK_SIGNING_SECRET="your-secret" \
  -e GOOGLE_API_KEY="your-api-key" \
  -v $HOME/.kube/config:/root/.kube/config:ro \
  -p 8888:8888 \
  kubeai-chatbot
```

## Credits

This product includes software developed by Google Cloud Platform under the Apache License 2.0.

**Original Project**: [kubectl-ai](https://github.com/GoogleCloudPlatform/kubectl-ai)  
**Original Copyright**: Copyright 2024-2025 Google LLC  
**Original License**: Apache License 2.0

This project is a derivative work based on kubectl-ai. The original source code has been modified and adapted to create a Slack-focused Kubernetes chatbot. We are grateful to Google Cloud Platform and all contributors to kubectl-ai for their excellent work in creating the foundation for AI-powered Kubernetes interactions.

### Modifications

All modifications are documented in the NOTICE file.

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for the full license text.

This project maintains the original Apache License 2.0 from kubectl-ai. All original copyright notices and license headers have been preserved in the source files. See the [NOTICE](NOTICE) file for detailed attribution information.

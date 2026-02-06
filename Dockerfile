ARG GO_VERSION="1.24.3"
ARG AWS_CLI_VERSION="2.33.14"
ARG GCLOUD_CLI_VERSION="530.0.0"
ARG KUBECTL_VERSION="1.33.0"

# Build executable binary
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS builder
WORKDIR /src

# Declare ARGs inside the stage to make them available
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG COMMIT_HASH
ARG BUILD_DATE

# Construction of LDFLAGS - corrected variable names (commit, date)
ENV LDFLAGS="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT_HASH} -X main.date=${BUILD_DATE}"

COPY go.mod go.sum ./
COPY gollm/ ./gollm/
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -v -o kubeai-chatbot -ldflags="$LDFLAGS" ./cmd

# Runtime image with both AWS CLI and Google Cloud CLI
FROM debian:bookworm-slim AS runtime
ARG KUBECTL_VERSION
ARG GCLOUD_CLI_VERSION
ARG AWS_CLI_VERSION
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies, kubectl, Google Cloud CLI, and AWS CLI
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        gnupg \
        curl \
        unzip \
        python3 \
        python3-pip \
        groff \
        less && \
    mkdir -p /opt/tools/kubectl/bin/ && \
    curl -v -L "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /opt/tools/kubectl/bin/kubectl && \
    chmod +x /opt/tools/kubectl/bin/kubectl && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        google-cloud-cli=${GCLOUD_CLI_VERSION}-0 \
        google-cloud-cli-gke-gcloud-auth-plugin && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${AWS_CLI_VERSION}.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf aws awscliv2.zip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/kubeai-chatbot /bin/kubeai-chatbot
RUN ln -sf /opt/tools/kubectl/bin/kubectl /bin/kubectl

USER 1000
ENTRYPOINT [ "/bin/kubeai-chatbot" ]
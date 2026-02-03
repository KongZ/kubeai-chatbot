ARG GO_VERSION="1.24.3"
ARG GCLOUD_CLI_VERSION="530.0.0-stable"
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

# Install kubectl
FROM debian:bookworm-slim AS kubectl-tool
ARG KUBECTL_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    mkdir -p /opt/tools/kubectl/bin/ && \
    curl -v -L "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /opt/tools/kubectl/bin/kubectl && \
    chmod +x /opt/tools/kubectl/bin/kubectl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Allow to use kubectl in GKE
FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:${GCLOUD_CLI_VERSION} AS runtime
RUN apt-get update -y && \
    apt-get install -y apt-transport-https ca-certificates gnupg curl ca-certificates && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update -y && \
    apt-get install -y google-cloud-cli-gke-gcloud-auth-plugin && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/kubeai-chatbot /bin/kubeai-chatbot
COPY --from=kubectl-tool /opt/tools/kubectl/ /opt/tools/kubectl/
RUN ln -sf /opt/tools/kubectl/bin/kubectl /bin/kubectl

ENTRYPOINT [ "/bin/kubeai-chatbot" ]
###############################################################################
# Copyright 2025 The kubeai-chatbot authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###############################################################################
# Project variables
PACKAGE = github.com/KongZ/kubeai-chatbot
DOCKER_REGISTRY ?= ghcr.io/kongz
SLACK_KUBEAI_DOCKER_IMAGE = ${DOCKER_REGISTRY}/kubeai-chatbot

# Build variables
BUILD_ARCH ?= linux/amd64
VERSION = $(shell git describe --tags --always --dirty)
COMMIT_HASH = $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE = $(shell date +%FT%T%z)
LDFLAGS += -w -s -X main.version=${VERSION} -X main.commitHash=${COMMIT_HASH} -X main.buildDate=${BUILD_DATE}
export CGO_ENABLED ?= 0
export GOOS = $(shell go env GOOS)
# export GO111MODULE=off
ifeq (${VERBOSE}, 1)
	GOFLAGS += -v
endif

# Docker variables
ifeq ($(BUILD_ARCH), linux/amd64)
	DOCKER_TAG = ${VERSION}
else
	DOCKER_TAG = ${VERSION}-$(BUILD_ARCH)
endif

.PHONY: build
build: ## Build all binaries
	@echo "\033[0;31m\n🚜 Building kubeai-chatbot..."
	@go build ${GOFLAGS} -tags "${GOTAGS}" -ldflags "${LDFLAGS}" -o kubeai-chatbot ./cmd
	@echo "\033[0;32m\n🏃‍♂️ Running Go test..."
	@go test -race -cover -v -coverprofile=coverage.txt ./...
	@echo "\033[0;34m\n👨‍⚕️ Running Staticcheck..."
	@staticcheck -f stylish -fail -U1000 ./...
	@echo "\033[0;33m\n👮‍♀️ Running Gosec..."
	@gosec -exclude G104,G204,G301,G302,G304,G306,G402,G404 ./...
	@echo "\033[0m"

.PHONY: build-cli
build-cli: ## Build all cli binaries
	@echo "\033[0;31m\n🚜 Building kubeai-chatbot-cli (linux/amd64)..."
	@mkdir -p bin/linux/amd64
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/linux/amd64/kubeai-chatbot cmd/main.go
	@echo "\033[0;31m\n🚜 Building kubeai-chatbot-cli (windows/386)..."
	@mkdir -p bin/win/386
	@GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o bin/win/386/kubeai-chatbot.exe cmd/main.go
	@echo "\033[0;31m\n🚜 Building kubeai-chatbot-cli (darwin/amd64)..."
	@mkdir -p bin/darwin/amd64
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o bin/darwin/amd64/kubeai-chatbot cmd/main.go
	@echo "\033[0;31m\n🚜 Building kubeai-chatbot-cli (darwin/arm64)..."
	@mkdir -p bin/darwin/arm64
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o bin/darwin/arm64/kubeai-chatbot cmd/main.go
	@echo "\033[0m"

.PHONY: build-debug
build-debug: GOFLAGS += -gcflags "all=-N -l"
build-debug: build ## Build a binary with remote debugging capabilities

.PHONY: docker
docker: ## Build a kubeai-chatbot Docker image
	@echo "Building architecture ${BUILD_ARCH}"
	docker build -t ${CANARY_GATE_DOCKER_IMAGE}:${DOCKER_TAG} \
		--platform $(BUILD_ARCH) \
		--build-arg=VERSION=$(VERSION) \
		--build-arg=COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg=BUILD_DATE=$(BUILD_DATE) \
		-f Dockerfile .

.PHONY: docker-multi
docker-multi: BUILD_ARCH := $(strip $(BUILD_ARCH)),linux/arm64
docker-multi: ## Build a kubeai-chatbot Docker image in multi-architect
	@echo "Building architecture ${BUILD_ARCH}"
	nerdctl build -t ${CANARY_GATE_DOCKER_IMAGE}:${DOCKER_TAG} \
		--platform=$(BUILD_ARCH) \
		--build-arg=VERSION=$(VERSION) \
		--build-arg=COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg=BUILD_DATE=$(BUILD_DATE) \
		-f Dockerfile .

.PHONY: docker-multi-push
docker-multi-push: BUILD_ARCH := $(strip $(BUILD_ARCH)),linux/arm64
docker-multi-push: ## Build a kubeai-chatbot Docker image in multi-architect and push to registry
	@nerdctl login ghcr.io -u $(GH_NAME) -p $(CR_PAT)
	@echo "Building architecture ${BUILD_ARCH}"
	nerdctl build -t ${CANARY_GATE_DOCKER_IMAGE}:${DOCKER_TAG} \
		--platform=$(BUILD_ARCH) \
		--build-arg=VERSION=$(VERSION) \
		--build-arg=COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg=BUILD_DATE=$(BUILD_DATE) \
		-f Dockerfile .
	nerdctl push --all-platforms ${CANARY_GATE_DOCKER_IMAGE}:${DOCKER_TAG}

release-%: ## Release a new version
	git tag -m 'Release $*' $*

	@echo "Version updated to $*!"
	@echo
	@echo "To push the changes execute the following:"
	@echo
	@echo "git push; git push origin $*"

.PHONY: patch
patch: ## Release a new patch version
	@${MAKE} release-$(shell git describe --abbrev=0 --tags | awk -F'[ .]' '{print $$1"."$$2"."$$3+1}')

.PHONY: minor
minor: ## Release a new minor version
	@${MAKE} release-$(shell git describe --abbrev=0 --tags | awk -F'[ .]' '{print $$1"."$$2+1".0"}')

.PHONY: major
major: ## Release a new major version
	@${MAKE} release-$(shell git describe --abbrev=0 --tags | awk -F'[ .]' '{print $$1+1".0.0"}')

.PHONY: help
.DEFAULT_GOAL := help
help: # A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
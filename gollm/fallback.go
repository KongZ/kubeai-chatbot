package gollm

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	ollama "github.com/ollama/ollama/api"
	openai "github.com/openai/openai-go"
	"google.golang.org/genai"
	"k8s.io/klog/v2"
)

// modelSwitcher is implemented by provider chats that support model fallback.
type modelSwitcher interface {
	setModel(model string)
	snapshotHistory() any
	restoreHistory(snapshot any)
}

// fallbackClient accepts a comma-separated model list and falls back to the
// next model when the current one returns a quota (HTTP 429) error.
type fallbackClient struct {
	Client
}

func withModelFallback(c Client) Client {
	return &fallbackClient{Client: c}
}

// splitModels parses a comma-separated model list.
func splitModels(model string) []string {
	var models []string
	for _, m := range strings.Split(model, ",") {
		if m = strings.TrimSpace(m); m != "" {
			models = append(models, m)
		}
	}
	if len(models) == 0 {
		return []string{model}
	}
	return models
}

func (c *fallbackClient) StartChat(systemPrompt, model string) Chat {
	models := splitModels(model)
	inner := c.Client.StartChat(systemPrompt, models[0])
	if len(models) == 1 {
		return inner
	}
	sw, ok := inner.(modelSwitcher)
	if !ok {
		klog.Warningf("%T does not support model fallback, using %s only", inner, models[0])
		return inner
	}
	return &fallbackChat{Chat: inner, sw: sw, models: models}
}

func (c *fallbackClient) GenerateCompletion(ctx context.Context, req *CompletionRequest) (CompletionResponse, error) {
	models := splitModels(req.Model)
	var resp CompletionResponse
	var err error
	for i, model := range models {
		r := *req
		r.Model = model
		resp, err = c.Client.GenerateCompletion(ctx, &r)
		if err == nil || !isQuotaError(err) || i == len(models)-1 {
			break
		}
		klog.FromContext(ctx).Info("model quota exhausted, falling back", "from", model, "to", models[i+1])
	}
	return resp, err
}

// fallbackChat switches the underlying chat to the next model on a quota error
// and resends the same message. It stays on the new model for later sends.
type fallbackChat struct {
	Chat
	sw     modelSwitcher
	models []string
	idx    int
}

func (c *fallbackChat) next(ctx context.Context) bool {
	if c.idx+1 >= len(c.models) {
		return false
	}
	c.idx++
	klog.FromContext(ctx).Info("model quota exhausted, falling back", "from", c.models[c.idx-1], "to", c.models[c.idx])
	c.sw.setModel(c.models[c.idx])
	return true
}

func (c *fallbackChat) Send(ctx context.Context, contents ...any) (ChatResponse, error) {
	snap := c.sw.snapshotHistory()
	resp, err := c.Chat.Send(ctx, contents...)
	for err != nil && isQuotaError(err) && c.next(ctx) {
		c.sw.restoreHistory(snap)
		resp, err = c.Chat.Send(ctx, contents...)
	}
	return resp, err
}

func (c *fallbackChat) SendStreaming(ctx context.Context, contents ...any) (ChatResponseIterator, error) {
	snap := c.sw.snapshotHistory()
	start := func() (ChatResponseIterator, error) {
		for {
			stream, err := c.Chat.SendStreaming(ctx, contents...)
			if err == nil || !isQuotaError(err) || !c.next(ctx) {
				return stream, err
			}
			c.sw.restoreHistory(snap)
		}
	}
	stream, err := start()
	if err != nil {
		return nil, err
	}
	return func(yield func(ChatResponse, error) bool) {
		for {
			// Fall back only if nothing was yielded yet, so output never mixes models.
			yielded, fellBack := false, false
			for resp, err := range stream {
				if err != nil && !yielded && isQuotaError(err) && c.next(ctx) {
					fellBack = true
					break
				}
				yielded = true
				if !yield(resp, err) {
					return
				}
			}
			if !fellBack {
				return
			}
			c.sw.restoreHistory(snap)
			if stream, err = start(); err != nil {
				yield(nil, err)
				return
			}
		}
	}, nil
}

// isQuotaError reports whether err is an HTTP 429 from any supported provider SDK.
func isQuotaError(err error) bool {
	if err == nil {
		return false
	}
	var geminiErr genai.APIError
	if errors.As(err, &geminiErr) {
		return geminiErr.Code == http.StatusTooManyRequests
	}
	var openaiErr *openai.Error
	if errors.As(err, &openaiErr) {
		return openaiErr.StatusCode == http.StatusTooManyRequests
	}
	var azureErr *azcore.ResponseError
	if errors.As(err, &azureErr) {
		return azureErr.StatusCode == http.StatusTooManyRequests
	}
	var ollamaErr ollama.StatusError
	if errors.As(err, &ollamaErr) {
		return ollamaErr.StatusCode == http.StatusTooManyRequests
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests
	}
	// AWS SDK (Bedrock) errors expose the HTTP status this way.
	var awsErr interface{ HTTPStatusCode() int }
	if errors.As(err, &awsErr) {
		return awsErr.HTTPStatusCode() == http.StatusTooManyRequests
	}
	return false
}

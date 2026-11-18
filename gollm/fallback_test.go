package gollm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	ollama "github.com/ollama/ollama/api"
	openai "github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"google.golang.org/genai"
)

const quotaBody = `{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED"}}`

// fakeLLM serves 429 for models in exhausted and ok otherwise; it records the model of each call.
func fakeLLM(t *testing.T, modelOf func(*http.Request) string, ok func(http.ResponseWriter, *http.Request), exhausted ...string) (string, *[]string) {
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		model := modelOf(r)
		mu.Lock()
		calls = append(calls, model)
		mu.Unlock()
		for _, m := range exhausted {
			if m == model {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(quotaBody))
				return
			}
		}
		ok(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &calls
}

func fakeGemini(t *testing.T, exhausted ...string) (Client, *[]string) {
	const body = `{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}]}`
	url, calls := fakeLLM(t,
		func(r *http.Request) string {
			return strings.SplitN(r.URL.Path[strings.Index(r.URL.Path, "models/")+len("models/"):], ":", 2)[0]
		},
		func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "streamGenerateContent") {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: " + body + "\n\n"))
				return
			}
			_, _ = w.Write([]byte(body))
		}, exhausted...)
	client, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey: "test", Backend: genai.BackendGeminiAPI, HTTPOptions: genai.HTTPOptions{BaseURL: url},
	})
	if err != nil {
		t.Fatal(err)
	}
	return withModelFallback(&GoogleAIClient{client: client}), calls
}

func TestSplitModels(t *testing.T) {
	if got := splitModels(" a, b ,,c "); strings.Join(got, "|") != "a|b|c" {
		t.Fatalf("got %v", got)
	}
	if got := splitModels("single"); len(got) != 1 || got[0] != "single" {
		t.Fatalf("got %v", got)
	}
}

type awsLikeErr struct{ code int }

func (e awsLikeErr) Error() string       { return "aws" }
func (e awsLikeErr) HTTPStatusCode() int { return e.code }

func TestIsQuotaError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"gemini 429 wrapped", fmt.Errorf("x: %w", genai.APIError{Code: 429}), true},
		{"gemini 500", genai.APIError{Code: 500}, false},
		{"openai 429", &openai.Error{StatusCode: 429}, true},
		{"openai 400", &openai.Error{StatusCode: 400}, false},
		{"azure 429", &azcore.ResponseError{StatusCode: 429}, true},
		{"ollama 429", ollama.StatusError{StatusCode: 429}, true},
		{"gollm 429", &APIError{StatusCode: 429}, true},
		{"aws 429", fmt.Errorf("x: %w", awsLikeErr{429}), true},
		{"aws 400", awsLikeErr{400}, false},
		{"plain", fmt.Errorf("boom"), false},
	}
	for _, tc := range cases {
		if got := isQuotaError(tc.err); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestSingleModelIsNotWrapped(t *testing.T) {
	client, _ := fakeGemini(t)
	if _, ok := client.StartChat("sys", "a").(*fallbackChat); ok {
		t.Fatal("single model should not be wrapped")
	}
}

func TestGeminiSendFallsBack(t *testing.T) {
	client, calls := fakeGemini(t, "a")
	chat := client.StartChat("sys", "a,b")
	for _, q := range []string{"q1", "q2"} {
		if _, err := chat.Send(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	inner := chat.(*fallbackChat).Chat.(*GeminiChat)
	// Second send stays on b; failed attempt left no trace in history.
	if strings.Join(*calls, ",") != "a,b,b" || len(inner.history) != 4 {
		t.Fatalf("calls=%v history=%d", *calls, len(inner.history))
	}
}

func TestGeminiAllModelsExhausted(t *testing.T) {
	client, calls := fakeGemini(t, "a", "b")
	_, err := client.StartChat("sys", "a,b").Send(context.Background(), "q")
	if !isQuotaError(err) || strings.Join(*calls, ",") != "a,b" {
		t.Fatalf("err=%v calls=%v", err, *calls)
	}
}

func TestGeminiSendStreamingFallsBack(t *testing.T) {
	client, calls := fakeGemini(t, "a")
	chat := client.StartChat("sys", "a,b")
	stream, err := chat.SendStreaming(context.Background(), "q")
	if err != nil {
		t.Fatal(err)
	}
	var text string
	for resp, err := range stream {
		if err != nil {
			t.Fatal(err)
		}
		s, _ := resp.Candidates()[0].Parts()[0].AsText()
		text += s
	}
	inner := chat.(*fallbackChat).Chat.(*GeminiChat)
	if text != "hi" || strings.Join(*calls, ",") != "a,b" || len(inner.history) != 2 {
		t.Fatalf("text=%q calls=%v history=%d", text, *calls, len(inner.history))
	}
}

func TestOpenAISendFallsBack(t *testing.T) {
	url, calls := fakeLLM(t,
		func(r *http.Request) string {
			var body struct{ Model string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			return body.Model
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hi"}}]}`))
		}, "a")
	oc := openai.NewClient(option.WithBaseURL(url), option.WithAPIKey("test"), option.WithMaxRetries(0))
	client := withModelFallback(&OpenAIClient{client: oc})
	chat := client.StartChat("sys", "a,b")
	if _, err := chat.Send(context.Background(), "q"); err != nil {
		t.Fatal(err)
	}
	inner := chat.(*fallbackChat).Chat.(*openAIChatSession)
	// system + user + assistant
	if strings.Join(*calls, ",") != "a,b" || len(inner.history) != 3 {
		t.Fatalf("calls=%v history=%d", *calls, len(inner.history))
	}
}

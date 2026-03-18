// Copyright 2026 https://github.com/KongZ/kubeai-chatbot
// Portions Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KongZ/kubeai-chatbot/gollm"
	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/KongZ/kubeai-chatbot/pkg/journal"
	"github.com/KongZ/kubeai-chatbot/pkg/sessions"
	"github.com/KongZ/kubeai-chatbot/pkg/skills"
	"github.com/KongZ/kubeai-chatbot/pkg/tools"
	"github.com/google/uuid"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
)

//go:embed systemprompt_template_default.txt
var defaultSystemPromptTemplate string

// ModifyResourcesMode controls how the agent handles resource modifications.
type ModifyResourcesMode string

const (
	// ModifyResourcesModeNone disables all resource modification; the agent provides commands for the user to run manually.
	ModifyResourcesModeNone ModifyResourcesMode = "none"
	// ModifyResourcesModeAllow allows resource modification after explicit user confirmation.
	ModifyResourcesModeAllow ModifyResourcesMode = "allow"
	// ModifyResourcesModeAuto allows the agent to modify resources automatically without user confirmation.
	ModifyResourcesModeAuto ModifyResourcesMode = "auto"
)

type Agent struct {
	// Input is the channel to receive user input.
	Input chan any

	// Output is the channel to send messages to the UI.
	Output chan any

	// AgentName is the name of the assistant.
	AgentName string

	// ModifyResources controls how the agent handles resource modifications.
	// "none" = read-only, never execute writes; "allow" = execute writes after user confirms; "auto" = execute writes automatically.
	ModifyResources ModifyResourcesMode

	// tool calls that are pending execution
	// These will typically be all the tool calls suggested by the LLM in the
	// previous iteration of the agentic loop.
	pendingFunctionCalls []ToolCallAnalysis

	// currChatContent tracks chat content that needs to be sent
	// to the LLM in the current iteration of the agentic loop.
	currChatContent []any

	// currIteration tracks the current iteration of the agentic loop.
	currIteration int

	LLM gollm.Client

	// PromptTemplateFile allows specifying a custom template file
	PromptTemplateFile string
	// ExtraPromptPaths allows specifying additional prompt templates
	// to be combined with PromptTemplateFile
	ExtraPromptPaths []string
	Model            string
	Provider         string

	RemoveWorkDir bool

	MaxIterations int

	// Kubeconfig is the path to the kubeconfig file.
	Kubeconfig string

	SkipPermissions bool

	Tools tools.Tools

	EnableToolUseShim bool

	// Recorder captures events for diagnostics
	Recorder journal.Recorder

	llmChat gollm.Chat

	workDir string

	// Session optionally provides a session to use.
	// This is used by the UI to track the state of the agent and the conversation.
	Session *api.Session

	// protects session from concurrent access
	sessionMu sync.Mutex

	// cached list of available models
	availableModels []string

	// ChatMessageStore is the underlying session persistence layer.
	ChatMessageStore api.ChatMessageStore

	// SessionBackend is the configured backend for session persistence (e.g., memory, filesystem).
	SessionBackend string

	// sessionManager is a cached SessionManager instance, initialized once in Init.
	sessionManager *sessions.SessionManager

	// lastErr is the most recent error run into, for use across the stack
	lastErr error

	// EnvVars holds environment variables that should be passed to tools
	EnvVars map[string]string

	// SkillsRegistry holds the loaded skills for keyword matching and system prompt listing.
	SkillsRegistry *skills.Registry

	// cancel is the function to cancel the agent's context
	cancel context.CancelFunc
}

// Assert InMemoryChatStore implements ChatMessageStore
var _ api.ChatMessageStore = &sessions.InMemoryChatStore{}

// getSessionManager returns the cached session manager, lazily initializing it if needed.
func (c *Agent) getSessionManager() (*sessions.SessionManager, error) {
	if c.sessionManager == nil {
		sm, err := sessions.NewSessionManager(c.SessionBackend)
		if err != nil {
			return nil, fmt.Errorf("failed to create session manager: %w", err)
		}
		c.sessionManager = sm
	}
	return c.sessionManager, nil
}

func (s *Agent) GetSession() *api.Session {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	// Create a shallow copy of the session struct. The Messages slice header
	// is also copied, providing the caller with a snapshot of the messages
	// at this point in time. The UI should treat the messages as read-only
	// to avoid race conditions.
	sessionCopy := *s.Session
	return &sessionCopy
}

// addMessage creates a new message, adds it to the session, and sends it to the output channel
func (c *Agent) addMessage(source api.MessageSource, messageType api.MessageType, payload any) *api.Message {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	message := &api.Message{
		ID:        uuid.New().String(),
		Source:    source,
		Type:      messageType,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	// session should always have a ChatMessageStore at this point
	if err := c.Session.ChatMessageStore.AddChatMessage(message); err != nil {
		klog.Errorf("failed to add chat message to store: %v", err)
	}
	c.Session.LastModified = time.Now()
	c.Output <- message
	return message
}

// setAgentState updates the agent state and ensures LastModified is updated
func (c *Agent) setAgentState(newState api.AgentState) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	currentState := c.agentState()
	if currentState != newState {
		klog.Infof("Agent state changing from %s to %s", currentState, newState)
		c.Session.AgentState = newState
		c.Session.LastModified = time.Now()
	}
}

func (c *Agent) AgentState() api.AgentState {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	return c.agentState()
}

// agentState returns the agent state without locking.
// The caller is responsible for locking.
func (c *Agent) agentState() api.AgentState {
	return c.Session.AgentState
}

func (s *Agent) Init(ctx context.Context) error {
	log := klog.FromContext(ctx)

	s.Input = make(chan any, 10)
	s.Output = make(chan any, 10)
	s.currIteration = 0
	// when we support session, we will need to initialize this with the
	// current history of the conversation.
	s.currChatContent = []any{}

	if s.Session != nil {
		if s.Session.ChatMessageStore == nil {
			s.Session.ChatMessageStore = sessions.NewInMemoryChatStore()
		}
		s.ChatMessageStore = s.Session.ChatMessageStore
		if s.Session.ID == "" {
			s.Session.ID = uuid.New().String()
		}
		if s.Session.CreatedAt.IsZero() {
			s.Session.CreatedAt = time.Now()
		}
		if s.Session.LastModified.IsZero() {
			s.Session.LastModified = time.Now()
		}
		s.Session.Messages = s.Session.ChatMessageStore.ChatMessages()
	} else {
		return fmt.Errorf("agent requires a session to be provided")
	}

	// Initialize session manager for reuse across agent methods
	sessionMgr, err := sessions.NewSessionManager(s.SessionBackend)
	if err != nil {
		return fmt.Errorf("failed to create session manager: %w", err)
	}
	s.sessionManager = sessionMgr

	// Create a session working directory in the user's home directory
	// to avoid read-only filesystem issues in containers
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Error(err, "Failed to get user home directory")
		return err
	}
	workDir := filepath.Join(homeDir, sessions.KubeAIDirName, "agent")
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		log.Error(err, "Failed to create session working directory")
		return err
	}

	log.Info("Created agent working directory", "workDir", workDir)

	s.workDir = workDir

	// Register kubectl tool
	s.Tools.RegisterTool(tools.NewKubectlTool())

	kubeContexts, err := loadKubeContextNames(ctx, s.Kubeconfig)
	if err != nil {
		log.Error(err, "Could not load kube contexts for system prompt, proceeding without context list")
		kubeContexts = nil
	}

	var allSkills []skills.Skill
	if s.SkillsRegistry != nil {
		allSkills = s.SkillsRegistry.All()
	}

	systemPrompt, err := s.generatePrompt(ctx, defaultSystemPromptTemplate, PromptData{
		Tools:                s.Tools,
		EnableToolUseShim:    s.EnableToolUseShim,
		ModifyResources:      s.ModifyResources,
		SessionIsInteractive: true,
		AgentName:            s.AgentName,
		KubeContexts:         kubeContexts,
		Skills:               allSkills,
	})
	if err != nil {
		return fmt.Errorf("generating system prompt: %w", err)
	}

	// Start a new chat session
	s.llmChat = gollm.NewRetryChat(
		s.LLM.StartChat(systemPrompt, s.Model),
		gollm.RetryConfig{
			MaxAttempts:    3,
			InitialBackoff: 10 * time.Second,
			MaxBackoff:     60 * time.Second,
			BackoffFactor:  2,
			Jitter:         true,
		},
	)
	err = s.llmChat.Initialize(s.Session.ChatMessageStore.ChatMessages())
	if err != nil {
		return fmt.Errorf("initializing chat session: %w", err)
	}

	if !s.EnableToolUseShim {
		var functionDefinitions []*gollm.FunctionDefinition
		for _, tool := range s.Tools.AllTools() {
			functionDefinitions = append(functionDefinitions, tool.FunctionDefinition())
		}
		// Sort function definitions to help KV cache reuse
		sort.Slice(functionDefinitions, func(i, j int) bool {
			return functionDefinitions[i].Name < functionDefinitions[j].Name
		})
		if err := s.llmChat.SetFunctionDefinitions(functionDefinitions); err != nil {
			return fmt.Errorf("setting function definitions: %w", err)
		}
	}

	return nil
}

func (c *Agent) Close() error {
	if c.workDir != "" {
		if c.RemoveWorkDir {
			if err := os.RemoveAll(c.workDir); err != nil {
				klog.Warningf("error cleaning up directory %q: %v", c.workDir, err)
			}
		}
	}
	// Cancel the agent's context
	if c.cancel != nil {
		c.cancel()
	}
	// Close the LLM client
	if c.LLM != nil {
		if err := c.LLM.Close(); err != nil {
			klog.Warningf("error closing LLM client: %v", err)
		}
	}
	return nil
}

func (c *Agent) LastErr() error {
	return c.lastErr
}

func (c *Agent) Run(ctx context.Context, initialQuery string) error {
	log := klog.FromContext(ctx)

	if c.Recorder != nil {
		ctx = journal.ContextWithRecorder(ctx, c.Recorder)
	}
	if c.Session != nil && c.Session.SlackUserID != "" {
		ctx = journal.ContextWithSlackUserID(ctx, c.Session.SlackUserID)
	}

	log.Info("Starting agent loop", "initialQuery", initialQuery)
	go func() {
		if initialQuery != "" {
			c.addMessage(api.MessageSourceUser, api.MessageTypeText, initialQuery)
			answer, handled, err := c.handleMetaQuery(ctx, initialQuery)
			if err != nil {
				log.Error(err, "error handling meta query")
				c.setAgentState(api.AgentStateDone)
				c.pendingFunctionCalls = []ToolCallAnalysis{}
				c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "Error: "+err.Error())
			} else if handled {
				// initialQuery is the 'exit' or 'quit' metaquery
				if c.AgentState() == api.AgentStateExited {
					c.addMessage(api.MessageSourceAgent, api.MessageTypeText, answer)
					close(c.Output)
					return
				}
				// we handled the meta query, so we don't need to run the agentic loop
				c.setAgentState(api.AgentStateDone)
				c.pendingFunctionCalls = []ToolCallAnalysis{}
				c.addMessage(api.MessageSourceAgent, api.MessageTypeText, answer)
			} else {
				// Start the agentic loop with the initial query
				c.setAgentState(api.AgentStateRunning)
				c.currIteration = 0
				c.currChatContent = []any{c.buildQueryWithSkills(initialQuery)}
				c.pendingFunctionCalls = []ToolCallAnalysis{}
			}
		} else {
			if len(c.Session.Messages) == 0 {
				// Starting new session
				c.addMessage(api.MessageSourceAgent, api.MessageTypeText, "Hey there, what can I help you with today?")
			}
		}
		c.lastErr = nil
		for {
			var userInput any
			log.V(2).Info("Agent loop iteration", "state", c.AgentState())
			switch c.AgentState() {
			case api.AgentStateIdle, api.AgentStateDone:
				log.V(2).Info("initiating user input")
				c.addMessage(api.MessageSourceAgent, api.MessageTypeUserInputRequest, ">>>")
				select {
				case <-ctx.Done():
					log.V(2).Info("Agent loop done")
					return
				case userInput = <-c.Input:
					log.V(3).Info("Received input from channel", "userInput", userInput)
					if userInput == io.EOF {
						log.V(2).Info("Agent loop done, EOF received")
						c.setAgentState(api.AgentStateExited)
						c.addMessage(api.MessageSourceAgent, api.MessageTypeText, "It has been a pleasure assisting you. Have a great day!")
						return
					}
					query, ok := userInput.(*api.UserInputResponse)
					if !ok {
						log.Error(nil, "Received unexpected input from channel", "userInput", userInput)
						return
					}
					if strings.TrimSpace(query.Query) == "" {
						log.V(2).Info("No query provided, skipping agentic loop")
						continue
					}
					c.addMessage(api.MessageSourceUser, api.MessageTypeText, query.Query)
					answer, handled, err := c.handleMetaQuery(ctx, query.Query)
					if err != nil {
						log.Error(err, "error handling meta query")
						c.setAgentState(api.AgentStateDone)
						c.pendingFunctionCalls = []ToolCallAnalysis{}
						c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "Error: "+err.Error())
						continue
					}

					// Update c.EnvVars with the one from the input for this turn
					// This ensures thread safety as the loop processes one request at a time
					c.sessionMu.Lock()
					c.EnvVars = query.EnvVars
					c.sessionMu.Unlock()

					if handled {
						// metaquery set the state to 'Exited', so we should exit
						if c.AgentState() == api.AgentStateExited {
							c.addMessage(api.MessageSourceAgent, api.MessageTypeText, answer)
							close(c.Output)
							return
						}
						// we handled the meta query, so we don't need to run the agentic loop
						c.setAgentState(api.AgentStateDone)
						c.pendingFunctionCalls = []ToolCallAnalysis{}
						c.addMessage(api.MessageSourceAgent, api.MessageTypeText, answer)
						continue
					}

					c.setAgentState(api.AgentStateRunning)
					c.currIteration = 0
					c.currChatContent = []any{c.buildQueryWithSkills(query.Query)}
					c.pendingFunctionCalls = []ToolCallAnalysis{}
					log.Info("Set agent state to running, will process agentic loop", "currIteration", c.currIteration, "currChatContent", len(c.currChatContent))
				}
			case api.AgentStateWaitingForInput:
				select {
				case <-ctx.Done():
					log.V(2).Info("Agent loop done")
					return
				case userInput = <-c.Input:
					if userInput == io.EOF {
						log.V(2).Info("Agent loop done, EOF received")
						c.setAgentState(api.AgentStateExited)
						c.addMessage(api.MessageSourceAgent, api.MessageTypeText, "It has been a pleasure assisting you. Have a great day!")
						return
					}
					choiceResponse, ok := userInput.(*api.UserChoiceResponse)
					if !ok {
						log.Error(nil, "Received unexpected input from channel", "userInput", userInput)
						return
					}
					dispatchToolCalls := c.handleChoice(ctx, choiceResponse)
					if dispatchToolCalls {
						if err := c.DispatchToolCalls(ctx); err != nil {
							log.Error(err, "error dispatching tool calls")
							c.setAgentState(api.AgentStateDone)
							c.pendingFunctionCalls = []ToolCallAnalysis{}
							c.Session.LastModified = time.Now()
							c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "Error: "+err.Error())
							continue
						}
						// Clear pending function calls after execution
						c.pendingFunctionCalls = []ToolCallAnalysis{}
						c.setAgentState(api.AgentStateRunning)
						c.currIteration = c.currIteration + 1
					} else {
						// if user has declined, we are done with this iteration
						c.currIteration = c.currIteration + 1
						c.pendingFunctionCalls = []ToolCallAnalysis{}
						c.setAgentState(api.AgentStateRunning)
						c.Session.LastModified = time.Now()
					}
				}
			case api.AgentStateRunning:
				// Agent is running, don't wait for input, just continue to process the agentic loop
				log.V(2).Info("Agent is in running state, processing agentic loop")
			case api.AgentStateExited:
				log.V(2).Info("Agent exited")
				return
			}

			if c.AgentState() == api.AgentStateRunning {
				log.V(2).Info("Processing agentic loop", "currIteration", c.currIteration, "maxIterations", c.MaxIterations, "currChatContentLen", len(c.currChatContent))

				if c.currIteration >= c.MaxIterations {
					c.setAgentState(api.AgentStateDone)
					c.pendingFunctionCalls = []ToolCallAnalysis{}
					c.addMessage(api.MessageSourceAgent, api.MessageTypeText, "Maximum number of iterations reached. You can help me by providing more specific input. Or If you’d like me to continue with the previous attempt, let me know.")
					continue
				}

				// we run the agentic loop for one iteration
				// Save before clearing so we can restore for a retry after trimming.
				lastChatContent := c.currChatContent

				stream, err := c.llmChat.SendStreaming(ctx, c.currChatContent...)
				if err != nil {
					log.Error(err, "error sending streaming LLM response")
					c.setAgentState(api.AgentStateDone)
					c.pendingFunctionCalls = []ToolCallAnalysis{}
					c.lastErr = err
					continue
				}

				// Clear our "response" now that we sent the last response
				c.currChatContent = nil

				if c.EnableToolUseShim {
					// convert the candidate response into a gollm.ChatResponse
					stream, err = candidateToShimCandidate(stream)
					if err != nil {
						c.setAgentState(api.AgentStateDone)
						c.pendingFunctionCalls = []ToolCallAnalysis{}
						continue
					}
				}
				// Process each part of the response
				var functionCalls []gollm.FunctionCall

				// accumulator for streamed text
				var streamedText string
				var llmError error

				for response, err := range stream {
					if err != nil {
						log.Error(err, "error reading streaming LLM response")
						llmError = err
						c.setAgentState(api.AgentStateDone)
						c.pendingFunctionCalls = []ToolCallAnalysis{}
						c.lastErr = llmError
						break
					}
					if response == nil {
						// end of streaming response
						break
					}
					// klog.Infof("response: %+v", response)

					if len(response.Candidates()) == 0 {
						llmError = fmt.Errorf("no candidates in response")
						log.Error(nil, "No candidates in response")
						c.setAgentState(api.AgentStateDone)
						c.pendingFunctionCalls = []ToolCallAnalysis{}
						break
					}

					candidate := response.Candidates()[0]

					for _, part := range candidate.Parts() {
						// Check if it's a text response
						if text, ok := part.AsText(); ok {
							log.V(3).Info("text response", "text", text)
							streamedText += text
						}

						// Check if it's a function call
						if calls, ok := part.AsFunctionCalls(); ok && len(calls) > 0 {
							log.V(2).Info("function calls", "calls", calls)
							functionCalls = append(functionCalls, calls...)
						}
					}
				}
				if llmError != nil {
					log.Error(llmError, "error streaming LLM response")
					c.pendingFunctionCalls = []ToolCallAnalysis{}
					if isContextLengthExceededError(llmError) {
						// Try to recover by dropping the oldest half of the history and retrying.
						if c.llmChat.TrimHistory() {
							log.V(2).Info("context length exceeded, trimmed history and will retry")
							c.addMessage(api.MessageSourceAgent, api.MessageTypeText,
								"_Note: The conversation history was too long. Older messages have been dropped so the conversation can continue._")
							c.currChatContent = lastChatContent
							continue
						}
						// Cannot trim further — give up.
						c.setAgentState(api.AgentStateDone)
						c.addMessage(api.MessageSourceAgent, api.MessageTypeError,
							"The conversation is too long to continue. You can start a new conversation, or type `clear` to reset this thread.")
					} else {
						c.setAgentState(api.AgentStateDone)
						c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "Error: "+llmError.Error())
					}
					c.lastErr = llmError
					continue
				}

				// Notify the user if older history entries were dropped to stay within context limits.
				if c.llmChat.WasTruncated() {
					c.addMessage(api.MessageSourceAgent, api.MessageTypeText,
						"_Note: Some earlier conversation history has been truncated to stay within the model's context limit. Older context may not be available._")
				}

				log.V(2).Info("streamedText", "streamedText", streamedText)

				if streamedText != "" {
					msg := c.addMessage(api.MessageSourceModel, api.MessageTypeText, streamedText)
					// If no function calls to be made, this is the final message of the turn
					if len(functionCalls) == 0 {
						msg.SetMetadata("is_final", "true")
					}
				}
				// If no function calls to be made, we're done
				if len(functionCalls) == 0 {
					log.V(2).Info("No function calls to be made, so most likely the task is completed, so we're done.")
					c.setAgentState(api.AgentStateDone)
					c.currChatContent = []any{}
					c.currIteration = 0
					c.pendingFunctionCalls = []ToolCallAnalysis{}
					log.V(2).Info("Agent task completed, transitioning to done state")
					if streamedText == "" {
						// If no tool calls to be made and we do not have a response from the LLM
						// we should let the user know for better diagnostics.
						// IMPORTANT: This also prevents UIs from getting blocked on reading from the output channel.
						log.V(2).Info("Empty response with no tool calls from LLM.")
						msg := c.addMessage(api.MessageSourceAgent, api.MessageTypeText, "Empty response from LLM")
						msg.SetMetadata("is_final", "true")
					}
					continue
				}

				toolCallAnalysisResults, err := c.analyzeToolCalls(ctx, functionCalls)
				if err != nil {
					log.Error(err, "error analyzing tool calls")
					c.setAgentState(api.AgentStateDone)
					c.pendingFunctionCalls = []ToolCallAnalysis{}
					c.Session.LastModified = time.Now()
					c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "Error: "+err.Error())
					c.lastErr = err
					continue
				}

				// mark the tools for dispatching
				c.pendingFunctionCalls = toolCallAnalysisResults

				interactiveToolCallIndex := -1
				modifiesResourceToolCallIndex := -1
				for i, result := range toolCallAnalysisResults {
					if result.ModifiesResourceStr != "no" {
						modifiesResourceToolCallIndex = i
					}
					if result.IsInteractive {
						interactiveToolCallIndex = i
					}
				}

				if interactiveToolCallIndex >= 0 {
					// Show error block for both shim enabled and disabled modes
					errorMessage := fmt.Sprintf("  %s\n", toolCallAnalysisResults[interactiveToolCallIndex].IsInteractiveError.Error())
					c.addMessage(api.MessageSourceAgent, api.MessageTypeError, errorMessage)

					if c.EnableToolUseShim {
						// Add the error as an observation
						observation := fmt.Sprintf("Result of running %q:\n%v",
							toolCallAnalysisResults[interactiveToolCallIndex].FunctionCall.Name,
							toolCallAnalysisResults[interactiveToolCallIndex].IsInteractiveError.Error())
						c.currChatContent = append(c.currChatContent, observation)
					} else {
						// For models with tool-use support (shim disabled), use proper FunctionCallResult
						// Note: This assumes the model supports sending FunctionCallResult
						c.currChatContent = append(c.currChatContent, gollm.FunctionCallResult{
							ID:     toolCallAnalysisResults[interactiveToolCallIndex].FunctionCall.ID,
							Name:   toolCallAnalysisResults[interactiveToolCallIndex].FunctionCall.Name,
							Result: map[string]any{"error": toolCallAnalysisResults[interactiveToolCallIndex].IsInteractiveError.Error()},
						})
					}
					c.pendingFunctionCalls = []ToolCallAnalysis{} // reset pending function calls
					c.currIteration = c.currIteration + 1
					continue // Skip execution for interactive commands
				}

				if !c.SkipPermissions && c.ModifyResources != ModifyResourcesModeAuto && modifiesResourceToolCallIndex >= 0 {
					// In read-only mode, block the write and return an error
					if c.ModifyResources == ModifyResourcesModeNone {
						var commandDescriptions []string
						for _, call := range c.pendingFunctionCalls {
							commandDescriptions = append(commandDescriptions, call.ParsedToolCall.Description())
						}

						errorMessage := "Resource modification is disabled (read-only mode). The following commands were blocked:\n* " + strings.Join(commandDescriptions, "\n* ") + "\nProvide the exact `kubectl` command in your response for the user to execute manually instead of using this tool."

						log.Error(nil, "Tool call blocked", "reason", errorMessage, "commands", commandDescriptions)

						// Add the error message to the chat history so the model knows it was blocked
						if c.EnableToolUseShim {
							c.currChatContent = append(c.currChatContent, "Error: "+errorMessage)
						} else {
							for _, call := range c.pendingFunctionCalls {
								c.currChatContent = append(c.currChatContent, gollm.FunctionCallResult{
									ID:     call.FunctionCall.ID,
									Name:   call.FunctionCall.Name,
									Result: map[string]any{"error": errorMessage},
								})
							}
						}

						c.setAgentState(api.AgentStateRunning)
						c.addMessage(api.MessageSourceAgent, api.MessageTypeError, errorMessage)
						c.pendingFunctionCalls = []ToolCallAnalysis{}
						c.currIteration = c.currIteration + 1
						continue
					}

					var commandDescriptions []string
					for _, call := range c.pendingFunctionCalls {
						commandDescriptions = append(commandDescriptions, call.ParsedToolCall.Description())
					}
					confirmationPrompt := "The following commands require your approval to run:\n* " + strings.Join(commandDescriptions, "\n* ")
					confirmationPrompt += "\n\nDo you want to proceed ?"

					choiceRequest := &api.UserChoiceRequest{
						Prompt: confirmationPrompt,
						Options: []api.UserChoiceOption{
							{Value: "yes", Label: "Yes"},
							{Value: "yes_and_dont_ask_me_again", Label: "Yes, and don't ask me again"},
							{Value: "no", Label: "No"},
						},
					}
					c.setAgentState(api.AgentStateWaitingForInput)
					c.addMessage(api.MessageSourceAgent, api.MessageTypeUserChoiceRequest, choiceRequest)
					// Request input from the user by sending a message on the output channel.
					// Remaining part of the loop will be now resumed when we receive a choice input
					// from the user.
					continue
				}

				// we are here means we are in the clear to dispatch the tool calls
				if err := c.DispatchToolCalls(ctx); err != nil {
					log.Error(err, "error dispatching tool calls")
					c.setAgentState(api.AgentStateDone)
					c.pendingFunctionCalls = []ToolCallAnalysis{}
					c.Session.LastModified = time.Now()
					c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "Error: "+err.Error())
					c.lastErr = err
					continue
				}
				c.currIteration = c.currIteration + 1
				c.pendingFunctionCalls = []ToolCallAnalysis{}
				log.Info("Tool calls dispatched successfully", "currIteration", c.currIteration, "currChatContentLen", len(c.currChatContent), "agentState", c.AgentState())
			}
		}
	}()

	return nil
}

// isContextLengthExceededError returns true when the LLM rejected the request
// because the input token count exceeded the model's maximum context window.
func isContextLengthExceededError(err error) bool {
	return strings.Contains(err.Error(), "input token count exceeds")
}

func (c *Agent) handleMetaQuery(ctx context.Context, query string) (answer string, handled bool, err error) {
	switch query {
	case "clear", "reset":
		c.sessionMu.Lock()
		// TODO: Remove this check when session persistence is default
		if err := c.Session.ChatMessageStore.ClearChatMessages(); err != nil {
			return "Failed to clear the conversation", false, err
		}
		if err := c.llmChat.Initialize(c.Session.ChatMessageStore.ChatMessages()); err != nil {
			klog.Errorf("failed to initialize chat after clear: %v", err)
		}
		c.sessionMu.Unlock()
		return "Cleared the conversation.", true, nil
	case "model":
		return "Current model is `" + c.Model + "`", true, nil
	case "models":
		models, err := c.listModels(ctx)
		if err != nil {
			return "", false, fmt.Errorf("listing models: %w", err)
		}
		return "Available models:\n\n  - " + strings.Join(models, "\n  - ") + "\n\n", true, nil
	case "tools":
		return "Available tools:\n\n  - " + strings.Join(c.Tools.Names(), "\n  - ") + "\n\n", true, nil
	case "session":
		if c.SessionBackend == "memory" {
			return "Ephemeral session (memory backed). No persistent info available.", true, nil
		}
		return fmt.Sprintf("Current session:\n\n%s", c.Session.String()), true, nil

	case "sessions":
		mgr, err := c.getSessionManager()
		if err != nil {
			return "", false, err
		}
		sessionList, err := mgr.ListSessions()
		if err != nil {
			return "", false, fmt.Errorf("failed to list sessions: %w", err)
		}
		if len(sessionList) == 0 {
			return "No sessions found.", true, nil
		}

		// Add ```text so markdown doesn't wreck the format
		availableSessions := "```text"
		availableSessions += "Available sessions:\n\n"
		availableSessions += "ID\t\t\tCreated\t\t\tLast Accessed\t\tModel\t\tProvider\n"
		availableSessions += "--\t\t\t-------\t\t\t-------------\t\t-----\t\t--------\n"

		for _, session := range sessionList {
			availableSessions += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n",
				session.ID,
				session.CreatedAt.Format("2006-01-02 15:04"),
				session.LastModified.Format("2006-01-02 15:04"),
				session.ModelID,
				session.ProviderID)
		}
		// close the ```text box
		availableSessions += "```"
		return availableSessions, true, nil
	}

	if strings.HasPrefix(query, "resume-session") {
		parts := strings.Split(query, " ")
		if len(parts) != 2 {
			return "Invalid command. Usage: resume-session <session_id>", true, nil
		}
		sessionID := parts[1]
		if err := c.LoadSession(sessionID); err != nil {
			return "", false, err
		}
		return fmt.Sprintf("Resumed session %s.", sessionID), true, nil
	}

	return "", false, nil
}

func (c *Agent) NewSession() (string, error) {
	if _, err := c.SaveSession(); err != nil {
		return "", fmt.Errorf("failed to save current session: %w", err)
	}

	metadata := sessions.Metadata{
		ModelID:    c.Model,
		ProviderID: c.Provider,
	}
	if c.Session != nil {
		metadata.SlackUserID = c.Session.SlackUserID
	}

	mgr, err := c.getSessionManager()
	if err != nil {
		return "", err
	}
	newSession, err := mgr.NewSession(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}

	newSession.Messages = [](*api.Message){}
	c.sessionMu.Lock()
	c.Session = newSession
	c.ChatMessageStore = newSession.ChatMessageStore
	c.sessionMu.Unlock()

	// Create a new chat session with the new model
	var switchSkills []skills.Skill
	if c.SkillsRegistry != nil {
		switchSkills = c.SkillsRegistry.All()
	}
	systemPrompt, err := c.generatePrompt(context.Background(), defaultSystemPromptTemplate, PromptData{
		Tools:                c.Tools,
		EnableToolUseShim:    c.EnableToolUseShim,
		ModifyResources:      c.ModifyResources,
		SessionIsInteractive: true,
		AgentName:            c.AgentName,
		Skills:               switchSkills,
	})
	if err != nil {
		return "", fmt.Errorf("generating system prompt for new session: %w", err)
	}

	c.llmChat = gollm.NewRetryChat(
		c.LLM.StartChat(systemPrompt, c.Model),
		gollm.RetryConfig{
			MaxAttempts:    3,
			InitialBackoff: 10 * time.Second,
			MaxBackoff:     60 * time.Second,
			BackoffFactor:  2,
			Jitter:         true,
		},
	)

	// Register kubectl tool if not already present
	found := false
	for _, name := range c.Tools.Names() {
		if name == "kubectl" {
			found = true
			break
		}
	}
	if !found {
		c.Tools.RegisterTool(tools.NewKubectlTool())
	}

	if err := c.llmChat.Initialize(c.Session.ChatMessageStore.ChatMessages()); err != nil {
		return "", fmt.Errorf("failed to initialize chat with new session: %w", err)
	}

	return newSession.ID, nil
}

func (c *Agent) SaveSession() (string, error) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	mgr, err := c.getSessionManager()
	if err != nil {
		return "", err
	}

	if c.Session != nil {
		foundSession, _ := mgr.FindSessionByID(c.Session.ID)
		if foundSession != nil {
			return foundSession.ID, nil
		}
	}

	metadata := sessions.Metadata{
		CreatedAt:    c.Session.CreatedAt,
		LastAccessed: time.Now(),
		ModelID:      c.Model,
		ProviderID:   c.Provider,
		SlackUserID:  c.Session.SlackUserID,
	}

	newSession, err := mgr.NewSession(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}

	messages := c.ChatMessageStore.ChatMessages()
	if err := newSession.ChatMessageStore.SetChatMessages(messages); err != nil {
		return "", fmt.Errorf("failed to save chat messages to new session: %w", err)
	}

	c.ChatMessageStore = newSession.ChatMessageStore
	c.Session = newSession
	c.Session.Messages = messages

	if c.llmChat != nil {
		_ = c.llmChat.Initialize(c.Session.ChatMessageStore.ChatMessages())
	}

	return newSession.ID, nil
}

// LoadSession loads a session by ID (or latest), updates the agent's state, and re-initializes the chat.
func (c *Agent) LoadSession(sessionID string) error {
	mgr, err := c.getSessionManager()
	if err != nil {
		return err
	}

	var session *api.Session
	if sessionID == "" || sessionID == "latest" {
		s, err := mgr.GetLatestSession()
		if err != nil {
			return fmt.Errorf("failed to get latest session: %w", err)
		}
		if s == nil {
			return fmt.Errorf("no sessions found to resume")
		}
		session = s
	} else {
		s, err := mgr.FindSessionByID(sessionID)
		if err != nil {
			return fmt.Errorf("failed to get session %q: %w", sessionID, err)
		}
		session = s
	}

	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	if session.ChatMessageStore == nil {
		session.ChatMessageStore = sessions.NewInMemoryChatStore()
	}

	c.Session = session
	c.ChatMessageStore = session.ChatMessageStore
	c.Session.Messages = session.ChatMessageStore.ChatMessages()
	c.Session.LastModified = time.Now()

	// Reset state if it was left running (e.g. from a crash)
	if c.Session.AgentState == api.AgentStateRunning || c.Session.AgentState == api.AgentStateInitializing {
		c.Session.AgentState = api.AgentStateIdle
	}

	if err := mgr.UpdateLastAccessed(session); err != nil {
		return fmt.Errorf("failed to update session metadata: %w", err)
	}

	if c.llmChat != nil {
		if err := c.llmChat.Initialize(c.Session.ChatMessageStore.ChatMessages()); err != nil {
			return fmt.Errorf("failed to re-initialize chat with new session: %w", err)
		}
	}

	return nil
}

func (c *Agent) listModels(ctx context.Context) ([]string, error) {
	if c.availableModels == nil {
		modelNames, err := c.LLM.ListModels(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing models: %w", err)
		}
		c.availableModels = modelNames
	}
	return c.availableModels, nil
}

func (c *Agent) DispatchToolCalls(ctx context.Context) error {
	log := klog.FromContext(ctx)
	// execute all pending function calls
	for _, call := range c.pendingFunctionCalls {
		// Only show "Running" message and proceed with execution for non-interactive commands
		toolDescription := call.ParsedToolCall.Description()

		c.addMessage(api.MessageSourceModel, api.MessageTypeToolCallRequest, toolDescription)

		output, err := call.ParsedToolCall.InvokeTool(ctx, tools.InvokeToolOptions{
			Kubeconfig: c.Kubeconfig,
			WorkDir:    c.workDir,
			Env:        c.EnvVars,
			Identity:   c.Session.UserIdentity,
		})

		if err != nil {
			log.Error(err, "error executing action", "output", output)
			c.addMessage(api.MessageSourceAgent, api.MessageTypeToolCallResponse, err.Error())
			return err
		}

		// Handle timeout message using UI blocks
		if execResult, ok := output.(*tools.ExecResult); ok && execResult != nil && execResult.StreamType == "timeout" {
			c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "\nTimeout reached after 7 seconds\n")
		}
		// Add the tool call result to maintain conversation flow
		var payload any
		if c.EnableToolUseShim {
			// Add the error as an observation
			observation := fmt.Sprintf("Result of running %q:\n%v",
				call.FunctionCall.Name,
				output)
			c.currChatContent = append(c.currChatContent, observation)
			payload = observation
		} else {
			// If shim is disabled, convert the result to a map and append FunctionCallResult
			result, err := tools.ToolResultToMap(output)
			if err != nil {
				log.Error(err, "error converting tool result to map", "output", output)
				return err
			}
			payload = result
			c.currChatContent = append(c.currChatContent, gollm.FunctionCallResult{
				ID:     call.FunctionCall.ID,
				Name:   call.FunctionCall.Name,
				Result: result,
			})
		}
		c.addMessage(api.MessageSourceAgent, api.MessageTypeToolCallResponse, payload)
	}
	return nil
}

// The key idea is to treat all tool calls to be executed atomically or not
// If all tool calls are readonly call, it is straight forward
// if some of the tool calls are not readonly, then the interesting question is should the permission
// be asked for each of the tool call or only once for all the tool calls.
// I think treating all tool calls as atomic is the right thing to do.

type ToolCallAnalysis struct {
	FunctionCall        gollm.FunctionCall
	ParsedToolCall      *tools.ToolCall
	IsInteractive       bool
	IsInteractiveError  error
	ModifiesResourceStr string
}

func (c *Agent) analyzeToolCalls(ctx context.Context, toolCalls []gollm.FunctionCall) ([]ToolCallAnalysis, error) {
	toolCallAnalysis := make([]ToolCallAnalysis, len(toolCalls))
	for i, call := range toolCalls {
		toolCallAnalysis[i].FunctionCall = call
		toolCall, err := c.Tools.ParseToolInvocation(ctx, call.Name, call.Arguments)
		if err != nil {
			return nil, fmt.Errorf("error parsing tool call: %w", err)
		}
		toolCallAnalysis[i].IsInteractive, err = toolCall.GetTool().IsInteractive(call.Arguments)
		if err != nil {
			toolCallAnalysis[i].IsInteractiveError = err
		}
		toolCallAnalysis[i].ModifiesResourceStr = toolCall.GetTool().CheckModifiesResource(call.Arguments)
		toolCallAnalysis[i].ParsedToolCall = toolCall
	}
	return toolCallAnalysis, nil
}

func (c *Agent) handleChoice(ctx context.Context, choice *api.UserChoiceResponse) (dispatchToolCalls bool) {
	log := klog.FromContext(ctx)
	// if user input is a choice and use has declined the operation,
	// we need to abort all pending function calls.
	// update the currChatContent with the choice and keep the agent loop running.

	// Normalize the input
	switch choice.Choice {
	case 1:
		dispatchToolCalls = true
	case 2:
		c.SkipPermissions = true
		dispatchToolCalls = true
	case 3:
		c.currChatContent = append(c.currChatContent, gollm.FunctionCallResult{
			ID:   c.pendingFunctionCalls[0].FunctionCall.ID,
			Name: c.pendingFunctionCalls[0].FunctionCall.Name,
			Result: map[string]any{
				"error":     "User declined to run this operation.",
				"status":    "declined",
				"retryable": false,
			},
		})
		c.pendingFunctionCalls = []ToolCallAnalysis{}
		dispatchToolCalls = false
		c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "Operation was skipped. User declined to run this operation.")
	default:
		// This case should technically not be reachable due to AskForConfirmation loop
		err := fmt.Errorf("invalid confirmation choice: %q", choice.Choice)
		log.Error(err, "Invalid choice received from AskForConfirmation")
		c.pendingFunctionCalls = []ToolCallAnalysis{}
		dispatchToolCalls = false
		c.addMessage(api.MessageSourceAgent, api.MessageTypeError, "Invalid choice received. Cancelling operation.")
	}
	return dispatchToolCalls
}

type kubeConfigFile struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// loadKubeContextNames reads a kubeconfig file, tests connectivity to each context's
// Kubernetes API server in parallel, and returns only the names of reachable contexts.
// Contexts that fail the connectivity check are logged and excluded from the result.
// Returns nil, nil when the kubeconfig file does not exist (e.g. in-cluster deployments).
func loadKubeContextNames(ctx context.Context, kubeconfigPath string) ([]string, error) {
	kubeconfigPath = os.ExpandEnv(kubeconfigPath)
	data, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg kubeConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Contexts) == 0 {
		return nil, nil
	}

	log := klog.FromContext(ctx)

	// Build a map from cluster name → server URL for quick lookup.
	clusterServer := make(map[string]string, len(cfg.Clusters))
	for _, cl := range cfg.Clusters {
		clusterServer[cl.Name] = cl.Cluster.Server
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // reachability probe only
		},
	}

	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(cfg.Contexts))

	for _, c := range cfg.Contexts {
		name := c.Name
		server := clusterServer[c.Context.Cluster]
		go func() {
			if server == "" {
				results <- result{name: name, err: fmt.Errorf("no server URL for context %s", name)}
				return
			}
			url := strings.TrimRight(server, "/") + "/readyz"
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if reqErr != nil {
				results <- result{name: name, err: reqErr}
				return
			}
			resp, doErr := httpClient.Do(req)
			if doErr != nil {
				results <- result{name: name, err: doErr}
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				results <- result{name: name, err: fmt.Errorf("/readyz returned HTTP %d", resp.StatusCode)}
				return
			}
			results <- result{name: name}
		}()
	}

	names := make([]string, 0, len(cfg.Contexts))
	for range cfg.Contexts {
		r := <-results
		if r.err != nil {
			log.Info("Kube context is not reachable, excluding from agent context list", "context", r.name, "err", r.err)
		} else {
			names = append(names, r.name)
		}
	}
	return names, nil
}

// generateFromTemplate generates a prompt for LLM. It uses the prompt from the provides template file or default.
func (a *Agent) generatePrompt(_ context.Context, defaultPromptTemplate string, data PromptData) (string, error) {
	promptTemplate := defaultPromptTemplate
	if a.PromptTemplateFile != "" {
		content, err := os.ReadFile(a.PromptTemplateFile)
		if err != nil {
			return "", fmt.Errorf("error reading template file: %v", err)
		}
		promptTemplate = string(content)
	}

	for _, extraPromptPath := range a.ExtraPromptPaths {
		content, err := os.ReadFile(extraPromptPath)
		if err != nil {
			return "", fmt.Errorf("error reading extra prompt path: %v", err)
		}
		promptTemplate += "\n" + string(content)
	}

	tmpl, err := template.New("promptTemplate").Parse(promptTemplate)
	if err != nil {
		return "", fmt.Errorf("building template for prompt: %w", err)
	}

	var result strings.Builder
	err = tmpl.Execute(&result, &data)
	if err != nil {
		return "", fmt.Errorf("evaluating template for prompt: %w", err)
	}
	return result.String(), nil
}

// PromptData represents the structure of the data to be filled into the template.
type PromptData struct {
	Query string
	Tools tools.Tools

	EnableToolUseShim    bool
	ModifyResources      ModifyResourcesMode
	SessionIsInteractive bool
	AgentName            string
	KubeContexts         []string       // context names from kubeconfig, injected at startup
	Skills               []skills.Skill // available skills, listed in system prompt
}

func (a *PromptData) IsReadOnly() bool    { return a.ModifyResources == ModifyResourcesModeNone }
func (a *PromptData) IsAllowModify() bool { return a.ModifyResources == ModifyResourcesModeAllow }
func (a *PromptData) IsAutoModify() bool  { return a.ModifyResources == ModifyResourcesModeAuto }

func (a *PromptData) ToolsAsJSON() string {
	var toolDefinitions []*gollm.FunctionDefinition

	for _, tool := range a.Tools.AllTools() {
		toolDefinitions = append(toolDefinitions, tool.FunctionDefinition())
	}

	json, err := json.MarshalIndent(toolDefinitions, "", "  ")
	if err != nil {
		return ""
	}
	return string(json)
}

func (a *PromptData) ToolNames() string {
	return strings.Join(a.Tools.Names(), ", ")
}

// buildQueryWithSkills prepends instructions from any auto-triggered skills to the query.
// Skills are matched by keyword triggers in the user's message.
func (c *Agent) buildQueryWithSkills(query string) string {
	if c.SkillsRegistry == nil {
		return query
	}
	matched := c.SkillsRegistry.Match(query)
	if len(matched) == 0 {
		return query
	}
	var sb strings.Builder
	for _, s := range matched {
		if s.Instructions != "" {
			sb.WriteString("## Skill: ")
			sb.WriteString(s.Name)
			sb.WriteString("\n")
			sb.WriteString(s.Instructions)
			sb.WriteString("\n\n")
		}
	}
	sb.WriteString(query)
	return sb.String()
}

type ReActResponse struct {
	Thought string  `json:"thought"`
	Answer  string  `json:"answer,omitempty"`
	Action  *Action `json:"action,omitempty"`
}

type Action struct {
	Name             string `json:"name"`
	Reason           string `json:"reason"`
	Command          string `json:"command"`
	ModifiesResource string `json:"modifies_resource"`
}

func extractJSON(s string) (string, bool) {
	const jsonBlockMarker = "```json"

	first := strings.Index(s, jsonBlockMarker)
	last := strings.LastIndex(s, "```")
	if first == -1 || last == -1 || first == last {
		return "", false
	}
	data := s[first+len(jsonBlockMarker) : last]

	return data, true
}

// parseReActResponse parses the LLM response into a ReActResponse struct
// This function assumes the input contains exactly one JSON code block
// formatted with ```json and ``` markers. The JSON block is expected to
// contain a valid ReActResponse object.
func parseReActResponse(input string) (*ReActResponse, error) {
	cleaned, found := extractJSON(input)
	if !found {
		return nil, fmt.Errorf("no JSON code block found in %q", cleaned)
	}

	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.TrimSpace(cleaned)

	var reActResp ReActResponse
	if err := json.Unmarshal([]byte(cleaned), &reActResp); err != nil {
		return nil, fmt.Errorf("parsing JSON %q: %w", cleaned, err)
	}
	return &reActResp, nil
}

// toMap converts the value to a map, going via JSON
func toMap(v any) (map[string]any, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("converting %T to json: %w", v, err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(j, &m); err != nil {
		return nil, fmt.Errorf("converting json to map: %w", err)
	}
	return m, nil
}

func candidateToShimCandidate(iterator gollm.ChatResponseIterator) (gollm.ChatResponseIterator, error) {
	return func(yield func(gollm.ChatResponse, error) bool) {
		var buf strings.Builder
		for response, err := range iterator {
			if err != nil {
				yield(nil, err)
				return
			}

			if len(response.Candidates()) == 0 {
				yield(nil, fmt.Errorf("no candidates in LLM response"))
				return
			}

			candidate := response.Candidates()[0]

			for _, part := range candidate.Parts() {
				if text, ok := part.AsText(); ok {
					buf.WriteString(text)
					klog.Infof("text is %q", text)
				} else {
					yield(nil, fmt.Errorf("no text part found in candidate"))
					return
				}
			}
		}

		buffer := buf.String()
		if buffer == "" {
			yield(nil, nil)
			return
		}

		parsedReActResp, err := parseReActResponse(buffer)
		if err != nil {
			yield(nil, fmt.Errorf("parsing ReAct response %q: %w", buffer, err))
			return
		}
		yield(&ShimResponse{candidate: parsedReActResp}, nil)
	}, nil
}

type ShimResponse struct {
	candidate *ReActResponse
}

func (r *ShimResponse) UsageMetadata() any {
	return nil
}

func (r *ShimResponse) Candidates() []gollm.Candidate {
	return []gollm.Candidate{&ShimCandidate{candidate: r.candidate}}
}

type ShimCandidate struct {
	candidate *ReActResponse
}

func (c *ShimCandidate) String() string {
	return fmt.Sprintf("Thought: %s\nAnswer: %s\nAction: %s", c.candidate.Thought, c.candidate.Answer, c.candidate.Action)
}

func (c *ShimCandidate) Parts() []gollm.Part {
	var parts []gollm.Part
	if c.candidate.Thought != "" {
		parts = append(parts, &ShimPart{text: c.candidate.Thought})
	}
	if c.candidate.Answer != "" {
		parts = append(parts, &ShimPart{text: c.candidate.Answer})
	}
	if c.candidate.Action != nil {
		parts = append(parts, &ShimPart{action: c.candidate.Action})
	}
	return parts
}

type ShimPart struct {
	text   string
	action *Action
}

func (p *ShimPart) AsText() (string, bool) {
	return p.text, p.text != ""
}

func (p *ShimPart) AsFunctionCalls() ([]gollm.FunctionCall, bool) {
	if p.action != nil {
		functionCallArgs, err := toMap(p.action)
		if err != nil {
			return nil, false
		}
		delete(functionCallArgs, "name") // passed separately
		// delete(functionCallArgs, "reason")
		// delete(functionCallArgs, "modifies_resource")
		return []gollm.FunctionCall{
			{
				Name:      p.action.Name,
				Arguments: functionCallArgs,
			},
		}, true
	}
	return nil, false
}

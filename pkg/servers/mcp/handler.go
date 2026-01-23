/*
Copyright 2025 The Kruise Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"k8s.io/klog/v2"
)

// Handler handles MCP tool calls
type Handler struct {
	sessionManager *SessionManager
	adapter        *E2BAdapter
	config         *ServerConfig
	auth           *Auth
}

// NewHandler creates a new handler
func NewHandler(sessionManager *SessionManager, adapter *E2BAdapter, config *ServerConfig, auth *Auth) *Handler {
	return &Handler{
		sessionManager: sessionManager,
		adapter:        adapter,
		config:         config,
		auth:           auth,
	}
}

// getSessionID extracts MCP session ID from context
// Falls back to userID if sessionID is not available (for stdio mode)
func getSessionID(ctx context.Context, userID string) string {
	// Try to get MCP client session from context
	if clientSession := server.ClientSessionFromContext(ctx); clientSession != nil {
		sessionID := clientSession.SessionID()
		if sessionID != "" {
			return sessionID
		}
	}

	// Fallback to userID for stdio mode or when sessionID is not available
	return userID
}

// HandleRunCode handles the run_code tool
func (h *Handler) HandleRunCode(ctx context.Context, req mcpgo.CallToolRequest, args RunCodeRequest) (RunCodeResponse, error) {
	log := klog.FromContext(ctx).WithValues("tool", ToolRunCode)

	// Get user from context
	user, err := GetUserFromContext(ctx)
	if err != nil {
		return RunCodeResponse{}, err
	}

	// Get or determine session ID
	sessionID := getSessionID(ctx, user.ID.String())
	log = log.WithValues("sessionID", sessionID, "userID", user.ID.String())

	// Validate code length
	if len(args.Code) > h.config.MaxCodeLength {
		return RunCodeResponse{}, fmt.Errorf("code exceeds maximum length of %d characters", h.config.MaxCodeLength)
	}

	// Get or create session
	session, err := h.sessionManager.GetOrCreateSession(ctx, sessionID, user.ID.String(), h.config.DefaultTemplate)
	if err != nil {
		return RunCodeResponse{}, err
	}

	log.Info(fmt.Sprintf("session msg: %v ", session))

	log.Info("executing code", "sandboxID", session.SandboxID, "codeLength", len(args.Code))

	// Execute code through sandbox
	ctx, cancel := context.WithTimeout(ctx, h.config.CodeExecutionTimeout)
	defer cancel()

	result, err := h.executeCodeInSandbox(ctx, session, args.Code)
	if err != nil {
		log.Error(err, "code execution failed")
		return RunCodeResponse{}, fmt.Errorf("code execution failed: %w", err)
	}

	log.Info("code executed successfully", "sandboxID", session.SandboxID, "result", fmt.Sprintf("%v", *result))

	return *result, nil
}

// Helper functions

func (h *Handler) executeCodeInSandbox(ctx context.Context, session *UserSession, code string) (*RunCodeResponse, error) {
	log := klog.FromContext(ctx)
	
	// Prepare E2B compliant request body with all required fields
	requestBody, err := json.Marshal(map[string]interface{}{
		"code":       code,
		"context_id": nil,      // Reserved for future multi-context support
		"language":   "python", // Currently only Python is supported
		"env_vars":   nil,      // Reserved for future environment variable support
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request to sandbox /execute endpoint
	// Note: X-Access-Token should be added by sandbox implementation based on session.AccessToken
	resp, err := h.adapter.RequestToSandbox(ctx, session.UserID, session.SandboxID, http.MethodPost, "/execute", 49999, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request to sandbox: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sandbox returned error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// Initialize execution result structure
	execution := &RunCodeResponse{
		Logs: ExecutionLogs{
			Stdout: []string{},
			Stderr: []string{},
		},
		Results:   []ExecutionResult{},
		SandboxID: session.SandboxID,
	}

	// Parse streaming SSE response line by line
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue // Skip empty lines
		}

		// Parse each line as JSON
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			log.V(1).Info("failed to parse JSON line, skipping", "line", line, "error", err)
			continue
		}

		// Extract type field to determine message type
		msgType, ok := data["type"].(string)
		if !ok {
			log.V(1).Info("missing or invalid type field, skipping", "data", data)
			continue
		}

		// Process different message types according to E2B specification
		switch msgType {
		case "stdout":
			if text, ok := data["text"].(string); ok {
				execution.Logs.Stdout = append(execution.Logs.Stdout, text)
			}
		case "stderr":
			if text, ok := data["text"].(string); ok {
				execution.Logs.Stderr = append(execution.Logs.Stderr, text)
			}
		case "result":
			// Parse complete result object with all MIME types
			var result ExecutionResult
			if resultBytes, err := json.Marshal(data); err == nil {
				if err := json.Unmarshal(resultBytes, &result); err == nil {
					execution.Results = append(execution.Results, result)
				} else {
					log.V(1).Info("failed to parse result object", "error", err)
				}
			}
		case "error":
			// Parse execution error with name, value, and traceback
			execution.Error = &ExecutionError{
				Name:      getStringField(data, "name"),
				Value:     getStringField(data, "value"),
				Traceback: getStringField(data, "traceback"),
			}
		case "number_of_executions":
			// Extract execution count
			if count, ok := data["execution_count"].(float64); ok {
				intCount := int(count)
				execution.ExecutionCount = &intCount
			}
		default:
			log.V(2).Info("unknown message type, ignoring", "type", msgType, "data", data)
		}
	}

	// Check for scanner errors (I/O issues during streaming)
	if err := scanner.Err(); err != nil {
		log.Error(err, "error reading streaming response", "sandboxID", session.SandboxID)
		// Return partial results even if streaming was interrupted
		return execution, fmt.Errorf("streaming interrupted: %w", err)
	}

	return execution, nil
}

// getStringField safely extracts a string field from a map
func getStringField(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

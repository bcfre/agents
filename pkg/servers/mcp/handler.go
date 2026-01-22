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
	// Prepare request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"code":     code,
		"language": "python",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request to sandbox
	resp, err := h.adapter.RequestToSandbox(ctx, session.UserID, session.SandboxID, http.MethodPost, "/execute", 49999, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request to sandbox: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sandbox returned error: %d - %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result RunCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	result.SandboxID = session.SandboxID
	return &result, nil
}

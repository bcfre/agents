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
	"context"
	"time"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"k8s.io/klog/v2"
)

// AuthenticationMiddleware creates middleware for API key authentication
func (s *MCPServer) AuthenticationMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		log := klog.FromContext(ctx).WithValues("middleware", "Authentication")

		// Skip authentication if disabled
		if !s.config.AuthEnabled {
			log.V(1).Info("authentication disabled, skipping")
			return next(ctx, req)
		}

		// Check if user is already in context (from HTTP layer)
		user, err := GetUserFromContext(ctx)
		if err != nil {
			log.Info("authentication failed", "error", err.Error())
			return nil, err
		}

		log.V(1).Info("authentication successful", "userID", user.ID.String(), "userName", user.Name)
		return next(ctx, req)
	}
}

// LoggingMiddleware creates middleware for logging tool calls
func (s *MCPServer) LoggingMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		log := klog.FromContext(ctx).WithValues("middleware", "Logging", "tool", req.Params.Name)

		// Get user info if available
		userID := "unknown"
		if user, err := GetUserFromContext(ctx); err == nil {
			userID = user.ID.String()
		}

		// Get session ID if available
		sessionID := "unknown"
		if clientSession := server.ClientSessionFromContext(ctx); clientSession != nil {
			if sid := clientSession.SessionID(); sid != "" {
				sessionID = sid
			}
		}

		log.Info("tool call started", "userID", userID, "sessionID", sessionID, "arguments", req.Params.Arguments)
		start := time.Now()

		// Call next handler
		result, err := next(ctx, req)

		// Log completion
		duration := time.Since(start)
		if err != nil {
			log.Error(err, "tool call failed", "duration", duration, "userID", userID, "sessionID", sessionID)
		} else {
			log.Info("tool call completed", "duration", duration, "userID", userID, "sessionID", sessionID)
		}

		return result, err
	}
}

// SessionManagementMiddleware creates middleware for session management
func (s *MCPServer) SessionManagementMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		log := klog.FromContext(ctx).WithValues("middleware", "SessionManagement")

		// Get user from context
		user, err := GetUserFromContext(ctx)
		if err != nil {
			// User not authenticated, skip session management
			return next(ctx, req)
		}

		// Extract session ID from MCP client session
		sessionID := user.ID.String() // Default to userID
		if clientSession := server.ClientSessionFromContext(ctx); clientSession != nil {
			if sid := clientSession.SessionID(); sid != "" {
				sessionID = sid
			}
		}

		log.V(1).Info("managing session", "sessionID", sessionID, "userID", user.ID.String())

		// Refresh session if it exists (for tools that don't create sessions)
		if session, ok := s.sessionManager.GetSession(sessionID); ok && session != nil {
			session.Refresh()
			s.sessionManager.sessions.Store(sessionID, session)
			log.V(1).Info("session refreshed", "sessionID", sessionID, "sandboxID", session.SandboxID)
		}

		// Call next handler
		result, err := next(ctx, req)

		// Refresh session again after successful execution
		if err == nil {
			if session, ok := s.sessionManager.GetSession(sessionID); ok && session != nil {
				session.Refresh()
				s.sessionManager.sessions.Store(sessionID, session)
			}
		}

		return result, err
	}
}

// applyMiddlewares applies all middlewares to a tool handler
func (s *MCPServer) applyMiddlewares(handler server.ToolHandlerFunc) server.ToolHandlerFunc {
	if !s.config.MiddlewareEnabled {
		return handler
	}
	
	// Apply middlewares in order (they will execute in reverse order)
	// Execution order: Authentication -> Session -> Logging -> Tool Handler
	handler = s.LoggingMiddleware(handler)
	handler = s.SessionManagementMiddleware(handler)
	handler = s.AuthenticationMiddleware(handler)
	
	return handler
}

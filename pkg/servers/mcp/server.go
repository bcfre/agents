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
	"fmt"
	"net/http"

	"k8s.io/klog/v2"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	sandbox_manager "github.com/openkruise/agents/pkg/sandbox-manager"
	"github.com/openkruise/agents/pkg/servers/e2b/keys"
)

// MCPServer represents the MCP server
type MCPServer struct {
	config         *ServerConfig
	mcpServer      *server.MCPServer
	handler        *Handler
	sessionManager *SessionManager
	adapter        *E2BAdapter
	auth           *Auth
	httpServer     *http.Server
}

// NewMCPServer creates a new MCP server
func NewMCPServer(
	config *ServerConfig,
	manager *sandbox_manager.SandboxManager,
	keyStorage *keys.SecretKeyStorage,
	maxTimeout int,
) (*MCPServer, error) {

	// Create adapter
	adapter := NewE2BAdapter(manager, maxTimeout)

	// Create auth
	auth := NewAuth(keyStorage)

	// Create session manager
	sessionManager := NewSessionManager(adapter, config)

	// Create handler
	handler := NewHandler(sessionManager, adapter, config, auth)

	// Create MCP server
	mcpServer := server.NewMCPServer(
		"ack-agents-mcp-server",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithLogging(),
	)

	// Create HTTP server
	mux := http.NewServeMux()
	// Add health check endpoint
	mux.HandleFunc("/health", handleHealth)

	s := &MCPServer{
		config:         config,
		mcpServer:      mcpServer,
		handler:        handler,
		sessionManager: sessionManager,
		adapter:        adapter,
		auth:           auth,
		httpServer: &http.Server{
			Addr:    config.HTTPAddress,
			Handler: mux,
		},
	}

	// Register tools
	s.registerTools()

	return s, nil
}

// Start starts the MCP server
func (s *MCPServer) Start(ctx context.Context) error {
	log := klog.FromContext(ctx).WithValues("component", "MCPServer")

	// Start session manager
	s.sessionManager.Start()

	switch s.config.Transport {
	case "http":
		// Start Streamable HTTP server
		log.Info("Starting MCP server with Streamable HTTP", "addr", s.httpServer.Addr)

		// Create streamable HTTP server with configuration
		var httpHandler http.Handler
		if s.config.HeartbeatEnabled {
			httpHandler = server.NewStreamableHTTPServer(s.mcpServer,
				server.WithEndpointPath(s.config.MCPEndpointPath),
				server.WithHeartbeatInterval(s.config.HeartbeatInterval),
				server.WithStateLess(false),
			)
		} else {
			httpHandler = server.NewStreamableHTTPServer(s.mcpServer,
				server.WithEndpointPath(s.config.MCPEndpointPath),
				server.WithStateLess(false),
			)
		}

		// Apply authentication middleware if enabled
		if s.config.AuthEnabled {
			log.Info("Authentication enabled, applying HTTP middleware")
			httpHandler = s.auth.HTTPAuthMiddleware(httpHandler)
		}

		// Update HTTP server handler
		s.httpServer.Handler = httpHandler

		go func() {
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error(err, "MCP HTTP server failed")
			}
		}()
	default:
		return fmt.Errorf("unsupported transport mode: %s", s.config.Transport)
	}

	log.Info("MCP server started successfully", "transport", s.config.Transport)
	return nil
}

// Stop stops the MCP server
func (s *MCPServer) Stop(ctx context.Context) error {
	log := klog.FromContext(ctx).WithValues("component", "MCPServer")

	// Stop session manager
	s.sessionManager.Stop()

	// Stop HTTP server if running
	if s.config.Transport == "http" || s.config.Transport == "sse" {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Error(err, "Failed to shutdown MCP HTTP server")
			return err
		}
	}

	log.Info("MCP server stopped")
	return nil
}

func (s *MCPServer) registerTools() {
	// Get tool definitions
	tools := GetToolDefinitions()

	// Register each tool with structured handlers
	for _, tool := range tools {
		s.mcpServer.AddTool(tool, s.createStructuredToolHandler(tool.Name))
	}
}

func (s *MCPServer) createStructuredToolHandler(toolName string) server.ToolHandlerFunc {
	// Create the base handler
	baseHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return s.executeStructuredTool(ctx, toolName, request)
	}

	// Apply middlewares
	return s.applyMiddlewares(baseHandler)
}

func (s *MCPServer) executeStructuredTool(ctx context.Context, toolName string, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log := klog.FromContext(ctx).WithValues("tool", toolName)
	log.Info("tool called", "arguments", request.Params.Arguments)

	// Route to appropriate structured handler
	switch toolName {
	case ToolRunCode:
		return mcp.NewStructuredToolHandler(s.handler.HandleRunCode)(ctx, request)
	default:
		log.Error(nil, "unknown tool", "toolName", toolName)
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

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
	"time"
)

// ServerConfig contains configuration for the MCP server
type ServerConfig struct {
	// Enabled indicates whether MCP server is enabled
	Enabled bool
	// Port is the port MCP server listens on
	Port int
	// Transport is the transport mode: "stdio", "sse" or "http"
	Transport string
	// HTTPAddress is the HTTP server listen address (format: "host:port")
	HTTPAddress string
	// AuthEnabled indicates whether X-API-KEY authentication is enabled
	AuthEnabled bool
	// SessionTimeout is the duration before idle sessions expire
	SessionTimeout time.Duration
	// DefaultTemplate is the default sandbox template ID
	DefaultTemplate string
	// MaxCodeLength is the maximum length of code that can be executed
	MaxCodeLength int
	// MaxFileSize is the maximum file size that can be uploaded (in bytes)
	MaxFileSize int64
	// CleanupInterval is the interval for cleaning up expired sessions
	CleanupInterval time.Duration
	// CodeExecutionTimeout is the timeout for code execution
	CodeExecutionTimeout time.Duration
	// CommandExecutionTimeout is the timeout for command execution
	CommandExecutionTimeout time.Duration
	// FileOperationTimeout is the timeout for file operations
	FileOperationTimeout time.Duration
	// MCPEndpointPath is the MCP service endpoint path
	MCPEndpointPath string
	// HeartbeatEnabled indicates whether heartbeat is enabled
	HeartbeatEnabled bool
	// HeartbeatInterval is the heartbeat interval
	HeartbeatInterval time.Duration
	// MiddlewareEnabled indicates whether middleware stack is enabled
	MiddlewareEnabled bool
}

// DefaultServerConfig returns default configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Enabled:                 false,
		Port:                    18082,
		Transport:               "http",
		HTTPAddress:             ":18082",
		AuthEnabled:             true,
		SessionTimeout:          30 * time.Minute,
		DefaultTemplate:         "code-interpreter",
		MaxCodeLength:           100000,
		MaxFileSize:             10 * 1024 * 1024, // 10MB
		CleanupInterval:         5 * time.Minute,
		CodeExecutionTimeout:    30 * time.Second,
		CommandExecutionTimeout: 30 * time.Second,
		FileOperationTimeout:    10 * time.Second,
		MCPEndpointPath:         "/mcp",
		HeartbeatEnabled:        true,
		HeartbeatInterval:       30 * time.Second,
		MiddlewareEnabled:       true,
	}
}

// UserSession represents a user's session with associated sandbox
type UserSession struct {
	// SessionID is the MCP protocol session identifier
	SessionID string
	// UserID is the unique identifier of the user
	UserID string
	// SandboxID is the ID of the sandbox associated with this session
	SandboxID string
	// TemplateID is the template used to create the sandbox
	TemplateID string
	// CreatedAt is the time when the session was created
	CreatedAt time.Time
	// LastAccessAt is the time when the session was last accessed
	LastAccessAt time.Time
	// AccessToken is the token for accessing the sandbox
	AccessToken string
}

// IsExpired checks if the session has expired
func (s *UserSession) IsExpired(timeout time.Duration) bool {
	return time.Since(s.LastAccessAt) > timeout
}

// Refresh updates the last access time
func (s *UserSession) Refresh() {
	s.LastAccessAt = time.Now()
}

// RunCodeRequest represents a request to execute code
type RunCodeRequest struct {
	Code string `json:"code" jsonschema:"required" jsonschema_description:"The Python code to execute"`
}

// RunCodeResponse represents the response from code execution
type RunCodeResponse struct {
	Stdout          string                 `json:"stdout" jsonschema_description:"Standard output from code execution"`
	Stderr          string                 `json:"stderr" jsonschema_description:"Standard error from code execution"`
	ExecutionResult map[string]interface{} `json:"execution_result,omitempty" jsonschema_description:"Execution result data"`
	SandboxID       string                 `json:"sandbox_id" jsonschema_description:"ID of the sandbox where code was executed"`
}

// UploadFileRequest represents a request to upload a file
type UploadFileRequest struct {
	Path    string `json:"path" jsonschema:"required" jsonschema_description:"The target path where the file should be saved"`
	Content string `json:"content" jsonschema:"required" jsonschema_description:"The file content encoded in base64"`
}

// UploadFileResponse represents the response from file upload
type UploadFileResponse struct {
	Success  bool   `json:"success" jsonschema_description:"Whether the upload was successful"`
	Message  string `json:"message" jsonschema_description:"Status message"`
	FilePath string `json:"file_path" jsonschema_description:"Path where the file was saved"`
}

// DeleteFileRequest represents a request to delete a file
type DeleteFileRequest struct {
	Path string `json:"path" jsonschema:"required" jsonschema_description:"The path of the file to delete"`
}

// DeleteFileResponse represents the response from file deletion
type DeleteFileResponse struct {
	Success bool   `json:"success" jsonschema_description:"Whether the deletion was successful"`
	Message string `json:"message" jsonschema_description:"Status message"`
}

// ExecuteCommandRequest represents a request to execute a command
type ExecuteCommandRequest struct {
	Command string            `json:"command" jsonschema:"required" jsonschema_description:"The command to execute"`
	Args    []string          `json:"args,omitempty" jsonschema_description:"Command arguments (optional)"`
	Cwd     string            `json:"cwd,omitempty" jsonschema_description:"Working directory for the command (optional)"`
	Env     map[string]string `json:"env,omitempty" jsonschema_description:"Environment variables for the command (optional)"`
}

// ExecuteCommandResponse represents the response from command execution
type ExecuteCommandResponse struct {
	Stdout   string `json:"stdout" jsonschema_description:"Standard output from command"`
	Stderr   string `json:"stderr" jsonschema_description:"Standard error from command"`
	ExitCode int32  `json:"exit_code" jsonschema_description:"Exit code of the command"`
	PID      uint32 `json:"pid" jsonschema_description:"Process ID of the command"`
}

// CleanupSandboxResponse represents the response from sandbox cleanup
type CleanupSandboxResponse struct {
	Success bool   `json:"success" jsonschema_description:"Whether the cleanup was successful"`
	Message string `json:"message" jsonschema_description:"Status message"`
}

// MCP error codes
const (
	ErrorCodeAuthFailed      = -32001
	ErrorCodeSandboxCreation = -32002
	ErrorCodeCodeExecution   = -32003
	ErrorCodeFileOperation   = -32004
	ErrorCodeTimeout         = -32005
	ErrorCodeInternalError   = -32603
)

// MCPError represents an MCP protocol error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error implements the error interface
func (e *MCPError) Error() string {
	return e.Message
}

// NewMCPError creates a new MCP error
func NewMCPError(code int, message string, data interface{}) *MCPError {
	return &MCPError{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

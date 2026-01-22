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
	"github.com/mark3labs/mcp-go/mcp"
)

// ToolNames defines the names of all available tools
const (
	ToolRunCode        = "run_code"
	ToolUploadFile     = "upload_file"
	ToolDeleteFile     = "delete_file"
	ToolExecuteCommand = "execute_command"
	ToolCleanupSandbox = "cleanup_sandbox"
)

// GetToolDefinitions returns all tool definitions for MCP
func GetToolDefinitions() []mcp.Tool {
	return []mcp.Tool{
		mcp.NewTool(
			ToolRunCode,
			mcp.WithDescription("Run Python code in a secure sandbox environment. The code is executed using Jupyter Notebook syntax."),
			mcp.WithString("code",
				mcp.Required(),
				mcp.Description("The Python code to execute"),
			),
			mcp.WithInputSchema[RunCodeRequest](),
			mcp.WithOutputSchema[RunCodeResponse](),
		),

		// todo: 为了降低复杂度，暂时先不实现
		// mcp.NewTool(
		// 	ToolUploadFile,
		// 	mcp.WithDescription("Upload a file to the sandbox filesystem. The file content should be base64 encoded."),
		// 	mcp.WithString("path",
		// 		mcp.Required(),
		// 		mcp.Description("The target path where the file should be saved in the sandbox"),
		// 	),
		// 	mcp.WithString("content",
		// 		mcp.Required(),
		// 		mcp.Description("The file content encoded in base64"),
		// 	),
		// 	mcp.WithInputSchema[UploadFileRequest](),
		// 	mcp.WithOutputSchema[UploadFileResponse](),
		// ),
		// mcp.NewTool(
		// 	ToolDeleteFile,
		// 	mcp.WithDescription("Delete a file from the sandbox filesystem."),
		// 	mcp.WithString("path",
		// 		mcp.Required(),
		// 		mcp.Description("The path of the file to delete"),
		// 	),
		// 	mcp.WithInputSchema[DeleteFileRequest](),
		// 	mcp.WithOutputSchema[DeleteFileResponse](),
		// ),
		// mcp.NewTool(
		// 	ToolExecuteCommand,
		// 	mcp.WithDescription("Execute a shell command in the sandbox."),
		// 	mcp.WithString("command",
		// 		mcp.Required(),
		// 		mcp.Description("The command to execute"),
		// 	),
		// 	mcp.WithArray("args",
		// 		mcp.Description("Command arguments (optional)"),
		// 		mcp.Items(map[string]interface{}{"type": "string"}),
		// 	),
		// 	mcp.WithString("cwd",
		// 		mcp.Description("Working directory for the command (optional)"),
		// 	),
		// 	mcp.WithObject("env",
		// 		mcp.Description("Environment variables for the command (optional)"),
		// 		mcp.AdditionalProperties(map[string]interface{}{"type": "string"}),
		// 	),
		// 	mcp.WithInputSchema[ExecuteCommandRequest](),
		// 	mcp.WithOutputSchema[ExecuteCommandResponse](),
		// ),
		// mcp.NewTool(
		// 	ToolCleanupSandbox,
		// 	mcp.WithDescription("Clean up and release the current user's sandbox. This will delete the sandbox and free up resources."),
		// 	mcp.WithOutputSchema[CleanupSandboxResponse](),
		// ),
	}
}

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
	ToolRunCode = "run_code"
	// ToolUploadFile     = "upload_file"
	// ToolDeleteFile     = "delete_file"
	// ToolExecuteCommand = "execute_command"
	// ToolCleanupSandbox = "cleanup_sandbox"
)

// GetToolDefinitions returns all tool definitions for MCP
func GetToolDefinitions() []mcp.Tool {
	return []mcp.Tool{
		mcp.NewTool(
			ToolRunCode,
			mcp.WithDescription("Execute Python code in a secure sandbox environment using Jupyter Notebook semantics. "+
				"The code execution follows E2B Code Interpreter standards and supports standard Python libraries. "+
				"Returns structured response with error, logs (stdout/stderr arrays), and results (rich output)."),
			mcp.WithString("code",
				mcp.Required(),
				mcp.Description("The Python code to execute in Jupyter Notebook cell format. "+
					"Supports multi-line code, import statements, variable definitions, and standard Python syntax. "+
					"Maximum length: 100,000 characters."),
			),
			mcp.WithInputSchema[RunCodeRequest](),
			mcp.WithOutputSchema[RunCodeResponse](),
		),
	}
}

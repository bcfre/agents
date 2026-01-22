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
	"time"

	"k8s.io/klog/v2"

	"github.com/google/uuid"
	"github.com/openkruise/agents/api/v1alpha1"
	sandbox_manager "github.com/openkruise/agents/pkg/sandbox-manager"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/pkg/servers/e2b/models"
)

// E2BAdapter wraps E2B Controller functionality for MCP server
type E2BAdapter struct {
	manager    *sandbox_manager.SandboxManager
	maxTimeout int
}

// NewE2BAdapter creates a new E2B adapter
func NewE2BAdapter(manager *sandbox_manager.SandboxManager, maxTimeout int) *E2BAdapter {
	return &E2BAdapter{
		manager:    manager,
		maxTimeout: maxTimeout,
	}
}

// CreateSandbox creates a new sandbox for the user
func (a *E2BAdapter) CreateSandbox(ctx context.Context, userID, sessionID, templateID string, timeout int) (*SandboxInfo, error) {
	log := klog.FromContext(ctx).WithValues("userID", userID, "templateID", templateID)

	if timeout == 0 {
		timeout = a.maxTimeout
	}
	accessToken := uuid.NewString()
	// Use ClaimSandbox to get or create a sandbox
	sbx, err := a.manager.ClaimSandbox(ctx, userID, templateID, infra.ClaimSandboxOptions{
		Modifier: func(sbx infra.Sandbox) {
			// Set timeout
			sbx.SetTimeout(infra.TimeoutOptions{
				ShutdownTime: time.Now().Add(time.Duration(timeout) * time.Second),
			})
			annotations := sbx.GetAnnotations()
			if annotations == nil {
				annotations = make(map[string]string)
			}

			annotations["mcp-owner"] = sessionID
			annotations[v1alpha1.AnnotationEnvdAccessToken] = accessToken
			route := sbx.GetRoute()
			annotations[v1alpha1.AnnotationEnvdURL] = fmt.Sprintf("http://%s:%d", route.IP, models.EnvdPort)
			sbx.SetAnnotations(annotations)
		},
	})
	if err != nil {
		log.Error(err, "failed to claim sandbox")
		return nil, fmt.Errorf("failed to claim sandbox: %w", err)
	}

	// Try to initialize envd
	if err := a.initEnvd(ctx, sbx, models.EnvVars{}, accessToken); err != nil {
		log.Error(err, "failed to initialize envd, but continuing")
		// Don't fail here as sandbox might already be initialized
	}

	state, _ := sbx.GetState()
	return &SandboxInfo{
		SandboxID:   sbx.GetSandboxID(),
		AccessToken: accessToken,
		State:       string(state),
	}, nil
}

// GetSandbox retrieves sandbox information
func (a *E2BAdapter) GetSandbox(ctx context.Context, userID, sandboxID string) (*SandboxInfo, error) {
	sbx, err := a.manager.GetClaimedSandbox(ctx, userID, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sandbox not found: %w", err)
	}

	state, _ := sbx.GetState()
	return &SandboxInfo{
		SandboxID:   sbx.GetSandboxID(),
		AccessToken: sbx.GetAnnotations()[v1alpha1.AnnotationEnvdAccessToken],
		State:       string(state),
	}, nil
}

// DeleteSandbox deletes a sandbox
func (a *E2BAdapter) DeleteSandbox(ctx context.Context, userID, sandboxID string) error {
	log := klog.FromContext(ctx).WithValues("userID", userID, "sandboxID", sandboxID)

	sbx, err := a.manager.GetClaimedSandbox(ctx, userID, sandboxID)
	if err != nil {
		log.Error(err, "failed to get sandbox")
		return fmt.Errorf("sandbox not found: %w", err)
	}

	if err := sbx.Kill(ctx); err != nil {
		log.Error(err, "failed to delete sandbox")
		return fmt.Errorf("failed to delete sandbox: %w", err)
	}

	log.Info("sandbox deleted successfully")
	return nil
}

// RequestToSandbox sends an HTTP request to the sandbox
func (a *E2BAdapter) RequestToSandbox(ctx context.Context, userID, sandboxID string, method, path string, port int, body io.Reader) (*http.Response, error) {
	sbx, err := a.manager.GetClaimedSandbox(ctx, userID, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sandbox not found: %w", err)
	}

	return sbx.Request(ctx, method, path, port, body)
}

// SandboxInfo contains basic sandbox information
type SandboxInfo struct {
	SandboxID   string
	AccessToken string
	State       string
}

func (a *E2BAdapter) initEnvd(ctx context.Context, sbx infra.Sandbox, envVars models.EnvVars, accessToken string) error {
	log := klog.FromContext(ctx).WithValues("sandboxID", sbx.GetName())

	initBody, err := json.Marshal(map[string]any{
		"envVars":     envVars,
		"accessToken": accessToken,
	})
	if err != nil {
		log.Error(err, "failed to marshal initBody")
		return err
	}

	_, err = sbx.Request(ctx, http.MethodPost, "/init", models.EnvdPort, bytes.NewBuffer(initBody))
	if err != nil {
		log.Error(err, "failed to send init request to envd")
		return err
	}

	log.V(1).Info("envd initialized successfully")
	return nil
}

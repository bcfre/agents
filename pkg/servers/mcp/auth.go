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
	"net/http"
	"strings"

	"k8s.io/klog/v2"

	"github.com/openkruise/agents/pkg/servers/e2b/keys"
	"github.com/openkruise/agents/pkg/servers/e2b/models"
)

// Auth handles authentication for MCP server
type Auth struct {
	keys *keys.SecretKeyStorage
}

// NewAuth creates a new Auth instance
func NewAuth(keys *keys.SecretKeyStorage) *Auth {
	return &Auth{
		keys: keys,
	}
}

// ValidateAPIKey validates the API key and returns user information
func (a *Auth) ValidateAPIKey(ctx context.Context, apiKey string) (*models.CreatedTeamAPIKey, error) {
	log := klog.FromContext(ctx).WithValues("middleware", "Auth")

	if a.keys == nil {
		// If authentication is disabled, return anonymous user
		return AnonymousUser(), nil
	}

	if apiKey == "" {
		log.Info("API key is empty")
		return nil, NewMCPError(ErrorCodeAuthFailed, "API key is required", nil)
	}

	user, ok := a.keys.LoadByKey(apiKey)
	if !ok {
		log.Info("invalid API key")
		return nil, NewMCPError(ErrorCodeAuthFailed, "Invalid API key", nil)
	}

	return user, nil
}

// GetUserFromContext extracts user from context
func GetUserFromContext(ctx context.Context) (*models.CreatedTeamAPIKey, error) {
	value := ctx.Value(userContextKey)
	if value == nil {
		return nil, NewMCPError(ErrorCodeAuthFailed, "User not found in context", nil)
	}

	user, ok := value.(*models.CreatedTeamAPIKey)
	if !ok {
		return nil, NewMCPError(ErrorCodeAuthFailed, "Invalid user in context", nil)
	}

	return user, nil
}

// SetUserContext sets user in context
func SetUserContext(ctx context.Context, user *models.CreatedTeamAPIKey) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// AnonymousUser returns an anonymous user for non-authentication mode
func AnonymousUser() *models.CreatedTeamAPIKey {
	return &models.CreatedTeamAPIKey{
		ID:   keys.AdminKeyID,
		Name: "auth-disabled",
	}
}

// HTTPAuthMiddleware creates an HTTP middleware for X-API-KEY authentication
func (a *Auth) HTTPAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		log := klog.FromContext(ctx).WithValues("middleware", "HTTPAuth", "remoteAddr", r.RemoteAddr)

		// Extract X-API-KEY from header
		apiKey := r.Header.Get("X-API-KEY")

		// Validate API key
		user, err := a.ValidateAPIKey(ctx, apiKey)
		if err != nil {
			// Security audit log: authentication failed
			log.Info("authentication failed", "error", err.Error(), "apiKeyHint", maskAPIKey(apiKey), "path", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Unauthorized","message":"Invalid or missing API key"}`))
			return
		}

		// Set user in context
		ctx = SetUserContext(ctx, user)
		// Authentication log: success
		log.V(1).Info("authentication successful", "userID", user.ID.String(), "userName", user.Name, "apiKeyHint", maskAPIKey(apiKey))

		// Call next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// maskAPIKey returns the first 4 characters of an API key for logging
func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 4 {
		return "****"
	}
	return apiKey[:4] + strings.Repeat("*", len(apiKey)-4)
}

type contextKey string

const (
	userContextKey contextKey = "user"
)

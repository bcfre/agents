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
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// SessionManager manages user sessions and their associated sandboxes
type SessionManager struct {
	sessions    sync.Map // map[sessionID]*UserSession
	adapter     *E2BAdapter
	config      *ServerConfig
	cleanupStop chan struct{}
	cleanupDone chan struct{}
}

// NewSessionManager creates a new session manager
func NewSessionManager(adapter *E2BAdapter, config *ServerConfig) *SessionManager {
	sm := &SessionManager{
		adapter:     adapter,
		config:      config,
		cleanupStop: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	return sm
}

// Start starts the session manager background tasks
func (sm *SessionManager) Start() {
	go sm.cleanupLoop()
}

// Stop stops the session manager
func (sm *SessionManager) Stop() {
	close(sm.cleanupStop)
	<-sm.cleanupDone
}

// GetOrCreateSession gets an existing session or creates a new one
// sessionID is the MCP protocol session identifier
// userID is the authenticated user identifier
// templateID is the sandbox template to use
func (sm *SessionManager) GetOrCreateSession(ctx context.Context, sessionID, userID, templateID string) (*UserSession, error) {
	log := klog.FromContext(ctx).WithValues("sessionID", sessionID, "userID", userID, "templateID", templateID)

	// Check if session already exists
	if value, ok := sm.sessions.Load(sessionID); ok {
		session := value.(*UserSession)

		// Verify session belongs to the user
		if session.UserID != userID {
			log.Error(nil, "session does not belong to user")
			return nil, NewMCPError(ErrorCodeAuthFailed, "Session does not belong to the authenticated user", nil)
		}

		// Check if session is expired
		if !session.IsExpired(sm.config.SessionTimeout) {
			// Refresh session
			session.Refresh()
			sm.sessions.Store(sessionID, session)
			log.V(1).Info("reusing existing sandbox", "sandboxID", session.SandboxID)
			return session, nil
		}

		// Session expired, clean it up
		log.Info("session expired, creating new sandbox", "oldSandboxID", session.SandboxID)
		_ = sm.adapter.DeleteSandbox(ctx, userID, session.SandboxID)
		sm.sessions.Delete(sessionID)
	}

	// Create new sandbox
	log.Info("creating new sandbox")
	sandboxInfo, err := sm.adapter.CreateSandbox(ctx, userID, sessionID, templateID, 0)
	if err != nil {
		log.Error(err, "failed to create sandbox")
		return nil, NewMCPError(ErrorCodeSandboxCreation, fmt.Sprintf("Failed to create sandbox: %v", err), nil)
	}

	// Create new session
	now := time.Now()
	session := &UserSession{
		SessionID:    sessionID,
		UserID:       userID,
		SandboxID:    sandboxInfo.SandboxID,
		TemplateID:   templateID,
		CreatedAt:    now,
		LastAccessAt: now,
		AccessToken:  sandboxInfo.AccessToken,
	}

	sm.sessions.Store(sessionID, session)
	log.Info("sandbox created successfully", "sandboxID", session.SandboxID)

	return session, nil
}

// GetSession retrieves an existing session by sessionID
func (sm *SessionManager) GetSession(sessionID string) (*UserSession, bool) {
	value, ok := sm.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}

	session := value.(*UserSession)
	if session.IsExpired(sm.config.SessionTimeout) {
		return nil, false
	}

	return session, true
}

// RefreshSession refreshes a session by sessionID
func (sm *SessionManager) RefreshSession(sessionID string) error {
	value, ok := sm.sessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("session not found")
	}

	session := value.(*UserSession)
	session.Refresh()
	sm.sessions.Store(sessionID, session)

	return nil
}

// ReleaseSandbox releases a sandbox by sessionID
func (sm *SessionManager) ReleaseSandbox(ctx context.Context, sessionID string) error {
	log := klog.FromContext(ctx).WithValues("sessionID", sessionID)

	value, ok := sm.sessions.Load(sessionID)
	if !ok {
		log.V(1).Info("no session found to release")
		return nil
	}

	session := value.(*UserSession)
	log.Info("releasing sandbox", "sandboxID", session.SandboxID, "userID", session.UserID)

	// Delete sandbox
	if err := sm.adapter.DeleteSandbox(ctx, session.UserID, session.SandboxID); err != nil {
		log.Error(err, "failed to delete sandbox")
		// Continue to delete session even if sandbox deletion fails
	}

	sm.sessions.Delete(sessionID)
	log.Info("sandbox released successfully")

	return nil
}

// CleanupExpiredSessions cleans up expired sessions
func (sm *SessionManager) CleanupExpiredSessions(ctx context.Context) {
	log := klog.FromContext(ctx).WithValues("action", "cleanupExpiredSessions")

	expiredCount := 0
	sm.sessions.Range(func(key, value interface{}) bool {
		sessionID := key.(string)
		session := value.(*UserSession)

		if session.IsExpired(sm.config.SessionTimeout) {
			log.Info("cleaning up expired session", "sessionID", sessionID, "userID", session.UserID, "sandboxID", session.SandboxID)
			_ = sm.adapter.DeleteSandbox(ctx, session.UserID, session.SandboxID)
			sm.sessions.Delete(sessionID)
			expiredCount++
		}

		return true
	})

	if expiredCount > 0 {
		log.Info("cleanup completed", "expiredSessions", expiredCount)
	}
}

// GetActiveSessions returns the number of active sessions
func (sm *SessionManager) GetActiveSessions() int {
	count := 0
	sm.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// GetSessionsByUserID returns all active sessions for a given user
func (sm *SessionManager) GetSessionsByUserID(userID string) []*UserSession {
	var sessions []*UserSession
	sm.sessions.Range(func(_, value interface{}) bool {
		session := value.(*UserSession)
		if session.UserID == userID && !session.IsExpired(sm.config.SessionTimeout) {
			sessions = append(sessions, session)
		}
		return true
	})
	return sessions
}

// GetSessionBySessionID returns a session by its ID (alias for GetSession)
func (sm *SessionManager) GetSessionBySessionID(sessionID string) (*UserSession, bool) {
	return sm.GetSession(sessionID)
}

// GetSandboxIDBySession returns the sandbox ID for a given session
func (sm *SessionManager) GetSandboxIDBySession(sessionID string) (string, bool) {
	session, ok := sm.GetSession(sessionID)
	if !ok {
		return "", false
	}
	return session.SandboxID, true
}

// GetAllSessions returns all active sessions (for debugging/monitoring)
func (sm *SessionManager) GetAllSessions() []*UserSession {
	var sessions []*UserSession
	sm.sessions.Range(func(_, value interface{}) bool {
		session := value.(*UserSession)
		if !session.IsExpired(sm.config.SessionTimeout) {
			sessions = append(sessions, session)
		}
		return true
	})
	return sessions
}

func (sm *SessionManager) cleanupLoop() {
	defer close(sm.cleanupDone)

	ticker := time.NewTicker(sm.config.CleanupInterval)
	defer ticker.Stop()

	ctx := context.Background()
	log := klog.FromContext(ctx).WithValues("component", "sessionManager", "task", "cleanupLoop")

	for {
		select {
		case <-ticker.C:
			sm.CleanupExpiredSessions(ctx)
		case <-sm.cleanupStop:
			log.Info("cleanup loop stopped")
			return
		}
	}
}

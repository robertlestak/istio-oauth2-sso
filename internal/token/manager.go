package token

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/umg/devops-istio-sso/internal/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// Manager handles refresh token storage and management
type Manager struct {
	store map[string]*types.StoredRefreshToken
	mutex sync.RWMutex
}

// NewManager creates a new token manager
func NewManager() *Manager {
	return &Manager{
		store: make(map[string]*types.StoredRefreshToken),
	}
}

// GenerateSessionID creates a unique session identifier for storing refresh tokens
func (m *Manager) GenerateSessionID() string {
	return uuid.New().String()
}

// StoreRefreshToken stores a refresh token server-side
func (m *Manager) StoreRefreshToken(sessionID, refreshToken, appID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.store[sessionID] = &types.StoredRefreshToken{
		RefreshToken: refreshToken,
		AppID:        appID,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
	}
	
	log.Printf("Stored refresh token for session %s, app %s", sessionID, appID)
}

// GetRefreshToken retrieves a refresh token by session ID
func (m *Manager) GetRefreshToken(sessionID string) (*types.StoredRefreshToken, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	token, exists := m.store[sessionID]
	if exists {
		// Update last used time
		m.mutex.RUnlock()
		m.mutex.Lock()
		token.LastUsed = time.Now()
		m.mutex.Unlock()
		m.mutex.RLock()
	}
	
	return token, exists
}

// RemoveRefreshToken removes a refresh token from storage
func (m *Manager) RemoveRefreshToken(sessionID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	delete(m.store, sessionID)
	log.Printf("Removed refresh token for session %s", sessionID)
}

// CleanupExpiredTokens removes old refresh tokens (run periodically)
func (m *Manager) CleanupExpiredTokens() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	cutoff := time.Now().Add(-24 * time.Hour) // Remove tokens not used in 24 hours
	for sessionID, token := range m.store {
		if token.LastUsed.Before(cutoff) {
			delete(m.store, sessionID)
			log.Printf("Cleaned up expired refresh token for session %s", sessionID)
		}
	}
}

// IsTokenExpired checks if an access token is expired or will expire soon
func (m *Manager) IsTokenExpired(token *types.OAuth2Token) bool {
	if token.Expiry.IsZero() {
		return false // No expiry set, assume valid
	}
	
	// Consider token expired if it expires within the next 5 minutes
	return time.Now().Add(5 * time.Minute).After(token.Expiry)
}

// RefreshAccessToken attempts to refresh an access token using stored refresh token
func (m *Manager) RefreshAccessToken(sessionID string, config *types.OAuth2Config) (*types.OAuth2Token, error) {
	storedToken, exists := m.GetRefreshToken(sessionID)
	if !exists {
		return nil, errors.New("no refresh token found for session")
	}
	
	if storedToken.AppID != config.ID {
		return nil, fmt.Errorf("app ID mismatch: stored=%s, requested=%s", storedToken.AppID, config.ID)
	}
	
	// Create a token with just the refresh token
	oldToken := &oauth2.Token{
		RefreshToken: storedToken.RefreshToken,
	}
	
	// Use OAuth2 library to refresh the token
	tokenSource := config.OAuth2.TokenSource(nil, oldToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		log.Printf("Failed to refresh token for session %s: %v", sessionID, err)
		// Remove invalid refresh token
		m.RemoveRefreshToken(sessionID)
		return nil, fmt.Errorf("failed to refresh token: %v", err)
	}
	
	// Update stored refresh token if a new one was provided
	if newToken.RefreshToken != "" && newToken.RefreshToken != storedToken.RefreshToken {
		m.StoreRefreshToken(sessionID, newToken.RefreshToken, storedToken.AppID)
	}
	
	// Convert to our OAuth2Token format
	refreshedToken := &types.OAuth2Token{
		AccessToken:  newToken.AccessToken,
		TokenType:    newToken.TokenType,
		RefreshToken: newToken.RefreshToken,
		Expiry:       newToken.Expiry,
	}
	
	log.Printf("Successfully refreshed token for session %s", sessionID)
	return refreshedToken, nil
}

// GetTokenCount returns the number of stored refresh tokens
func (m *Manager) GetTokenCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.store)
}

// StartCleanupRoutine starts a background goroutine to clean up expired refresh tokens
func (m *Manager) StartCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Run cleanup every hour
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				m.CleanupExpiredTokens()
			}
		}
	}()
}

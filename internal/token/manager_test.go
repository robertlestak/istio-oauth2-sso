package token

import (
	"testing"
	"time"

	"github.com/umg/devops-istio-sso/internal/types"
)

func TestGenerateSessionID(t *testing.T) {
	manager := NewManager()
	
	id1 := manager.GenerateSessionID()
	id2 := manager.GenerateSessionID()
	
	if id1 == id2 {
		t.Error("GenerateSessionID should return unique IDs")
	}
	
	if len(id1) == 0 {
		t.Error("GenerateSessionID should return non-empty string")
	}
}

func TestRefreshTokenStorage(t *testing.T) {
	manager := NewManager()
	
	sessionID := "test-session-123"
	refreshToken := "test-refresh-token"
	appID := "test-app"
	
	// Test storing a refresh token
	manager.StoreRefreshToken(sessionID, refreshToken, appID)
	
	// Test retrieving the refresh token
	stored, exists := manager.GetRefreshToken(sessionID)
	if !exists {
		t.Error("Expected refresh token to exist")
	}
	
	if stored.RefreshToken != refreshToken {
		t.Errorf("Expected refresh token %s, got %s", refreshToken, stored.RefreshToken)
	}
	
	if stored.AppID != appID {
		t.Errorf("Expected app ID %s, got %s", appID, stored.AppID)
	}
	
	// Test removing the refresh token
	manager.RemoveRefreshToken(sessionID)
	
	_, exists = manager.GetRefreshToken(sessionID)
	if exists {
		t.Error("Expected refresh token to be removed")
	}
}

func TestTokenExpiration(t *testing.T) {
	manager := NewManager()
	
	// Test token that's not expired
	token := &types.OAuth2Token{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(10 * time.Minute),
	}
	
	if manager.IsTokenExpired(token) {
		t.Error("Token should not be expired")
	}
	
	// Test token that's expired
	expiredToken := &types.OAuth2Token{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(-10 * time.Minute),
	}
	
	if !manager.IsTokenExpired(expiredToken) {
		t.Error("Token should be expired")
	}
	
	// Test token that expires soon (within 5 minutes)
	soonExpiredToken := &types.OAuth2Token{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(2 * time.Minute),
	}
	
	if !manager.IsTokenExpired(soonExpiredToken) {
		t.Error("Token should be considered expired (expires within 5 minutes)")
	}
	
	// Test token with zero expiry (should not be expired)
	noExpiryToken := &types.OAuth2Token{
		AccessToken: "test-token",
		Expiry:      time.Time{},
	}
	
	if manager.IsTokenExpired(noExpiryToken) {
		t.Error("Token with zero expiry should not be expired")
	}
}

func TestCleanupExpiredRefreshTokens(t *testing.T) {
	manager := NewManager()
	
	// Add a fresh token
	freshSessionID := "fresh-session"
	manager.StoreRefreshToken(freshSessionID, "fresh-token", "test-app")
	
	// Add an old token by manually setting the LastUsed time
	oldSessionID := "old-session"
	manager.StoreRefreshToken(oldSessionID, "old-token", "test-app")
	manager.store[oldSessionID].LastUsed = time.Now().Add(-25 * time.Hour) // 25 hours ago
	
	// Run cleanup
	manager.CleanupExpiredTokens()
	
	// Fresh token should still exist
	_, exists := manager.GetRefreshToken(freshSessionID)
	if !exists {
		t.Error("Fresh token should not be cleaned up")
	}
	
	// Old token should be removed
	_, exists = manager.GetRefreshToken(oldSessionID)
	if exists {
		t.Error("Old token should be cleaned up")
	}
}

func TestGetTokenCount(t *testing.T) {
	manager := NewManager()
	
	if manager.GetTokenCount() != 0 {
		t.Error("Expected token count to be 0 initially")
	}
	
	manager.StoreRefreshToken("session1", "token1", "app1")
	manager.StoreRefreshToken("session2", "token2", "app2")
	
	if manager.GetTokenCount() != 2 {
		t.Errorf("Expected token count to be 2, got %d", manager.GetTokenCount())
	}
	
	manager.RemoveRefreshToken("session1")
	
	if manager.GetTokenCount() != 1 {
		t.Errorf("Expected token count to be 1, got %d", manager.GetTokenCount())
	}
}

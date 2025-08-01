package token

import (
	"testing"
	"time"

	"github.com/umg/devops-istio-sso/internal/types"
)

func BenchmarkStoreRefreshToken(b *testing.B) {
	manager := NewManager()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionID := manager.GenerateSessionID()
		manager.StoreRefreshToken(sessionID, "test-token", "test-app")
	}
}

func BenchmarkGetRefreshToken(b *testing.B) {
	manager := NewManager()
	
	// Pre-populate with tokens
	sessionIDs := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		sessionID := manager.GenerateSessionID()
		sessionIDs[i] = sessionID
		manager.StoreRefreshToken(sessionID, "test-token", "test-app")
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionID := sessionIDs[i%1000]
		manager.GetRefreshToken(sessionID)
	}
}

func BenchmarkIsTokenExpired(b *testing.B) {
	manager := NewManager()
	token := &types.OAuth2Token{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(10 * time.Minute),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.IsTokenExpired(token)
	}
}

func BenchmarkConcurrentTokenOperations(b *testing.B) {
	manager := NewManager()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sessionID := manager.GenerateSessionID()
			manager.StoreRefreshToken(sessionID, "test-token", "test-app")
			manager.GetRefreshToken(sessionID)
			manager.RemoveRefreshToken(sessionID)
		}
	})
}

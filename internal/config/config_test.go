package config

import (
	"os"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	// Create a temporary config file
	configContent := `{
  "configs": [
    {
      "ID": "test-app",
      "OAuth2": {
        "ClientID": "test-client-id",
        "ClientSecret": "test-client-secret",
        "Endpoint": {
            "AuthURL": "https://example.com/auth",
            "TokenURL": "https://example.com/token"
        },
        "RedirectURL": "http://localhost/callback"
      },
      "LogoutURL": "https://example.com/logout",
      "CookieName": "oauth2_sso",
      "DefaultRedirectURI": "https://example.com",
      "SSODomain": ".example.com"
    }
  ]
}`
	
	tmpFile, err := os.CreateTemp("", "config-test-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	
	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()
	
	// Test loading the config
	manager := NewManager()
	err = manager.LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	
	// Test getting app by ID
	app, err := manager.GetAppByID("test-app")
	if err != nil {
		t.Fatalf("Failed to get app by ID: %v", err)
	}
	
	if app.ID != "test-app" {
		t.Errorf("Expected app ID 'test-app', got '%s'", app.ID)
	}
	
	if app.OAuth2.ClientID != "test-client-id" {
		t.Errorf("Expected client ID 'test-client-id', got '%s'", app.OAuth2.ClientID)
	}
}

func TestGetAppByID(t *testing.T) {
	manager := NewManager()
	
	// Test with empty ID
	_, err := manager.GetAppByID("")
	if err == nil {
		t.Error("Expected error for empty ID")
	}
	
	// Test with non-existent ID
	_, err = manager.GetAppByID("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent ID")
	}
}

func TestGetAllAppIDs(t *testing.T) {
	manager := NewManager()
	
	// Initially should be empty
	ids := manager.GetAllAppIDs()
	if len(ids) != 0 {
		t.Errorf("Expected 0 app IDs, got %d", len(ids))
	}
}

func TestGetDefaultApp(t *testing.T) {
	manager := NewManager()
	
	// Initially should be nil
	app := manager.GetDefaultApp()
	if app != nil {
		t.Error("Expected nil default app")
	}
}

package config

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/umg/devops-istio-sso/internal/types"
	log "github.com/sirupsen/logrus"
)

// Manager handles OAuth2 application configurations
type Manager struct {
	configs []*types.OAuth2Config
}

// NewManager creates a new configuration manager
func NewManager() *Manager {
	return &Manager{
		configs: make([]*types.OAuth2Config, 0),
	}
}

// LoadFromFile reads the OAuth2 application configuration file
// and parses into object in memory
func (m *Manager) LoadFromFile(filename string) error {
	l := log.WithFields(log.Fields{
		"action": "LoadFromFile",
		"file":   filename,
	})
	l.Printf("Loading configuration from file")
	
	bd, berr := os.ReadFile(filename)
	if berr != nil {
		l.Printf("ReadFile error=%v", berr)
		return berr
	}
	
	bd = []byte(os.ExpandEnv(string(bd)))
	
	type cfg struct {
		Configs []*types.OAuth2Config `json:"configs"`
	}
	
	var c cfg
	jerr := json.Unmarshal(bd, &c)
	if jerr != nil {
		l.Printf("json.Unmarshal error=%v", jerr)
		return jerr
	}
	
	m.configs = c.Configs
	if len(m.configs) < 1 {
		l.Printf("default oauth2 provider required")
		return errors.New("default oauth2 provider required")
	}
	
	l.Printf("%v configs loaded", len(m.configs))
	return nil
}

// GetAppByID retrieves a configured OAuth2 application by the ID
func (m *Manager) GetAppByID(id string) (*types.OAuth2Config, error) {
	if id == "" {
		return nil, errors.New("client not provided")
	}
	
	log.Printf("GetAppByID request %v\n", id)
	
	for _, v := range m.configs {
		if v.ID == id {
			log.Printf("GetAppByID found %v: %+v\n", v.ID, m.logConfig(v))
			
			// we found the app config - if there is a .Vault field, we need to
			// retrieve the secret from Vault
			if v.Vault != nil && v.Vault.Path != "" {
				log.Printf("GetAppByID vault %+v\n", v.Vault)
				// TODO: Implement vault integration
				return v, nil
			}
			return v, nil
		}
	}
	
	return nil, errors.New("client not found")
}

// GetDefaultApp returns the first configured application
func (m *Manager) GetDefaultApp() *types.OAuth2Config {
	if len(m.configs) > 0 {
		return m.configs[0]
	}
	return nil
}

// GetAllAppIDs returns all configured application IDs
func (m *Manager) GetAllAppIDs() []string {
	var ids []string
	for _, v := range m.configs {
		ids = append(ids, v.ID)
	}
	return ids
}

// logConfig returns a sanitized version of the config for logging
func (m *Manager) logConfig(c *types.OAuth2Config) types.OAuth2Config {
	return types.OAuth2Config{
		ID:                 c.ID,
		OAuth2:             c.OAuth2,
		LogoutURL:          c.LogoutURL,
		CookieName:         c.CookieName,
		DefaultRedirectURI: c.DefaultRedirectURI,
		HttpOnly:           c.HttpOnly,
		SSODomain:          c.SSODomain,
	}
}

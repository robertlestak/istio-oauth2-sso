package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/umg/devops-istio-sso/internal/types"
	log "github.com/sirupsen/logrus"
)

// Client wraps the Vault API client with additional functionality
type Client struct {
	client *api.Client
	config *types.VaultClient
}

// NewClient creates a new Vault client
func NewClient(config *types.VaultClient) (*Client, error) {
	vaultConfig := &api.Config{
		Address: config.VaultAddr,
	}
	
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %v", err)
	}
	
	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
	}
	
	return &Client{
		client: client,
		config: config,
	}, nil
}

// Login creates a vault token with the k8s auth provider
func (c *Client) Login() (string, error) {
	l := log.WithFields(log.Fields{
		"address": c.config.VaultAddr,
		"role":    c.config.Role,
		"path":    c.config.Path,
		"method":  c.config.AuthMethod,
	})
	l.Debugf("vault.Login(%s)\n", c.config.AuthMethod)
	
	if c.config.KubeToken == "" && os.Getenv("KUBE_TOKEN") != "" {
		log.Debugf("vault.NewClient using KUBE_TOKEN")
		fd, err := os.ReadFile(os.Getenv("KUBE_TOKEN"))
		if err != nil {
			log.Debugf("vault.NewClient error: %v\n", err)
			return "", err
		}
		c.config.KubeToken = string(fd)
	}
	
	options := map[string]interface{}{
		"role": c.config.Role,
		"jwt":  c.config.KubeToken,
	}
	
	path := fmt.Sprintf("auth/%s/login", c.config.AuthMethod)
	secret, err := c.client.Logical().Write(path, options)
	if err != nil {
		log.Debugf("vault.Login(%s) error: %v\n", c.config.AuthMethod, err)
		return "", err
	}
	
	c.config.Token = secret.Auth.ClientToken
	log.Debugf("vault.Login(%s) success\n", c.config.AuthMethod)
	c.client.SetToken(c.config.Token)
	return c.config.Token, nil
}

// GetKVSecret retrieves a kv secret from vault
func (c *Client) GetKVSecret(secretPath string) (map[string]interface{}, error) {
	log.Debugf("vault.GetSecret(%s)\n", secretPath)
	var secrets map[string]interface{}
	
	if secretPath == "" {
		return secrets, errors.New("secret path required")
	}
	
	ss := strings.Split(secretPath, "/")
	if len(ss) < 2 {
		return secrets, errors.New("secret path must be in kv/path/to/secret format")
	}
	
	ss = insertSliceString(ss, 1, "data")
	secretPath = strings.Join(ss, "/")
	
	secret, err := c.client.Logical().Read(secretPath)
	if err != nil {
		log.Debugf("vault.GetKVSecret(%s) c.Read error: %v\n", secretPath, err)
		return secrets, err
	}
	
	if secret == nil || secret.Data == nil {
		return nil, errors.New("secret not found")
	}
	
	return secret.Data["data"].(map[string]interface{}), nil
}

// AuthAndGetConfig authenticates with Vault and retrieves OAuth2 config
func (c *Client) AuthAndGetConfig() (*types.OAuth2Config, error) {
	// Authenticate if no token
	if c.config.Token == "" {
		_, err := c.Login()
		if err != nil {
			return nil, fmt.Errorf("vault authentication failed: %v", err)
		}
	}
	
	// Get secret
	secrets, err := c.GetKVSecret(c.config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %v", err)
	}
	
	// Convert to OAuth2Config
	jd, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret: %v", err)
	}
	
	var oc types.OAuth2Config
	err = json.Unmarshal(jd, &oc)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}
	
	oc.Vault = c.config
	return &oc, nil
}

// insertSliceString inserts a string into a slice at the specified index
func insertSliceString(a []string, index int, value string) []string {
	if len(a) == index { // nil or empty slice or after last element
		return append(a, value)
	}
	a = append(a[:index+1], a[index:]...) // index < len(a)
	a[index] = value
	return a
}

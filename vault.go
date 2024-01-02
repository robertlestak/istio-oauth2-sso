package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/hashicorp/vault/api"
)

// VaultClient is a single self-contained vault client
type VaultClient struct {
	VaultAddr  string      `yaml:"VaultAddr"`
	AuthMethod string      `yaml:"AuthMethod"`
	Namespace  string      `yaml:"Namespace"`
	Role       string      `yaml:"Role"`
	Path       string      `yaml:"Path"`
	KubeToken  string      // auto-filled
	Client     *api.Client // auto-filled
	Token      string      `yaml:"Token"` // auto-filled
}

// NewClients creates and returns a new vault client with a valid token or error
func (vc *VaultClient) NewClient() (*api.Client, error) {
	log.Debugf("vault.NewClient")
	config := &api.Config{
		Address: vc.VaultAddr,
	}
	var err error
	vc.Client, err = api.NewClient(config)
	if err != nil {
		log.Debugf("vault.NewClient error: %v\n", err)
		return vc.Client, err
	}
	if vc.Namespace != "" {
		vc.Client.SetNamespace(vc.Namespace)
	}
	_, terr := vc.NewToken()
	if terr != nil {
		return vc.Client, terr
	}
	return vc.Client, err
}

// Login creates a vault token with the k8s auth provider
func (vc *VaultClient) Login() (string, error) {
	l := log.WithFields(log.Fields{
		"address": vc.VaultAddr,
		"role":    vc.Role,
		"path":    vc.Path,
		"method":  vc.AuthMethod,
	})
	l.Debugf("vault.Login(%s)\n", vc.AuthMethod)
	if vc.Client == nil {
		_, err := vc.NewClient()
		if err != nil {
			l.Debugf("vault.NewToken error: %v\n", err)
			return "", err
		}
	}
	if vc.KubeToken == "" && os.Getenv("KUBE_TOKEN") != "" {
		log.Debugf("vault.NewClient using KUBE_TOKEN")
		fd, err := os.ReadFile(os.Getenv("KUBE_TOKEN"))
		if err != nil {
			log.Debugf("vault.NewClient error: %v\n", err)
			return "", err
		}
		vc.KubeToken = string(fd)
	}
	options := map[string]interface{}{
		"role": vc.Role,
		"jwt":  vc.KubeToken,
	}
	path := fmt.Sprintf("auth/%s/login", vc.AuthMethod)
	secret, err := vc.Client.Logical().Write(path, options)
	if err != nil {
		log.Debugf("vault.Login(%s) error: %v\n", vc.AuthMethod, err)
		return "", err
	}
	vc.Token = secret.Auth.ClientToken
	log.Debugf("vault.Login(%s) success\n", vc.AuthMethod)
	vc.Client.SetToken(vc.Token)
	return vc.Token, nil
}

func tokenEnvTemplate(t string) string {
	l := log.WithFields(log.Fields{
		"action": "tokenEnvTemplate",
	})
	l.Debug("start")
	if !strings.Contains(t, "{{") {
		return ""
	}
	evs := strings.Split(t, "{{")
	if len(evs) < 2 {
		return ""
	}
	evs = strings.Split(evs[1], "}}")
	if len(evs) < 2 {
		return ""
	}
	ev := evs[0]
	return os.Getenv(ev)
}

// NewToken generate a new token for session. If LOCAL env var is set and the token is as well, the login is
// skipped and the token is used instead.
func (vc *VaultClient) NewToken() (string, error) {
	l := log.WithFields(log.Fields{
		"address": vc.VaultAddr,
		"role":    vc.Role,
		"path":    vc.Path,
		"method":  vc.AuthMethod,
	})
	l.Debugf("vault.NewToken()\n")
	if tv := tokenEnvTemplate(vc.Token); tv != "" {
		l.Debugf("vault.NewToken using token from env var\n")
		if vc.Client == nil {
			_, err := vc.NewClient()
			if err != nil {
				l.Debugf("vault.NewToken error: %v\n", err)
				return "", err
			}
		}
		vc.Client.SetToken(tv)
		return tv, nil
	}
	l.Debug("checking for local token")
	if os.Getenv("LOCAL") != "" && vc.Token != "" {
		l.Debug("using local token")
		if vc.Client == nil {
			_, err := vc.NewClient()
			if err != nil {
				l.Debugf("vault.NewToken error: %v\n", err)
				return "", err
			}
		}
		vc.Client.SetToken(vc.Token)
		return vc.Token, nil
	}
	l.Debug("vault.NewToken calling Login")
	return vc.Login()
}

// GetKVSecret retrieves a kv secret from vault
func (vc *VaultClient) GetKVSecret(s string) (map[string]interface{}, error) {
	log.Debugf("vault.GetSecret(%s)\n", s)
	var secrets map[string]interface{}
	if s == "" {
		return secrets, errors.New("secret path required")
	}
	ss := strings.Split(s, "/")
	if len(ss) < 2 {
		return secrets, errors.New("secret path must be in kv/path/to/secret format")
	}
	ss = insertSliceString(ss, 1, "data")
	//log.Debugf("headers_sent=%+v", vc.Client.Headers())
	c := vc.Client.Logical()
	s = strings.Join(ss, "/")
	secret, err := c.Read(s)
	if err != nil {
		log.Debugf("vault.GetKVSecret(%s) c.Read error: %v\n", s, err)
		return secrets, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("secret not found")
	}
	return secret.Data["data"].(map[string]interface{}), nil
}

// GetKVSecretRetry will login and retry secret access on failure
// to gracefully handle token expiration
func (vc *VaultClient) GetKVSecretRetry(s string) (map[string]interface{}, error) {
	var sec map[string]interface{}
	var err error
	sec, err = vc.GetKVSecret(s)
	if err != nil {
		_, terr := vc.NewToken()
		if terr != nil {
			return sec, terr
		}
		sec, err = vc.GetKVSecret(s)
		if err != nil {
			return sec, err
		}
	}
	return sec, err
}

// WriteSecretRetry will login and retry secret write on failure
// to gracefully handle token expiration
func (vc *VaultClient) WriteSecretRetry(s string, data map[string]interface{}) (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"action": "WriteSecretRetry",
		"secret": s,
	})
	l.Debug("start")
	var secrets map[string]interface{}
	var err error
	secrets, err = vc.WriteSecret(s, data)
	if err != nil {
		l.Debugf("error: %v\n", err)
		_, terr := vc.NewToken()
		if terr != nil {
			l.Debugf("error: %v\n", terr)
			return secrets, terr
		}
		secrets, err = vc.WriteSecret(s, data)
		if err != nil {
			l.Errorf("error: %v\n", err)
			// ce := err.(*api.OutputStringError)
			// cs, err := ce.CurlString()
			// if err != nil {
			// 	l.Errorf("error: %v\n", err)
			// 	return secrets, err
			// }
			// l.Debugf("error: %v\n", cs)
			return secrets, err
		}
	}
	return secrets, err
}

// WriteSecret writes a secret to Vault VaultClient at path p with secret value s
func (vc *VaultClient) WriteSecret(p string, s map[string]interface{}) (map[string]interface{}, error) {
	var secrets map[string]interface{}
	pp := strings.Split(p, "/")
	if len(pp) < 2 {
		return secrets, errors.New("secret path must be in kv/path/to/secret format")
	}
	pp = insertSliceString(pp, 1, "data")
	p = strings.Join(pp, "/")
	log.Debugf("vault.PutSecret(%+v)\n", p)
	if s == nil {
		return secrets, errors.New("secret data required")
	}
	if p == "" {
		return secrets, errors.New("secret path required")
	}
	vd := map[string]interface{}{
		"data": s,
	}
	_, err := vc.Client.Logical().Write(p, vd)
	if err != nil {
		log.Debugf("vault.PutSecret(%+v) error: %v\n", p, err)
		return secrets, err
	}
	return secrets, nil
}

func insertSliceString(a []string, index int, value string) []string {
	if len(a) == index { // nil or empty slice or after last element
		return append(a, value)
	}
	a = append(a[:index+1], a[index:]...) // index < len(a)
	a[index] = value
	return a
}

func (vc *VaultClient) AuthAndGet() (map[string]interface{}, error) {
	var secrets map[string]interface{}
	var err error
	if vc.Client == nil {
		_, err := vc.NewClient()
		if err != nil {
			log.Debugf("vault.NewClient() error: %v\n", err)
			return secrets, err
		}
	}
	if vc.Token == "" {
		_, err := vc.NewToken()
		if err != nil {
			log.Debugf("vault.NewToken() error: %v\n", err)
			return secrets, err
		}
	}
	secrets, err = vc.GetKVSecretRetry(vc.Path)
	if err != nil {
		log.Debugf("vault.GetKVSecretRetry() error: %v\n", err)
		return secrets, err
	}
	return secrets, nil
}

func (vc *VaultClient) AuthAndGetConfig() (*OAuth2Config, error) {
	sec, err := vc.AuthAndGet()
	if err != nil {
		return nil, err
	}
	jd, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	var oc OAuth2Config
	err = json.Unmarshal(jd, &oc)
	if err != nil {
		return nil, err
	}
	oc.Vault = vc
	return &oc, nil
}

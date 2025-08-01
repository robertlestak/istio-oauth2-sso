package types

import (
	"time"

	"golang.org/x/oauth2"
)

// OAuth2Token represents an OAuth2 token with additional fields
type OAuth2Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// IDToken is the token that validates the client's identity.
	IDToken string `json:"id_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// raw optionally contains extra metadata from the server
	// when updating a token.
	raw interface{}
}

// OAuth2Token converts to standard oauth2.Token
func (o *OAuth2Token) OAuth2Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  o.AccessToken,
		TokenType:    o.TokenType,
		RefreshToken: o.RefreshToken,
		Expiry:       o.Expiry,
	}
}

// OAuth2Config contains the base OAuth2 config as well as additional information for session
type OAuth2Config struct {
	OAuth2             *oauth2.Config `json:"OAuth2"`
	ID                 string         `json:"ID"`
	Vault              *VaultClient   `json:"Vault"`
	LogoutURL          string         `json:"LogoutURL"`
	CookieName         string         `json:"CookieName"`
	HttpOnly           bool           `json:"HttpOnly"`
	DefaultRedirectURI string         `json:"DefaultRedirectURI"`
	SSODomain          string         `json:"SSODomain"`
}

// VaultClient is a single self-contained vault client
type VaultClient struct {
	VaultAddr  string `yaml:"VaultAddr"`
	AuthMethod string `yaml:"AuthMethod"`
	Namespace  string `yaml:"Namespace"`
	Role       string `yaml:"Role"`
	Path       string `yaml:"Path"`
	KubeToken  string // auto-filled
	Token      string `yaml:"Token"` // auto-filled
}

// SSODomainConfig contains the configuration for SSO Cookies
type SSODomainConfig struct {
	Token       *OAuth2Token `json:"Token"`
	CookieName  string       `json:"CookieName"`
	HttpOnly    bool         `json:"HttpOnly"`
	RedirectURL string       `json:"RedirectURL"`
	SSODomain   string       `json:"SSODomain"`
}

// StoredRefreshToken contains refresh token and associated metadata
type StoredRefreshToken struct {
	RefreshToken string    `json:"refresh_token"`
	AppID        string    `json:"app_id"`
	UserID       string    `json:"user_id,omitempty"` // Optional: can be extracted from ID token
	CreatedAt    time.Time `json:"created_at"`
	LastUsed     time.Time `json:"last_used"`
}

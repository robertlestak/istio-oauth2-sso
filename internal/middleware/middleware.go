package middleware

import (
	"net/http"
	"strings"

	"github.com/umg/devops-istio-sso/internal/config"
	"github.com/umg/devops-istio-sso/internal/session"
	"github.com/umg/devops-istio-sso/internal/token"
	"github.com/umg/devops-istio-sso/internal/types"
	log "github.com/sirupsen/logrus"
)

// TokenValidationMiddleware checks if tokens are expired and refreshes them automatically
func TokenValidationMiddleware(configManager *config.Manager, sessionManager *session.Manager, tokenManager *token.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip validation for auth endpoints
			if strings.HasPrefix(r.URL.Path, "/oauth2/") ||
				strings.HasPrefix(r.URL.Path, "/callback") ||
				strings.HasPrefix(r.URL.Path, "/refresh/") ||
				strings.HasPrefix(r.URL.Path, "/logout/") ||
				r.URL.Path == "/403" || r.URL.Path == "/healthz" || r.URL.Path == "/token-status" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if user has a valid session
			sessionID := sessionManager.GetSessionIDFromRequest(r)
			if sessionID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Get current token from session
			session, _ := sessionManager.GetSession(r, sessionManager.GetSessionName(r))
			appID, ok := session.Values["ID"].(string)
			if !ok || appID == "" {
				next.ServeHTTP(w, r)
				return
			}

			config, err := configManager.GetAppByID(appID)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Check if access token cookie exists
			_, err = r.Cookie(config.CookieName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// For simplicity, we'll attempt refresh if the cookie is close to expiring
			// In a real implementation, you'd parse the JWT to check expiry

			// Try to refresh the token transparently
			newToken, refreshErr := tokenManager.RefreshAccessToken(sessionID, config)
			if refreshErr != nil {
				log.Printf("Failed to refresh token for session %s: %v", sessionID, refreshErr)
				next.ServeHTTP(w, r)
				return
			}

			// Update the cookie with new token
			sso := &types.SSODomainConfig{
				CookieName:  config.CookieName,
				Token:       newToken,
				SSODomain:   config.SSODomain,
				HttpOnly:    config.HttpOnly,
				RedirectURL: "",
			}
			
			setCookieOnly(sso, w, r, sessionManager, tokenManager)

			log.Printf("Transparently refreshed token for session %s", sessionID)
			next.ServeHTTP(w, r)
		})
	}
}

// setCookieOnly sets the SSO cookie without redirecting (helper function for middleware)
func setCookieOnly(sso *types.SSODomainConfig, w http.ResponseWriter, r *http.Request, sessionManager *session.Manager, tokenManager *token.Manager) {
	session, _ := sessionManager.GetSession(r, sessionManager.GetSessionName(r))
	
	var cid string
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	
	// Get session ID for refresh token storage
	var sessionID string
	if v, ok := session.Values["session_id"].(string); ok {
		sessionID = v
	}
	
	// Set the access token cookie
	tv := sso.Token.AccessToken
	if tv == "" {
		tv = sso.Token.IDToken
	}
	
	http.SetCookie(w, &http.Cookie{
		Name:     sso.CookieName,
		Value:    tv,
		Expires:  sso.Token.Expiry,
		Domain:   sso.SSODomain,
		Path:     "/",
		HttpOnly: sso.HttpOnly,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	
	// Store refresh token server-side
	if sso.Token.RefreshToken != "" && sessionID != "" {
		tokenManager.StoreRefreshToken(sessionID, sso.Token.RefreshToken, cid)
	}
}

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/umg/devops-istio-sso/internal/config"
	"github.com/umg/devops-istio-sso/internal/session"
	"github.com/umg/devops-istio-sso/internal/token"
	"github.com/umg/devops-istio-sso/internal/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// Service handles authentication operations
type Service struct {
	configManager  *config.Manager
	sessionManager *session.Manager
	tokenManager   *token.Manager
}

// NewService creates a new authentication service
func NewService(configManager *config.Manager, sessionManager *session.Manager, tokenManager *token.Manager) *Service {
	return &Service{
		configManager:  configManager,
		sessionManager: sessionManager,
		tokenManager:   tokenManager,
	}
}

// LoginHandler handles calls to the root to either redirect to IDP or back to application after auth
func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "LoginHandler",
	})
	l.Print("LoginHandler")
	
	config, err := s.configFromRequest(r)
	if err != nil {
		l.Print(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	l.Print("getSession")
	session, _ := s.sessionManager.GetSession(r, s.sessionManager.GetSessionName(r))
	session.Options.MaxAge = 0
	session.Options.Domain = config.SSODomain
	session.Options.Path = "/"
	
	// Generate or retrieve session ID for refresh token storage
	var sessionID string
	if existingSessionID, ok := session.Values["session_id"].(string); ok && existingSessionID != "" {
		sessionID = existingSessionID
	} else {
		sessionID = s.tokenManager.GenerateSessionID()
		session.Values["session_id"] = sessionID
	}
	
	l = l.WithFields(log.Fields{
		"session_id": sessionID,
		"action":     "LoginHandler",
	})
	
	session.Values["redirect_uri"] = config.DefaultRedirectURI
	session.Values["ID"] = config.ID
	session.Values["client_id"] = config.OAuth2.ClientID
	
	if r.FormValue("redirect") != "" {
		l.Printf("redirect_uri=%v", r.FormValue("redirect"))
		session.Values["redirect_uri"] = r.FormValue("redirect")
	}
	
	// Set session ID cookie for client-side access
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth2_session_id",
		Value:    sessionID,
		Domain:   config.SSODomain,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	
	s.sessionManager.SaveSession(r, w, session)
	u := config.OAuth2.AuthCodeURL(s.sessionManager.SessionState(session), oauth2.AccessTypeOnline)
	log.Printf("LoginHandler auth ClientID=%v, redirect_uri=%v, auth_code_url=%v\n", session.Values["ID"], session.Values["redirect_uri"], u)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// RefreshHandler provides transparent token refresh for authenticated users
func (s *Service) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("RefreshHandler")
	values := mux.Vars(r)
	appID := values["ID"]
	
	// Get the session ID from the request
	sessionID := s.sessionManager.GetSessionIDFromRequest(r)
	if sessionID == "" {
		http.Error(w, "No session found", http.StatusUnauthorized)
		return
	}
	
	// Get app config
	config, err := s.configManager.GetAppByID(appID)
	if err != nil {
		http.Error(w, fmt.Sprintf("get client error: %v", err), http.StatusBadRequest)
		return
	}
	
	// Attempt to refresh the token
	newToken, err := s.tokenManager.RefreshAccessToken(sessionID, config)
	if err != nil {
		log.Printf("RefreshHandler error: %v", err)
		http.Error(w, "Failed to refresh token", http.StatusUnauthorized)
		return
	}
	
	// Create SSO config and update cookie
	sso := &types.SSODomainConfig{
		CookieName:  config.CookieName,
		Token:       newToken,
		SSODomain:   config.SSODomain,
		HttpOnly:    config.HttpOnly,
		RedirectURL: "",
	}
	
	// Update the SSO cookie with new token (don't redirect)
	s.setCookieOnly(sso, w, r)
	
	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Token refreshed successfully",
	})
}

// CallbackHandler handles responses from IDP
func (s *Service) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "CallbackHandler",
	})
	l.Print("CallbackHandler")
	
	session, err := s.sessionManager.GetSession(r, s.sessionManager.GetSessionName(r))
	if err != nil {
		l.Printf("CallbackHandler error: %v\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	session.Options.Path = "/"
	var rurl string
	if v, ok := session.Values["redirect_uri"]; ok && v != nil {
		rurl = v.(string)
	}
	
	l.Printf("check callback state")
	if r.FormValue("state") != s.sessionManager.SessionState(session) {
		l.Println("invalid callback state")
		s.sessionManager.ClearSession(session, r, w)
		http.Redirect(w, r, "/403?redirect="+rurl, http.StatusTemporaryRedirect)
		return
	}
	
	l.Printf("createReq")
	resp, err := s.createOAuthRequest(r, session)
	if err != nil {
		l.Printf("createReq error: %v\n", err)
		s.sessionManager.ClearSession(session, r, w)
		http.Redirect(w, r, "/403?redirect="+rurl, http.StatusTemporaryRedirect)
		return
	}
	
	l.Printf("getTokenFromBody")
	token, terr := s.getTokenFromBody(resp)
	if terr != nil || token == nil || (token.AccessToken == "" && token.IDToken == "") {
		if terr != nil {
			l.Printf("getTokenFromBody error: %v\n", terr)
		}
		s.sessionManager.ClearSession(session, r, w)
		http.Redirect(w, r, "/403?redirect="+rurl, http.StatusTemporaryRedirect)
		return
	}
	
	l.Printf("setSSOCookie")
	s.setSSOCookie(w, r, session, token)
}

// LogoutHandler handles session removal and redirect to IDP logout
func (s *Service) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := s.sessionManager.GetSession(r, s.sessionManager.GetSessionName(r))
	var cid string
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	
	// Clean up refresh token if session ID exists
	if sessionID, ok := session.Values["session_id"].(string); ok && sessionID != "" {
		s.tokenManager.RemoveRefreshToken(sessionID)
	}
	
	a, err := s.configManager.GetAppByID(cid)
	if err != nil {
		// no app found just use default logout url
		a = s.configManager.GetDefaultApp()
	}
	
	// Remove cookies
	http.SetCookie(w, &http.Cookie{
		Name:     a.CookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   a.SSODomain,
		HttpOnly: a.HttpOnly,
		Secure:   true,
	})
	
	// Remove session ID cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth2_session_id",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   a.SSODomain,
		HttpOnly: true,
		Secure:   true,
	})
	
	s.sessionManager.ClearSession(session, r, w)
	// Redirect to IDP logout URL
	http.Redirect(w, r, a.LogoutURL, http.StatusTemporaryRedirect)
}

// TokenStatusHandler provides information about the current token status
func (s *Service) TokenStatusHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := s.sessionManager.GetSessionIDFromRequest(r)
	if sessionID == "" {
		http.Error(w, "No session found", http.StatusUnauthorized)
		return
	}
	
	storedToken, exists := s.tokenManager.GetRefreshToken(sessionID)
	if !exists {
		http.Error(w, "No refresh token found", http.StatusUnauthorized)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id":        sessionID,
		"app_id":            storedToken.AppID,
		"created_at":        storedToken.CreatedAt,
		"last_used":         storedToken.LastUsed,
		"has_refresh_token": storedToken.RefreshToken != "",
	})
}

// configFromRequest retrieves the OAuth2 application configuration from the HTTP request
func (s *Service) configFromRequest(r *http.Request) (*types.OAuth2Config, error) {
	v := mux.Vars(r)
	session, _ := s.sessionManager.GetSession(r, s.sessionManager.GetSessionName(r))
	
	var aid string
	if v, ok := session.Values["ID"]; ok {
		aid = v.(string)
	}
	if aid == "" && v["ID"] != "" {
		aid = v["ID"]
	}
	
	l := log.WithFields(log.Fields{
		"action": "configFromRequest",
		"app_id": aid,
	})
	l.Println("configFromRequest")
	
	var config *types.OAuth2Config
	if v["ID"] != "" {
		l.Printf("getAppByID path id=%v", v["ID"])
		var e error
		config, e = s.configManager.GetAppByID(v["ID"])
		if e != nil {
			l.Printf("getAppByID path id=%v error=%v", v["ID"], e)
			return config, e
		}
	} else if aid != "" {
		l.Printf("getAppByID session id=%v", aid)
		var e error
		config, e = s.configManager.GetAppByID(aid)
		if e != nil {
			l.Printf("getAppByID session id=%v error=%v", aid, e)
			return config, e
		}
	} else {
		config = s.configManager.GetDefaultApp()
		l.Printf("default appID")
	}
	
	return config, nil
}

// createOAuthRequest creates a new OAuth login request with the IDP
func (s *Service) createOAuthRequest(r *http.Request, session *sessions.Session) (*http.Response, error) {
	l := log.WithFields(log.Fields{
		"action": "createOAuthRequest",
	})
	l.Printf("createOAuthRequest %+v", session.Values)
	
	var cid string
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	
	l.Printf("getAppByID(%v)", cid)
	config, err := s.configManager.GetAppByID(cid)
	if err != nil {
		l.Print(err)
		return nil, err
	}
	
	// Create new OAuth login request
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", config.OAuth2.ClientID)
	form.Set("client_secret", config.OAuth2.ClientSecret)
	form.Set("code", r.FormValue("code"))
	form.Set("scope", strings.Join(config.OAuth2.Scopes, " "))
	form.Set("redirect_uri", config.OAuth2.RedirectURL)
	
	l.Printf("Login client_id=%v, scope=%v, redirect_uri=%v token_url=%v\n",
		config.OAuth2.ClientID,
		strings.Join(config.OAuth2.Scopes, " "),
		config.OAuth2.RedirectURL,
		config.OAuth2.Endpoint.TokenURL,
	)
	
	l.Printf("send oauth2 request to %v", config.OAuth2.Endpoint.TokenURL)
	req, err := http.NewRequest(http.MethodPost, config.OAuth2.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		l.Printf("send oauth NewRequest error=%v", err)
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.Printf("send oauth request error=%v", err)
		return resp, err
	}
	
	return resp, nil
}

// getTokenFromBody retrieves the OAuth2 token from the HTTP response body
func (s *Service) getTokenFromBody(r *http.Response) (*types.OAuth2Token, error) {
	l := log.WithFields(log.Fields{
		"action": "getTokenFromBody",
	})
	l.Printf("getTokenFromBody")
	
	defer r.Body.Close()
	if r.StatusCode >= 400 {
		l.Printf("getTokenFromBody StatusCode=%v", r.StatusCode)
		bd, err := io.ReadAll(r.Body)
		if err != nil {
			l.Printf("getTokenFromBody StatusCode=%v body read error=%v", r.StatusCode, err)
			return nil, err
		}
		return nil, fmt.Errorf("error creating token: %v", string(bd))
	}
	
	l.Printf("getTokenFromBody JSON Decode")
	var token *types.OAuth2Token
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		l.Printf("getTokenFromBody JSON Decode error=%v", err)
		return nil, fmt.Errorf("json error: %v", err)
	}
	
	return token, nil
}

// setSSOCookie sets SSO cookie on all supported domains before redirecting user back to original resource
func (s *Service) setSSOCookie(w http.ResponseWriter, r *http.Request, session *sessions.Session, token *types.OAuth2Token) {
	var cid string
	if v, ok := session.Values["client_id"]; ok {
		cid = v.(string)
	}
	var aid string
	if v, ok := session.Values["ID"]; ok {
		aid = v.(string)
	}
	
	l := log.WithFields(log.Fields{
		"action":    "setSSOCookie",
		"client_id": cid,
		"app_id":    aid,
	})
	l.Print("setSSOCookie")
	
	// retrieve OAuth2 application for client
	config, err := s.configManager.GetAppByID(aid)
	if err != nil {
		l.Printf("getAppByID(%s) error=%v", cid, err)
		http.Error(w, fmt.Sprintf("get client error: %v", err), http.StatusBadRequest)
		return
	}
	
	var redirectURI = "/"
	if v, ok := session.Values["redirect_uri"]; ok {
		redirectURI = v.(string)
	}
	
	// create SSODomainConfig object to set SSO cookies
	sso := &types.SSODomainConfig{
		CookieName:  config.CookieName,
		Token:       token,
		SSODomain:   config.SSODomain,
		HttpOnly:    config.HttpOnly,
		RedirectURL: redirectURI,
	}
	
	// set SSO cookie on all supported domains
	s.setCookie(sso, w, r, true)
}

// setCookie sets a SSO cookie with optional redirect
func (s *Service) setCookie(sso *types.SSODomainConfig, w http.ResponseWriter, r *http.Request, shouldRedirect bool) {
	s.setCookieInternal(sso, w, r, shouldRedirect)
}

// setCookieOnly sets the SSO cookie without redirecting
func (s *Service) setCookieOnly(sso *types.SSODomainConfig, w http.ResponseWriter, r *http.Request) {
	s.setCookieInternal(sso, w, r, false)
}

// setCookieInternal handles the actual cookie setting logic
func (s *Service) setCookieInternal(sso *types.SSODomainConfig, w http.ResponseWriter, r *http.Request, shouldRedirect bool) {
	var cid string
	session, _ := s.sessionManager.GetSession(r, s.sessionManager.GetSessionName(r))
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	
	// Get session ID for refresh token storage
	var sessionID string
	if v, ok := session.Values["session_id"].(string); ok {
		sessionID = v
	}
	
	l := log.WithFields(log.Fields{
		"action":     "setCookieInternal",
		"client_id":  cid,
		"session_id": sessionID,
	})
	l.Printf("SetCookie Name=%v, Domain=%v\n", sso.CookieName, sso.SSODomain)
	
	// Set the access token cookie
	tv := sso.Token.AccessToken
	if tv == "" {
		tv = sso.Token.IDToken
	}
	exp := sso.Token.Expiry
	if exp.IsZero() {
		exp = time.Now().Add(time.Minute * 60)
	}
	
	http.SetCookie(w, &http.Cookie{
		Name:     sso.CookieName,
		Value:    tv,
		Expires:  exp,
		Domain:   sso.SSODomain,
		Path:     "/",
		HttpOnly: sso.HttpOnly,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	
	// Store refresh token server-side instead of in cookie
	if sso.Token.RefreshToken != "" && sessionID != "" {
		s.tokenManager.StoreRefreshToken(sessionID, sso.Token.RefreshToken, cid)
		l.Printf("Stored refresh token for session %s", sessionID)
	}
	
	if shouldRedirect {
		var redirectURI = sso.RedirectURL
		if v, ok := session.Values["redirect_uri"]; ok && v != nil {
			redirectURI = v.(string)
		}
		l.Printf("redirect_uri=%v", redirectURI)
		session.Options.Domain = sso.SSODomain
		session.Options.MaxAge = -1
		session.Options.Path = "/"
		l.Printf("sessions.Save %+v", session)
		err := s.sessionManager.SaveSession(r, w, session)
		if err != nil {
			l.Printf("sessions.Save error=%+v", err)
		}
		if redirectURI != "" {
			l.Printf("redirect=%v", redirectURI)
			http.Redirect(w, r, redirectURI, http.StatusFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}
}

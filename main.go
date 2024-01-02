package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"text/template"

	"github.com/google/uuid"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"

	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/boj/redistore.v1"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"

	_ "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	// store contains the session storage driver
	store sessions.Store
	// cfgs contains all supported OAuth2 application configurations
	cfgs []*OAuth2Config
	// ssokey contains the encryption key derived from session key
	ssokey []byte
)

// SSODomainConfig contains the configuration for SSO Cookies
type SSODomainConfig struct {
	Token       *OAuth2Token `json:"Token"`
	CookieName  string       `json:"CookieName"`
	HttpOnly    bool         `json:"HttpOnly"`
	RedirectURL string       `json:"RedirectURL"`
	SSODomain   string       `json:"SSODomain"`
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

func (o *OAuth2Token) OAuth2Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  o.AccessToken,
		TokenType:    o.TokenType,
		RefreshToken: o.RefreshToken,
		Expiry:       o.Expiry,
	}
}

// SessionState returns the client's session in a base64 encoded string
func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

// getRequestID retrieves a request_id for the request and creates one if it does not exist
func getRequestID(r *http.Request) string {
	l := log.WithFields(log.Fields{
		"action": "getRequestID",
	})
	l.Print("getRequestID")
	// check istio request headers
	if r.Header.Get("x-request-id") != "" {
		l.Printf("istio x-request-id=%s", r.Header.Get("x-request-id"))
		return r.Header.Get("x-request-id")
	}
	// check our session
	session, _ := store.Get(r, getSessionName(r))
	if v, ok := session.Values["request_id"].(string); ok {
		l.Printf("session request_id=%s", v)
		l.Printf("set x-request-id=%s", v)
		r.Header.Set("x-request-id", v)
		return v
	}
	// create a new
	uid := uuid.New()
	us := uid.String()
	l.Printf("new uuid=%s", us)
	l.Printf("set x-request-id=%s", us)
	r.Header.Set("x-request-id", us)
	return us
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("RefreshHandler")
	values := mux.Vars(r)
	cid := values["ID"]
	// retrieve OAuth2 application for client
	config, err := getAppByAppID(cid)
	if err != nil {
		http.Error(w, fmt.Sprintf("get client error: %v", err), http.StatusBadRequest)
		return
	}
	var token *oauth2.Token
	// retrieve refresh token from cookies
	refreshCookieName := config.CookieName + "_refresh"
	c, err := r.Cookie(refreshCookieName)
	if err != nil {
		log.Printf("RefreshHandler error: %v", err)
		http.Error(w, fmt.Sprintf("cookie error: %v", err), http.StatusBadRequest)
		return
	}
	// base64 decode the data
	strJson, err := base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		log.Printf("RefreshHandler error: %v", err)
		http.Error(w, fmt.Sprintf("base64 error: %v", err), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal([]byte(strJson), &token); err != nil {
		log.Printf("RefreshHandler error: %v", err)
		http.Error(w, fmt.Sprintf("json error: %v", err), http.StatusBadRequest)
		return
	}
	if token.RefreshToken != "" {
		newToken, refreshErr := config.OAuth2.TokenSource(r.Context(), token).Token()
		if refreshErr != nil {
			log.Printf("RefreshHandler error: %v", refreshErr)
			http.Error(w, fmt.Sprintf("refresh error: %v", refreshErr), http.StatusBadRequest)
			return
		}
		token = newToken
		nt := &OAuth2Token{
			AccessToken:  token.AccessToken,
			TokenType:    token.TokenType,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry,
		}
		sso := &SSODomainConfig{
			CookieName:  config.CookieName,
			Token:       nt,
			SSODomain:   config.SSODomain,
			HttpOnly:    config.HttpOnly,
			RedirectURL: "",
		}
		// set SSO cookie on all supported domains
		sso.SetCookie(w, r)
	} else {
		log.Printf("LoginHandler redirect ClientID=%v, redirect_uri=%v\n", cid, config.DefaultRedirectURI)
		http.Redirect(w, r, config.DefaultRedirectURI, http.StatusTemporaryRedirect)
	}
}

// LoginHandler handles calls to the root to either redirect to IDP or back to application after auth
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "LoginHandler",
	})
	l.Print("LoginHandler")
	config, err := configFromRequest(r)
	if err != nil {
		l.Print(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	l.Print("getSession")
	session, _ := store.Get(r, getSessionName(r))
	session.Options.MaxAge = 0
	session.Options.Domain = config.SSODomain
	session.Options.Path = "/"
	rid := getRequestID(r)
	l = l.WithFields(log.Fields{
		"request_id": rid,
		"action":     "LoginHandler",
	})
	session.Values["redirect_uri"] = config.DefaultRedirectURI
	session.Values["ID"] = config.ID
	session.Values["client_id"] = config.OAuth2.ClientID
	if r.FormValue("redirect") != "" {
		l.Printf("redirect_uri=%v", r.FormValue("redirect"))
		session.Values["redirect_uri"] = r.FormValue("redirect")
	}
	sessions.Save(r, w)
	u := config.OAuth2.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline)
	log.Printf("LoginHandler auth ClientID=%v, redirect_uri=%v, auth_code_url=%v\n", session.Values["ID"], session.Values["redirect_uri"], u)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func clearSession(session *sessions.Session, r *http.Request, w http.ResponseWriter) {
	var cid string
	if v, ok := session.Values["client_id"]; ok && v != nil {
		cid = v.(string)
	}
	var aid string
	if v, ok := session.Values["ID"]; ok && v != nil {
		aid = v.(string)
	}
	rid := getRequestID(r)
	l := log.WithFields(log.Fields{
		"action":     "clearSession",
		"client_id":  cid,
		"app_id":     aid,
		"request_id": rid,
	})
	l.Printf("clearSession")
	session.Options.MaxAge = -1
	sessions.Save(r, w)
}

// LogoutHandler handles session removal and redirect to IDP logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, getSessionName(r))
	var cid string
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	a, err := getAppByAppID(cid)
	if err != nil {
		// no app found just use default logout url
		a = cfgs[0]
	}
	// remove cookie and session
	// TODO: iterate through all SSO domains and remove cookies on all
	http.SetCookie(w, &http.Cookie{
		Name:     os.Getenv("SSO_COOKIE_NAME"),
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   os.Getenv("SSO_COOKIE_DOMAIN"),
		HttpOnly: a.HttpOnly,
		Secure:   true,
	})
	clearSession(session, r, w)
	// Redirect to IDP logout URL
	http.Redirect(w, r, a.LogoutURL, http.StatusTemporaryRedirect)
}

// createReq creates a new OAuth login request with the IDP
// defined for the user's session
func createReq(r *http.Request, session *sessions.Session) (*http.Response, error) {
	rid := getRequestID(r)
	l := log.WithFields(log.Fields{
		"action":     "createReq",
		"request_id": rid,
	})
	l.Printf("createReq %+v", session.Values)
	var cid string
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	l.Printf("getAppByAppID(%v)", cid)
	config, err := getAppByAppID(cid)
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

// setSSOCookie sets SSO cookie on all supported domains before redirecting user back to original resource
func setSSOCookie(w http.ResponseWriter, r *http.Request, session *sessions.Session, token *OAuth2Token) {
	var cid string
	if v, ok := session.Values["client_id"]; ok {
		cid = v.(string)
	}
	var aid string
	if v, ok := session.Values["ID"]; ok {
		aid = v.(string)
	}
	rid := getRequestID(r)
	l := log.WithFields(log.Fields{
		"action":     "setSSOCookie",
		"client_id":  cid,
		"request_id": rid,
		"app_id":     aid,
	})
	l.Print("setSSOCookie")
	// retrieve OAuth2 application for client
	config, err := getAppByAppID(aid)
	if err != nil {
		l.Printf("getAppByAppID(%s) error=%v", cid, err)
		http.Error(w, fmt.Sprintf("get client error: %v", err), http.StatusBadRequest)
		return
	}
	var redirectURI = "/"
	if v, ok := session.Values["redirect_uri"]; ok {
		redirectURI = v.(string)
	}
	// create SSODomainConfig object to set SSO cookies

	sso := &SSODomainConfig{
		CookieName:  config.CookieName,
		Token:       token,
		SSODomain:   config.SSODomain,
		HttpOnly:    config.HttpOnly,
		RedirectURL: redirectURI,
	}
	// set SSO cookie on all supported domains
	sso.SetCookie(w, r)
}

// SetCookie sets a SSO cookie on the current SSODomain object
// naively assuming it is running on the proper endpoint for the domain
func (sso *SSODomainConfig) SetCookie(w http.ResponseWriter, r *http.Request) {
	var cid string
	session, _ := store.Get(r, getSessionName(r))
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	rid := getRequestID(r)
	l := log.WithFields(log.Fields{
		"action":     "SetCookie",
		"client_id":  cid,
		"request_id": rid,
	})
	l.Printf("SetCookie Name=%v, Domain=%v\n", sso.CookieName, sso.SSODomain)
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
	if sso.Token.RefreshToken != "" {
		jd, err := json.Marshal(sso.Token)
		if err != nil {
			l.Printf("json.Marshal error: %v", err)
			http.Error(w, fmt.Sprintf("json error: %v", err), http.StatusBadRequest)
			return
		}
		// base64 encode the data
		jd = []byte(base64.StdEncoding.EncodeToString(jd))
		http.SetCookie(w, &http.Cookie{
			Name:     sso.CookieName + "_refresh",
			Value:    string(jd),
			Expires:  exp,
			Domain:   sso.SSODomain,
			Path:     "/",
			HttpOnly: sso.HttpOnly,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		})
	}
	var redirectURI = sso.RedirectURL
	if v, ok := session.Values["redirect_uri"]; ok && v != nil {
		redirectURI = v.(string)
	}
	l.Printf("redirect_uri=%v", redirectURI)
	session.Options.Domain = sso.SSODomain
	session.Options.MaxAge = -1
	session.Options.Path = "/"
	l.Printf("sessions.Save %+v", session)
	err := sessions.Save(r, w)
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

// getTokenFromBody retrieves the OAuth2 token from the HTTP response body
func getTokenFromBody(r *http.Response) (*OAuth2Token, error) {
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
	var token *OAuth2Token
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		l.Printf("getTokenFromBody JSON Decode error=%v", err)
		return nil, fmt.Errorf("json error: %v", err)
	}
	return token, nil
}

func appIDs() []string {
	var ids []string
	for _, v := range cfgs {
		ids = append(ids, v.ID)
	}
	return ids
}

func appIDFromCookies(r *http.Request) string {
	for _, c := range r.Cookies() {
		for _, a := range appIDs() {
			if c.Name == a {
				return a
			}
		}
	}
	return ""
}

func getSessionName(r *http.Request) string {
	vars := mux.Vars(r)
	sessionName := vars["ID"]
	if sessionName == "" {
		sessionName = appIDFromCookies(r)
	}
	if sessionName == "" {
		sessionName = "session"
	}
	l := log.WithFields(log.Fields{
		"action": "getSessionName",
	})
	l.Printf("session_name=%v", sessionName)
	return sessionName
}

// CallbackHandler handles responses from IDP
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	rid := getRequestID(r)
	l := log.WithFields(log.Fields{
		"action":     "CallbackHandler",
		"request_id": rid,
	})
	l.Print("CallbackHandler")
	session, err := store.Get(r, getSessionName(r))
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
	l = l.WithFields(log.Fields{
		"action":     "CallbackHandler",
		"request_id": rid,
	})
	l.Printf("check callback state")
	if r.FormValue("state") != SessionState(session) {
		l.Println("invalid callback state")
		clearSession(session, r, w)
		http.Redirect(w, r, "/403?request_id="+rid+"&redirect="+rurl, http.StatusTemporaryRedirect)
		return
	}
	l.Printf("createReq")
	resp, err := createReq(r, session)
	if err != nil {
		l.Printf("createReq error: %v\n", err)
		clearSession(session, r, w)
		http.Redirect(w, r, "/403?request_id="+rid+"&redirect="+rurl, http.StatusTemporaryRedirect)
		return
	}
	l.Printf("getTokenFromBody")
	token, terr := getTokenFromBody(resp)
	if terr != nil || token == nil || (token.AccessToken == "" && token.IDToken == "") {
		if terr != nil {
			l.Printf("getTokenFromBody error: %v\n", terr)
		}
		if token == nil {
			l.Printf("getTokenFromBody token is nil\n")
		} else if token.AccessToken == "" || token.IDToken == "" {
			l.Printf("getTokenFromBody token is invalid\n")
		}
		clearSession(session, r, w)
		http.Redirect(w, r, "/403?request_id="+rid+"&redirect="+rurl, http.StatusTemporaryRedirect)
		return
	} else if token == nil {
		l.Print("token nil, redirecting /403")
		clearSession(session, r, w)
		http.Redirect(w, r, "/403?request_id="+rid+"&redirect="+rurl, http.StatusTemporaryRedirect)
		return
	}
	l.Printf("setSSOCookie")
	setSSOCookie(w, r, session, token)
}

// getAppByAppID retrieves a configured OAuth2 application by the ClientID
// for configurations which have multiple ClientIDs, a separate `id` field enables
// selecting a specific configuration.
func getAppByAppID(i string) (*OAuth2Config, error) {
	if i == "" {
		return nil, errors.New("client not provided")
	}
	log.Printf("getAppByAppID request %v\n", i)
	for _, v := range cfgs {
		if v.ID == i {
			log.Printf("getAppByAppID found %v: %+v\n", v.ID, logConfig(v))
			// we found the app config - if there is a .Vault field, we need to
			// retrieve the secret from Vault
			if v.Vault != nil && v.Vault.Path != "" {
				log.Printf("getAppByAppID vault %+v\n", v.Vault)
				// we have a vault config, so we need to retrieve the secret
				// from Vault
				cfg, err := v.Vault.AuthAndGetConfig()
				if err != nil {
					log.Printf("getAppByAppID vault error: %v\n", err)
					return nil, err
				}
				return cfg, nil
			}
			return v, nil
		}
	}
	return nil, errors.New("client not found")
}

func logConfig(c *OAuth2Config) OAuth2Config {
	return OAuth2Config{
		ID:                 c.ID,
		OAuth2:             c.OAuth2,
		LogoutURL:          c.LogoutURL,
		CookieName:         c.CookieName,
		DefaultRedirectURI: c.DefaultRedirectURI,
		HttpOnly:           c.HttpOnly,
		SSODomain:          c.SSODomain,
	}
}

// configFromRequest retrieves the OAuth2 application configuration
// from the HTTP request, assuming ClientID was provided in the URL.
// If ClientID is not provided, defaults to first application
func configFromRequest(r *http.Request) (*OAuth2Config, error) {
	v := mux.Vars(r)
	session, _ := store.Get(r, getSessionName(r))
	rid := getRequestID(r)
	var aid string
	if v, ok := session.Values["ID"]; ok {
		aid = v.(string)
	}
	if aid == "" && v["ID"] != "" {
		aid = v["ID"]
	}
	l := log.WithFields(log.Fields{
		"action":     "configFromRequest",
		"request_id": rid,
		"app_id":     aid,
	})
	l.Println("configFromRequest")
	var config *OAuth2Config
	if v["ID"] != "" && rid == "" {
		l.Printf("getAppByAppID path id=%v", v["ID"])
		// user defined app id and no existing request id
		l.Printf("ClientID=%s", v["ID"])
		var e error
		config, e = getAppByAppID(v["ID"])
		if e != nil {
			l.Printf("getAppByAppID path id=%v error=%v", v["ID"], e)
			return config, e
		}
		l.Printf("appID found %+v\n", logConfig(config))
	} else if rid != "" {
		l.Printf("getAppByAppID request id=%v", rid)
		// request id already defined
		var e error
		config, e = getAppByAppID(aid)
		if e != nil {
			l.Printf("getAppByAppID request id=%v error=%v", rid, e)
			return config, e
		}
		l.Printf("appID with request_id found %+v\n", logConfig(config))
	} else {
		config = cfgs[0]
		l.Printf("default appID %+v\n", logConfig(config))
	}
	return config, nil
}

// readCfgs reads the OAuth2 application configuration file
// and parses into object in memory
func readCfgs(f string) error {
	l := log.WithFields(log.Fields{
		"action": "readCfgs",
	})
	l.Printf("readCfgs")
	bd, berr := os.ReadFile(f)
	if berr != nil {
		l.Printf("ReadFile error=%v", berr)
		return berr
	}
	bd = []byte(os.ExpandEnv(string(bd)))
	type cfg struct {
		Configs []*OAuth2Config `json:"configs"`
	}
	var c cfg
	jerr := json.Unmarshal(bd, &c)
	if jerr != nil {
		l.Printf("json.Unmarshal error=%v", jerr)
		return jerr
	}
	cfgs = c.Configs
	if len(cfgs) < 1 {
		l.Printf("default oauth2 provider required")
		return errors.New("default oauth2 provider required")
	}
	l.Printf("%v configs loaded", len(cfgs))
	return nil
}

// redisStore instantiates a redis session store
func redisStore() {
	s, err := redistore.NewRediStore(100, "tcp", os.Getenv("SESSION_STORE_REDIS"), "", []byte(os.Getenv("SESSION_KEY")), nil)
	if err != nil {
		log.Fatal(err)
	}
	store = s
}

// fsStore instantiates a filesystem session store
func fsStore() {
	f := sessions.NewFilesystemStore("", []byte(os.Getenv("SESSION_KEY")), nil)
	f.MaxLength(0)
	store = f
}

// cookieStore instantiates a cookie session store
func cookieStore() {
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
}

func HandleUnauthorized(w http.ResponseWriter, r *http.Request) {
	rid := r.FormValue("request_id")
	ruri := r.FormValue("redirect")
	l := log.WithFields(log.Fields{
		"action":       "HandleUnauthorized",
		"request_id":   rid,
		"redirect_uri": ruri,
	})
	l.Print("HandleUnauthorized")
	lp := filepath.Join("web", "403.html")
	tmpl, _ := template.ParseFiles(lp)
	data := make(map[string]string)
	if rid != "" {
		data["request_id"] = rid
	}
	if ruri != "" {
		data["redirect_uri"] = ruri
	}
	tmpl.ExecuteTemplate(w, "403", data)
}

func init() {
	// parse configuration
	cerr := readCfgs(os.Getenv("OAUTH2_CONFIG_FILE"))
	if cerr != nil {
		log.Fatal(cerr)
	}
	// configure session storage driver
	switch os.Getenv("SESSION_STORE_TYPE") {
	case "redis":
		redisStore()
	case "filesystem":
		fsStore()
	case "cookie":
		cookieStore()
	default:
		cookieStore()
	}
	gob.Register(&oauth2.Token{})
	// Create ssokey from the first 32 bytes from SESSION_KEY
	if len(os.Getenv("SESSION_KEY")) < 32 {
		log.Fatal("SESSION_KEY must be 32 bytes or larger")
	}
	ssokey = []byte(os.Getenv("SESSION_KEY")[:32])
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", LoginHandler)
	r.HandleFunc("/refresh/{ID}", RefreshHandler)
	r.HandleFunc("/oauth2/{ID}", LoginHandler)
	r.HandleFunc("/logout/{ID}", LogoutHandler)
	r.HandleFunc("/callback", CallbackHandler)
	r.HandleFunc("/callback/{ID}", CallbackHandler)
	r.HandleFunc("/403", HandleUnauthorized)
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            false,
	})
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), c.Handler(r)))
}

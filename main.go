package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

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
	Token       *oauth2.Token `json:"Token"`
	CookieName  string        `json:"CookieName"`
	RedirectURL string        `json:"RedirectURL"`
	SSODomain   string        `json:"SSODomain"`
}

// OAuth2Config contains the base OAuth2 config as well as additional information for session
type OAuth2Config struct {
	OAuth2             *oauth2.Config `json:"OAuth2"`
	ID                 string         `json:"ID"`
	LogoutURL          string         `json:"LogoutURL"`
	CookieName         string         `json:"CookieName"`
	DefaultRedirectURI string         `json:"DefaultRedirectURI"`
	SSODomain          string         `json:"SSODomain"`
}

// SessionState returns the client's session in a base64 encoded string
func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

// LoginHandler handles calls to the root to either redirect to IDP or back to application after auth
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("LoginHandler")
	config, err := configFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := store.Get(r, "session")
	session.Values["redirect_uri"] = config.DefaultRedirectURI
	session.Values["ID"] = config.ID
	log.Printf("sessions.Save: %+v", session.Values)
	sessions.Save(r, w)
	var token *oauth2.Token
	if r.FormValue("redirect") != "" {
		session.Values["redirect_uri"] = r.FormValue("redirect")
		sessions.Save(r, w)
	} else {
		if v, ok := session.Values["token"]; ok {
			token = v.(*oauth2.Token)
		}
	}
	// if token is empty redirect to IDP, otherwise redirect back to application
	if token == nil {
		u := config.OAuth2.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline)
		log.Printf("LoginHandler auth ClientID=%v, redirect_uri=%v, auth_code_url=%v\n", session.Values["ID"], session.Values["redirect_uri"], u)
		http.Redirect(w, r, u, http.StatusTemporaryRedirect)
	} else {
		log.Printf("LoginHandler redirect ClientID=%v, redirect_uri=%v\n", session.Values["ID"], config.DefaultRedirectURI)
		http.Redirect(w, r, config.DefaultRedirectURI, http.StatusTemporaryRedirect)
	}
}

// LogoutHandler handles session removal and redirect to IDP logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	var cid string
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	// remove cookie and session
	// TODO: iterate through all SSO domains and remove cookies on all
	session.Options.MaxAge = -1
	http.SetCookie(w, &http.Cookie{
		Name:     os.Getenv("SSO_COOKIE_NAME"),
		Value:    "",
		MaxAge:   -1,
		Domain:   os.Getenv("SSO_COOKIE_DOMAIN"),
		HttpOnly: true,
		//Secure:   true,
		Secure: false,
	})
	sessions.Save(r, w)
	a, err := getAppByClientID(cid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Redirect to IDP logout URL
	http.Redirect(w, r, a.LogoutURL, http.StatusTemporaryRedirect)
}

// createReq creates a new OAuth login request with the IDP
// defined for the user's session
func createReq(r *http.Request, session *sessions.Session) (*http.Response, error) {
	log.Printf("createReq %+v", session.Values)
	var cid string
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	config, err := getAppByClientID(cid)
	if err != nil {
		return nil, err
	}
	// Create new OAuth login request
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", config.OAuth2.ClientID)
	form.Set("client_secret", config.OAuth2.ClientSecret)
	form.Set("code", r.FormValue("code"))
	form.Set("scope", strings.Join(config.OAuth2.Scopes, ","))
	form.Set("redirect_uri", config.OAuth2.RedirectURL)
	log.Printf("Login client_id=%v, scope=%v, redirect_uri=%v token_url=%v\n",
		config.OAuth2.ClientID,
		strings.Join(config.OAuth2.Scopes, ","),
		config.OAuth2.RedirectURL,
		config.OAuth2.Endpoint.TokenURL,
	)
	req, err := http.NewRequest(http.MethodPost, config.OAuth2.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

// setSSOCookie sets SSO cookie on all supported domains before redirecting user back to original resource
func setSSOCookie(w http.ResponseWriter, r *http.Request, session *sessions.Session, token *oauth2.Token) {
	var cid string
	// retrieve ClientID from session
	if v, ok := session.Values["ID"]; ok {
		cid = v.(string)
	}
	// retrieve OAuth2 application for client
	config, err := getAppByClientID(cid)
	if err != nil {
		http.Error(w, fmt.Sprintf("get client error: %v", err), http.StatusBadRequest)
		return
	}
	var redirectURI = "/"
	if v, ok := session.Values["redirect_uri"]; ok {
		redirectURI = v.(string)
	}
	session.Values["redirect_uri"] = nil
	sessions.Save(r, w)
	// create SSODomainConfig object to set SSO cookies
	sso := &SSODomainConfig{
		CookieName:  config.CookieName,
		Token:       token,
		SSODomain:   config.SSODomain,
		RedirectURL: redirectURI,
	}
	// set SSO cookie on all supported domains
	sso.SetCookie(w, r)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// SetCookie sets a SSO cookie on the current SSODomain object
// naively assuming it is running on the proper endpoint for the domain
func (sso *SSODomainConfig) SetCookie(w http.ResponseWriter, r *http.Request) {
	log.Printf("SetCookie Name=%v, Domain=%v\n", sso.CookieName, sso.SSODomain)
	http.SetCookie(w, &http.Cookie{
		Name:     sso.CookieName,
		Value:    sso.Token.AccessToken,
		Expires:  time.Now().Add(time.Minute * 60),
		Domain:   sso.SSODomain,
		HttpOnly: true,
		Secure:   true,
	})
}

// getTokenFromBody retrieves the OAuth2 token from the HTTP response body
func getTokenFromBody(r *http.Response) (*oauth2.Token, error) {
	defer r.Body.Close()
	if r.StatusCode >= 400 {
		bd, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("error creating token: %v", string(bd))
	}
	var token oauth2.Token
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("json error: %v", err)
	}
	return &token, nil
}

// CallbackHandler handles responses from IDP
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if r.FormValue("state") != SessionState(session) {
		log.Println("invalid callback state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	resp, err := createReq(r, session)
	if err != nil {
		log.Printf("createReq error: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	token, terr := getTokenFromBody(resp)
	if terr != nil {
		log.Printf("getTokenFromBody error: %v\n", terr)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	session.Values["token"] = &token
	session.Save(r, w)
	setSSOCookie(w, r, session, token)
}

// getAppByClientID retrieves a configured OAuth2 application by the ClientID
// for configurations which have multiple ClientIDs, a separate `id` field enables
// selecting a specific configuration.
func getAppByClientID(i string) (*OAuth2Config, error) {
	log.Printf("getAppByClientID %v\n", i)
	for _, v := range cfgs {
		if v.ID == i {
			log.Printf("getAppByClientID %v: %+v\n", v.ID, v.OAuth2)
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
		SSODomain:          c.SSODomain,
	}
}

// configFromRequest retrieves the OAuth2 application configuration
// from the HTTP request, assuming ClientID was provided in the URL.
// If ClientID is not provided, defaults to first application
func configFromRequest(r *http.Request) (*OAuth2Config, error) {
	v := mux.Vars(r)
	log.Println("configFromRequest")
	var config *OAuth2Config
	if v["ClientID"] != "" {
		log.Printf("configFromRequest ClientID=%s", v["ClientID"])
		var e error
		config, e = getAppByClientID(v["ClientID"])
		if e != nil {
			return config, e
		}
		log.Printf("configFromRequest %+v\n", logConfig(config))
	} else {
		config = cfgs[0]
		log.Printf("configFromRequest default %+v\n", logConfig(config))
	}
	return config, nil
}

// readCfgs reads the OAuth2 application configuration file
// and parses into object in memory
func readCfgs(f string) error {
	bd, berr := ioutil.ReadFile(f)
	if berr != nil {
		return berr
	}
	jerr := json.Unmarshal(bd, &cfgs)
	if jerr != nil {
		return jerr
	}
	if len(cfgs) < 1 {
		return errors.New("default oauth2 provider required")
	}
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
	r.HandleFunc("/oauth2/{ClientID}", LoginHandler)
	r.HandleFunc("/logout", LogoutHandler)
	r.HandleFunc("/callback", CallbackHandler)
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), r))
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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

// SSODomain contains the configuration for a SSO domain
type SSODomain struct {
	Domain   string `json:"Domain"`
	Endpoint string `json:"Endpoint"`
}

// SSODomainConfig contains the configuration for SSO Cookies
type SSODomainConfig struct {
	Token       *oauth2.Token `json:"Token"`
	CookieName  string        `json:"CookieName"`
	RedirectURL string        `json:"RedirectURL"`
	SSODomains  []SSODomain   `json:"SSODomains"`
}

// OAuth2Config contains the base OAuth2 config as well as additional information for session
type OAuth2Config struct {
	OAuth2             *oauth2.Config `json:"OAuth2"`
	LogoutURL          string         `json:"LogoutURL"`
	CookieName         string         `json:"CookieName"`
	DefaultRedirectURI string         `json:"DefaultRedirectURI"`
	SSODomains         []SSODomain    `json:"SSODomains"`
}

// SessionState returns the client's session in a base64 encoded string
func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

// LoginHandler handles calls to the root to either redirect to IDP or back to application after auth
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	config, err := configFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := store.Get(r, "session")
	session.Values["redirect_uri"] = config.DefaultRedirectURI
	session.Values["ClientID"] = config.OAuth2.ClientID
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
		http.Redirect(w, r, config.OAuth2.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline), http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, config.DefaultRedirectURI, http.StatusTemporaryRedirect)
	}
}

// LogoutHandler handles session removal and redirect to IDP logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	var cid string
	if v, ok := session.Values["ClientID"]; ok {
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
		Secure:   true,
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
	var cid string
	if v, ok := session.Values["ClientID"]; ok {
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
	form.Set("redirect_uri", config.OAuth2.RedirectURL)
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

// encrypt is an aes encryption helper function
func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

// decrypt is an aes decription helper function
func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// decodeSSOConfig decodes the SSO configuration parameter to SSODomainConfig object
func decodeSSOConfig(s string) (SSODomainConfig, error) {
	var sso SSODomainConfig
	bd, err := decrypt(ssokey, []byte(s))
	if err != nil {
		return sso, err
	}
	jerr := json.Unmarshal(bd, &sso)
	if jerr != nil {
		return sso, jerr
	}
	return sso, nil
}

// encodeSSOConfig encodes a SSODomainConfig object into a string parameter
// that can be passed between SSO domains to properly set cookies
func encodeSSOConfig(sso *SSODomainConfig) (string, error) {
	var s string
	bd, jerr := json.Marshal(&sso)
	if jerr != nil {
		return s, jerr
	}
	//s = base64.StdEncoding.EncodeToString(bd)
	ed, err := encrypt(ssokey, bd)
	if err != nil {
		return s, err
	}
	s = string(ed)
	return s, nil
}

// setSSOCookies iterates through all configured SSO domains / endpoints and sets SSO
// cookie on all supported domains before redirecting user back to original resource
func setSSOCookies(w http.ResponseWriter, r *http.Request, session *sessions.Session, token *oauth2.Token) {
	var cid string
	// retrieve ClientID from session
	if v, ok := session.Values["ClientID"]; ok {
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
		SSODomains:  config.SSODomains,
		RedirectURL: redirectURI,
	}
	// set SSO cookie on all supported domains
	sso.SetCookies(w, r)
}

// SetCookie sets a SSO cookie on the current SSODomain object
// naively assuming it is running on the proper endpoint for the domain
func (sso *SSODomainConfig) SetCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sso.CookieName,
		Value:    sso.Token.AccessToken,
		Expires:  time.Now().Add(time.Minute * 60),
		Domain:   sso.SSODomains[0].Domain,
		HttpOnly: true,
		Secure:   true,
	})
}

// SetCookies iterates through SSO Domains and sets cookies on all domains
// This assumes the configured endpoints are operational, and with 307 the user
// to that endpoint. CNAME endpoints back to this API ingress
func (sso *SSODomainConfig) SetCookies(w http.ResponseWriter, r *http.Request) {
	var nsso []SSODomain
	// if no resources remain in list, redirect back to root to be sent to application
	if len(sso.SSODomains) == 0 {
		http.Redirect(w, r, sso.RedirectURL, http.StatusTemporaryRedirect)
		return
	} else if len(sso.SSODomains) > 1 {
		// if resources do remain in list, pop first off and update list
		nsso = sso.SSODomains[1:len(sso.SSODomains)]
	}
	sso.SetCookie(w, r)
	// Create new SSO domain config list object
	nssod := &SSODomainConfig{
		CookieName:  sso.CookieName,
		Token:       sso.Token,
		RedirectURL: sso.RedirectURL,
		SSODomains:  nsso,
	}
	// encode new sso object to Base64 string
	cd, cerr := encodeSSOConfig(nssod)
	if cerr != nil {
		http.Error(w, cerr.Error(), http.StatusBadRequest)
		return
	}
	// if Endpoint is nil, assume single domain configuration
	// and redirect back to original URL
	if sso.SSODomains[0].Endpoint == "" {
		http.Redirect(w, r, sso.RedirectURL, http.StatusTemporaryRedirect)
		return
	}
	u, uerr := url.Parse(sso.SSODomains[0].Endpoint)
	if uerr != nil {
		http.Error(w, uerr.Error(), http.StatusBadRequest)
		return
	}
	// encode URL with sso config
	form := url.Values{}
	form.Add("sso", cd)
	fd := form.Encode()
	u.RawQuery = fd
	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

// SSOHandler handles the request to iterate through SSO domains and set cookie
func SSOHandler(w http.ResponseWriter, r *http.Request) {
	// get sso list from query string
	sso := r.FormValue("sso")
	var ssod SSODomainConfig
	// decode base64 sso configuration
	if sso != "" {
		var e error
		ssod, e = decodeSSOConfig(sso)
		if e != nil {
			http.Error(w, e.Error(), http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "sso configuration required", http.StatusBadRequest)
		return
	}
	ssod.SetCookies(w, r)
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
		http.Error(w, "invalid callback state", http.StatusBadRequest)
		return
	}
	resp, err := createReq(r, session)
	if err != nil {
		http.Error(w, fmt.Sprintf("createReq error: %v", err), http.StatusBadRequest)
		return
	}
	token, terr := getTokenFromBody(resp)
	if terr != nil {
		http.Error(w, fmt.Sprintf("getTokenFromBody error: %v", terr), http.StatusBadRequest)
		return
	}
	session.Values["token"] = &token
	session.Save(r, w)
	setSSOCookies(w, r, session, token)
	//http.Redirect(w, r, redirectURI, http.StatusFound)
}

// getAppByClientID retrieves a configured OAuth2 application by the ClientID
func getAppByClientID(i string) (*OAuth2Config, error) {
	for _, v := range cfgs {
		if v.OAuth2.ClientID == i {
			return v, nil
		}
	}
	return nil, errors.New("client not found")
}

// configFromRequest retrieves the OAuth2 application configuration
// from the HTTP request, assuming ClientID was provided in the URL.
// If ClientID is not provided, defaults to first application
func configFromRequest(r *http.Request) (*OAuth2Config, error) {
	v := mux.Vars(r)
	var config *OAuth2Config
	if v["ClientID"] != "" {
		var e error
		config, e = getAppByClientID(v["ClientID"])
		if e != nil {
			return config, e
		}
	} else {
		config = cfgs[0]
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
	for _, v := range cfgs {
		v.OAuth2.Scopes = []string{"User.Read"}
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
	r.HandleFunc("/sso", SSOHandler)
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), r))
}

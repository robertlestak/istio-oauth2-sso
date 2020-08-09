package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
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
	store sessions.Store
	cfgs  []*OAuth2Config
)

// OAuth2Config contains the base OAuth2 config as well as additional information for session
type OAuth2Config struct {
	OAuth2             *oauth2.Config `json:"OAuth2"`
	LogoutURL          string         `json:"LogoutURL"`
	CookieName         string         `json:"CookieName"`
	DefaultRedirectURI string         `json:"DefaultRedirectURI"`
	SSODomains         []string       `json:"SSODomains"`
}

// SessionState returns the client's session in a base64 encoded string
func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

// IndexHandler handles calls to the root to either redirect to IDP or back to application after auth
func IndexHandler(w http.ResponseWriter, r *http.Request) {
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
	session.Options.MaxAge = -1
	http.SetCookie(w, &http.Cookie{
		Name:   os.Getenv("SSO_COOKIE_NAME"),
		Value:  "",
		MaxAge: -1,
		Domain: os.Getenv("SSO_COOKIE_DOMAIN"),
	})
	sessions.Save(r, w)
	a, err := getAppByClientID(cid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, a.LogoutURL, http.StatusTemporaryRedirect)
}

func createReq(r *http.Request, session *sessions.Session) (*http.Response, error) {
	var cid string
	if v, ok := session.Values["ClientID"]; ok {
		cid = v.(string)
	}
	config, err := getAppByClientID(cid)
	if err != nil {
		return nil, err
	}
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

func setSSOCookies(w http.ResponseWriter, session *sessions.Session, token *oauth2.Token) {
	var cid string
	if v, ok := session.Values["ClientID"]; ok {
		cid = v.(string)
	}
	config, err := getAppByClientID(cid)
	if err != nil {
		http.Error(w, fmt.Sprintf("get client error: %v", err), http.StatusBadRequest)
		return
	}
	// Placeholder until true cross-domain agent created
	for _, v := range config.SSODomains {
		http.SetCookie(w, &http.Cookie{
			Name:    config.CookieName,
			Value:   token.AccessToken,
			Expires: time.Now().Add(time.Minute * 60),
			Domain:  v,
		})
	}
}

func getTokenFromBody(resp *http.Response) (*oauth2.Token, error) {
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bd, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("error creating token: %v", string(bd))
	}
	var token oauth2.Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
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
	var redirectURI = "/"
	if v, ok := session.Values["redirect_uri"]; ok {
		redirectURI = v.(string)
	}
	session.Values["redirect_uri"] = nil
	session.Save(r, w)
	setSSOCookies(w, session, token)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func getAppByClientID(i string) (*OAuth2Config, error) {
	for _, v := range cfgs {
		if v.OAuth2.ClientID == i {
			return v, nil
		}
	}
	return nil, errors.New("client not found")
}

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

func redisStore() {
	s, err := redistore.NewRediStore(100, "tcp", os.Getenv("SESSION_STORE_REDIS"), "", []byte(os.Getenv("SESSION_KEY")), nil)
	if err != nil {
		log.Fatal(err)
	}
	store = s
}

func fsStore() {
	f := sessions.NewFilesystemStore("", []byte(os.Getenv("SESSION_KEY")), nil)
	f.MaxLength(0)
	store = f
}

func cookieStore() {
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
}

func init() {
	cerr := readCfgs(os.Getenv("OAUTH2_CONFIG_FILE"))
	if cerr != nil {
		log.Fatal(cerr)
	}
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
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", IndexHandler)
	r.HandleFunc("/oauth2/{ClientID}", IndexHandler)
	r.HandleFunc("/logout", LogoutHandler)
	r.HandleFunc("/callback", CallbackHandler)
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), r))
}

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"

	_ "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	clientID    string = os.Getenv("CLIENT_ID")
	clientSec   string = os.Getenv("CLIENT_SECRET")
	config      *oauth2.Config
	redirectURI string = os.Getenv("CALLBACK_URL")
	store       sessions.Store
)

// SessionState returns the client's session in a base64 encoded string
func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

// IndexHandler handles calls to the root to either redirect to IDP or back to application after auth
func IndexHandler(w http.ResponseWriter, req *http.Request) {
	session, _ := store.Get(req, "session")
	session.Values["redirect_uri"] = os.Getenv("DEFAULT_REDIRECT_URI")
	sessions.Save(req, w)
	var token *oauth2.Token
	if req.FormValue("redirect") != "" {
		session.Values["redirect_uri"] = req.FormValue("redirect")
		sessions.Save(req, w)
	} else {
		if v, ok := session.Values["token"]; ok {
			token = v.(*oauth2.Token)
		}
	}
	if token == nil {
		http.Redirect(w, req, config.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline), http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, req, os.Getenv("DEFAULT_REDIRECT_URI"), http.StatusTemporaryRedirect)
	}
}

// LogoutHandler handles session removal and redirect to IDP logout
func LogoutHandler(w http.ResponseWriter, req *http.Request) {
	session, _ := store.Get(req, "session")
	session.Options.MaxAge = -1
	http.SetCookie(w, &http.Cookie{
		Name:   os.Getenv("SSO_COOKIE_NAME"),
		Value:  "",
		MaxAge: -1,
		Domain: os.Getenv("SSO_COOKIE_DOMAIN"),
	})
	sessions.Save(req, w)
	http.Redirect(w, req, os.Getenv("LOGOUT_URL"), http.StatusTemporaryRedirect)
}

func createReq(r *http.Request) (*http.Response, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSec)
	form.Set("code", r.FormValue("code"))
	form.Set("redirect_uri", redirectURI)
	req, err := http.NewRequest(http.MethodPost, config.Endpoint.TokenURL, strings.NewReader(form.Encode()))
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

// CallbackHandler handles responses from IDP
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if r.FormValue("state") != SessionState(session) {
		http.Error(w, "invalid callback state", http.StatusBadRequest)
		return
	}
	resp, err := createReq(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("createReq error: %v", err), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bd, _ := ioutil.ReadAll(resp.Body)
		http.Error(w, fmt.Sprintf("error creating token: %v - %v", err, string(bd)), http.StatusBadRequest)
		return
	}
	var token oauth2.Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		http.Error(w, fmt.Sprintf("json error: %v", err), http.StatusBadRequest)
		return
	}
	session.Values["token"] = &token
	if err := sessions.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("session error: %v", err), http.StatusBadRequest)
		return
	}
	var redirectURI = "/"
	if v, ok := session.Values["redirect_uri"]; ok {
		redirectURI = v.(string)
	}
	session.Values["redirect_uri"] = nil
	session.Save(r, w)
	http.SetCookie(w, &http.Cookie{
		Name:    os.Getenv("SSO_COOKIE_NAME"),
		Value:   token.AccessToken,
		Expires: time.Now().Add(time.Minute * 60),
		Domain:  os.Getenv("SSO_COOKIE_DOMAIN"),
	})
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func init() {
	fsStore := sessions.NewFilesystemStore("", []byte(os.Getenv("SESSION_KEY")), nil)
	fsStore.MaxLength(0)
	store = fsStore
	config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: "",
		RedirectURL:  redirectURI,

		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("AUTH_URL"),
			TokenURL: os.Getenv("TOKEN_URL"),
		},
		Scopes: []string{"User.Read"},
	}
	gob.Register(&oauth2.Token{})
}

func main() {
	http.HandleFunc("/", IndexHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/callback", CallbackHandler)
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))
}

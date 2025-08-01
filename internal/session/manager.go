package session

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"gopkg.in/boj/redistore.v1"
	log "github.com/sirupsen/logrus"
)

// Manager handles session storage and management
type Manager struct {
	store sessions.Store
}

// NewManager creates a new session manager
func NewManager() *Manager {
	return &Manager{}
}

// InitializeStore configures the session storage driver
func (m *Manager) InitializeStore(storeType string) error {
	switch storeType {
	case "redis":
		return m.initRedisStore()
	case "filesystem":
		return m.initFSStore()
	case "cookie":
		return m.initCookieStore()
	default:
		return m.initCookieStore()
	}
}

// initRedisStore instantiates a redis session store
func (m *Manager) initRedisStore() error {
	s, err := redistore.NewRediStore(100, "tcp", os.Getenv("SESSION_STORE_REDIS"), "", []byte(os.Getenv("SESSION_KEY")), nil)
	if err != nil {
		return err
	}
	m.store = s
	return nil
}

// initFSStore instantiates a filesystem session store
func (m *Manager) initFSStore() error {
	f := sessions.NewFilesystemStore("", []byte(os.Getenv("SESSION_KEY")), nil)
	f.MaxLength(0)
	m.store = f
	return nil
}

// initCookieStore instantiates a cookie session store
func (m *Manager) initCookieStore() error {
	m.store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
	return nil
}

// GetSession retrieves a session by name
func (m *Manager) GetSession(r *http.Request, name string) (*sessions.Session, error) {
	return m.store.Get(r, name)
}

// SaveSession saves a session
func (m *Manager) SaveSession(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	return sessions.Save(r, w)
}

// GetSessionName determines the session name from the request
func (m *Manager) GetSessionName(r *http.Request) string {
	vars := mux.Vars(r)
	sessionName := vars["ID"]
	if sessionName == "" {
		sessionName = m.getAppIDFromCookies(r)
	}
	if sessionName == "" {
		sessionName = "session"
	}
	
	l := log.WithFields(log.Fields{
		"action": "GetSessionName",
	})
	l.Printf("session_name=%v", sessionName)
	return sessionName
}

// getAppIDFromCookies tries to determine app ID from cookies
func (m *Manager) getAppIDFromCookies(r *http.Request) string {
	// This would need to be implemented based on your app ID logic
	// For now, return empty string
	return ""
}

// GetSessionIDFromRequest extracts session ID from request
func (m *Manager) GetSessionIDFromRequest(r *http.Request) string {
	// Try to get session ID from a dedicated cookie
	if cookie, err := r.Cookie("oauth2_session_id"); err == nil {
		return cookie.Value
	}
	
	// Fallback: try to get from session store
	session, _ := m.GetSession(r, m.GetSessionName(r))
	if sessionID, ok := session.Values["session_id"].(string); ok {
		return sessionID
	}
	
	return ""
}

// SessionState returns the client's session in a base64 encoded string
func (m *Manager) SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

// ClearSession clears a session
func (m *Manager) ClearSession(session *sessions.Session, r *http.Request, w http.ResponseWriter) {
	var cid string
	if v, ok := session.Values["client_id"]; ok && v != nil {
		cid = v.(string)
	}
	var aid string
	if v, ok := session.Values["ID"]; ok && v != nil {
		aid = v.(string)
	}
	
	l := log.WithFields(log.Fields{
		"action":    "ClearSession",
		"client_id": cid,
		"app_id":    aid,
	})
	l.Printf("ClearSession")
	session.Options.MaxAge = -1
	sessions.Save(r, w)
}

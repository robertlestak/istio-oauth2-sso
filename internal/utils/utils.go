package utils

import (
	"net/http"
	"path/filepath"
	"text/template"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// GetRequestID retrieves a request_id for the request and creates one if it does not exist
func GetRequestID(r *http.Request) string {
	l := log.WithFields(log.Fields{
		"action": "GetRequestID",
	})
	l.Print("GetRequestID")
	
	// check istio request headers
	if r.Header.Get("x-request-id") != "" {
		l.Printf("istio x-request-id=%s", r.Header.Get("x-request-id"))
		return r.Header.Get("x-request-id")
	}
	
	// create a new one
	uid := uuid.New()
	us := uid.String()
	l.Printf("new uuid=%s", us)
	l.Printf("set x-request-id=%s", us)
	r.Header.Set("x-request-id", us)
	return us
}

// HandleUnauthorized renders the 403 error page
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

// HealthzHandler provides a simple health check endpoint
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

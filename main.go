package main

import (
	"encoding/gob"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/umg/devops-istio-sso/internal/auth"
	"github.com/umg/devops-istio-sso/internal/config"
	"github.com/umg/devops-istio-sso/internal/middleware"
	"github.com/umg/devops-istio-sso/internal/session"
	"github.com/umg/devops-istio-sso/internal/token"
	"github.com/umg/devops-istio-sso/internal/utils"
)

func init() {
	// Register types for session storage
	gob.Register(&oauth2.Token{})
	
	// Validate required environment variables
	if len(os.Getenv("SESSION_KEY")) < 32 {
		log.Fatal("SESSION_KEY must be 32 bytes or larger")
	}
}

func main() {
	// Initialize managers
	configManager := config.NewManager()
	sessionManager := session.NewManager()
	tokenManager := token.NewManager()
	
	// Load configuration
	configFile := os.Getenv("OAUTH2_CONFIG_FILE")
	if configFile == "" {
		log.Fatal("OAUTH2_CONFIG_FILE environment variable is required")
	}
	
	if err := configManager.LoadFromFile(configFile); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	// Initialize session store
	storeType := os.Getenv("SESSION_STORE_TYPE")
	if storeType == "" {
		storeType = "cookie"
	}
	
	if err := sessionManager.InitializeStore(storeType); err != nil {
		log.Fatalf("Failed to initialize session store: %v", err)
	}
	
	// Start token cleanup routine
	tokenManager.StartCleanupRoutine()
	
	// Initialize auth service
	authService := auth.NewService(configManager, sessionManager, tokenManager)
	
	// Setup routes
	r := mux.NewRouter()
	
	// Auth endpoints
	r.HandleFunc("/", authService.LoginHandler)
	r.HandleFunc("/oauth2/{ID}", authService.LoginHandler)
	r.HandleFunc("/callback", authService.CallbackHandler)
	r.HandleFunc("/callback/{ID}", authService.CallbackHandler)
	r.HandleFunc("/refresh/{ID}", authService.RefreshHandler)
	r.HandleFunc("/logout/{ID}", authService.LogoutHandler)
	r.HandleFunc("/token-status", authService.TokenStatusHandler)
	
	// Utility endpoints
	r.HandleFunc("/403", utils.HandleUnauthorized)
	r.HandleFunc("/healthz", utils.HealthzHandler)
	
	// Apply middleware
	tokenValidationMiddleware := middleware.TokenValidationMiddleware(configManager, sessionManager, tokenManager)
	r.Use(tokenValidationMiddleware)
	
	// Setup CORS
	c := cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            false,
	})
	
	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Starting server on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, c.Handler(r)))
}

// Package server implements the HTTP OIDC/OAuth2 provider. Users, providers,
// applications, sessions, auth codes, and tokens are all persisted in the SQL
// store; only in-flight external-provider logins are kept in memory.
package server

import (
	"crypto/rsa"
	"crypto/subtle"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
	"github.com/omegadc/access-nex/internal/store"
)

const sessionCookie = "oidc_sid"

type Server struct {
	issuer string
	key    *rsa.PrivateKey
	keyID  string
	store  *store.Store
	box    *secrets.Box

	mu          sync.Mutex
	oauthStates map[string]*models.OAuthProxyState
}

func New(issuer string, key *rsa.PrivateKey, st *store.Store, box *secrets.Box) *Server {
	return &Server{
		issuer:      issuer,
		key:         key,
		keyID:       "access-nex-key-1",
		store:       st,
		box:         box,
		oauthStates: make(map[string]*models.OAuthProxyState),
	}
}

// Handler returns the full route tree wrapped in security headers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Local OIDC/OAuth2 endpoints
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/revoke", s.handleRevoke)
	mux.HandleFunc("/introspect", s.handleIntrospect)
	mux.HandleFunc("/userinfo", s.handleUserInfo)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/end_session", s.handleEndSession)
	mux.HandleFunc("/apps", s.handleListApps)

	// External OAuth proxy: start a flow with an external provider, get back
	// a local auth code exchangeable at /token.
	mux.HandleFunc("/oauth/providers", s.handleOAuthProviders)
	mux.HandleFunc("/oauth/start", s.handleOAuthStart)
	mux.HandleFunc("/oauth/callback", s.handleOAuthCallback)

	// Built-in portal: direct session login to test user validation.
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/portal", s.handlePortal)
	mux.HandleFunc("/portal/logout", s.handlePortalLogout)

	return withSecurityHeaders(mux)
}

func (s *Server) endpoint(path string) string { return s.issuer + path }

// ── Data access helpers ───────────────────────────────────────────────────────

// clientByID looks up an enabled application by client ID.
func (s *Server) clientByID(id string) *models.App {
	app, err := s.store.GetApp(id)
	if err != nil || !app.Enabled {
		return nil
	}
	return app
}

func (s *Server) providerByID(id string) *models.Provider {
	p, err := s.store.GetProvider(id)
	if err != nil || !p.Enabled || p.Kind == models.ProviderKindInternal {
		return nil
	}
	return p
}

func (s *Server) userBySubject(subject string) *models.User {
	u, err := s.store.GetUserBySubject(subject)
	if err != nil {
		return nil
	}
	return u
}

// authenticateUser verifies a username/password against the users table.
// External-provider accounts have no password hash and cannot password-login.
func (s *Server) authenticateUser(username, password string) (string, bool) {
	u, err := s.store.GetUserByUsername(username)
	if err != nil || u.PasswordHash == "" {
		return "", false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return "", false
	}
	return u.Subject, true
}

// authenticateClient validates client credentials on token-style endpoints.
func (s *Server) authenticateClient(r *http.Request) (*models.App, string) {
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	if clientID == "" {
		return nil, "Missing client credentials"
	}
	client := s.clientByID(clientID)
	if client == nil {
		return nil, "Unknown client_id"
	}
	if client.Public {
		if secret != "" {
			return nil, "Public clients must not send client_secret"
		}
		return client, ""
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(client.Secret)) != 1 {
		return nil, "Invalid client_secret"
	}
	return client, ""
}

// ── Session helpers (persisted in the sessions table) ─────────────────────────

func (s *Server) startSession(w http.ResponseWriter, subject string) {
	sessionID := secrets.RandomToken(32)
	expires := time.Now().Add(8 * time.Hour)
	if err := s.store.SaveSession(&models.Session{ID: sessionID, Subject: subject, ExpiresAt: expires}); err != nil {
		log.Printf("save session: %v", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sessionID,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) endSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteSession(cookie.Value); err != nil {
			log.Printf("delete session: %v", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) subjectFromSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	session, err := s.store.GetSession(cookie.Value)
	if err != nil {
		return "", false
	}
	if time.Now().After(session.ExpiresAt) {
		_ = s.store.DeleteSession(cookie.Value)
		return "", false
	}
	return session.Subject, true
}

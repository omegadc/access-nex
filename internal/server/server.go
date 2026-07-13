// Package server implements the HTTP OIDC/OAuth2 provider. Users, providers,
// applications, sessions, auth codes, tokens, grants, and signing keys are
// all persisted in the SQL store; only in-flight external-provider logins
// are kept in memory.
package server

import (
	"crypto/rsa"
	"crypto/subtle"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
	"github.com/omegadc/access-nex/internal/store"
)

const (
	sessionCookie   = "oidc_sid"
	maxLoginFails   = 5
	lockoutDuration = 15 * time.Minute
)

// SigningKey pairs a parsed RSA key with its JWKS key ID.
type SigningKey struct {
	Kid string
	Key *rsa.PrivateKey
}

type Server struct {
	issuer        string
	keys          []SigningKey // keys[0] is the active signing key
	store         *store.Store
	box           *secrets.Box
	secureCookies bool

	loginLimiter *rateLimiter
	tokenLimiter *rateLimiter

	mu          sync.Mutex
	oauthStates map[string]*models.OAuthProxyState

	corsMu      sync.Mutex
	corsOrigins map[string]bool
	corsLoaded  time.Time
}

// New builds a Server. keys must be non-empty with the active key first.
func New(issuer string, keys []SigningKey, st *store.Store, box *secrets.Box) *Server {
	return &Server{
		issuer:        issuer,
		keys:          keys,
		store:         st,
		box:           box,
		secureCookies: strings.HasPrefix(issuer, "https://"),
		loginLimiter:  newRateLimiter(10, time.Minute),
		tokenLimiter:  newRateLimiter(60, time.Minute),
		oauthStates:   make(map[string]*models.OAuthProxyState),
	}
}

func (s *Server) activeKey() SigningKey { return s.keys[0] }

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

	// External OAuth proxy
	mux.HandleFunc("/oauth/providers", s.handleOAuthProviders)
	mux.HandleFunc("/oauth/start", s.handleOAuthStart)
	mux.HandleFunc("/oauth/callback", s.handleOAuthCallback)

	// Portal
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/portal", s.handlePortal)
	mux.HandleFunc("/portal/logout", s.handlePortalLogout)

	// Admin UI + JSON API (session + is_admin required)
	mux.HandleFunc("GET /admin", s.requireAdminPage(s.handleAdminPage))
	mux.HandleFunc("GET /api/admin/users", s.requireAdminAPI(s.apiListUsers))
	mux.HandleFunc("POST /api/admin/users", s.requireAdminAPI(s.apiCreateUser))
	mux.HandleFunc("DELETE /api/admin/users/{username}", s.requireAdminAPI(s.apiDeleteUser))
	mux.HandleFunc("GET /api/admin/apps", s.requireAdminAPI(s.apiListApps))
	mux.HandleFunc("POST /api/admin/apps", s.requireAdminAPI(s.apiCreateApp))
	mux.HandleFunc("DELETE /api/admin/apps/{id}", s.requireAdminAPI(s.apiDeleteApp))
	mux.HandleFunc("GET /api/admin/providers", s.requireAdminAPI(s.apiListProviders))
	mux.HandleFunc("DELETE /api/admin/providers/{id}", s.requireAdminAPI(s.apiDeleteProvider))
	mux.HandleFunc("GET /api/admin/audit", s.requireAdminAPI(s.apiListAudit))

	return s.withSecurityHeaders(mux)
}

func (s *Server) endpoint(path string) string { return s.issuer + path }

// ── Security headers + per-client CORS ────────────────────────────────────────

// allowedOrigin reports whether origin belongs to a registered application
// (derived from redirect URI origins) or the issuer itself. The set is
// cached for 60 seconds.
func (s *Server) allowedOrigin(origin string) bool {
	s.corsMu.Lock()
	defer s.corsMu.Unlock()
	if time.Since(s.corsLoaded) > time.Minute || s.corsOrigins == nil {
		origins := map[string]bool{}
		if u, err := url.Parse(s.issuer); err == nil && u.Scheme != "" {
			origins[u.Scheme+"://"+u.Host] = true
		}
		apps, err := s.store.ListApps()
		if err == nil {
			for _, a := range apps {
				if !a.Enabled {
					continue
				}
				for _, ru := range a.RedirectURIs {
					if u, err := url.Parse(ru); err == nil && u.Scheme != "" && u.Host != "" {
						origins[u.Scheme+"://"+u.Host] = true
					}
				}
			}
		}
		s.corsOrigins = origins
		s.corsLoaded = time.Now()
	}
	return s.corsOrigins[origin]
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		// Per-client CORS: only origins belonging to registered apps.
		if origin := r.Header.Get("Origin"); origin != "" && s.allowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

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

// authenticateUser verifies a username/password against the users table,
// enforcing the failed-login lockout and writing audit entries.
func (s *Server) authenticateUser(username, password, ip string) (string, bool) {
	u, err := s.store.GetUserByUsername(username)
	if err != nil || u.PasswordHash == "" {
		s.store.Audit("login_failed", "", "", ip, "unknown user or passwordless account: "+username)
		return "", false
	}
	if !u.LockedUntil.IsZero() && time.Now().Before(u.LockedUntil) {
		s.store.Audit("login_locked", u.Subject, "", ip, "account locked until "+u.LockedUntil.Format(time.RFC3339))
		return "", false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		locked, _ := s.store.RegisterLoginFailure(username, maxLoginFails, lockoutDuration)
		detail := "wrong password"
		if locked {
			detail = "wrong password; account locked"
		}
		s.store.Audit("login_failed", u.Subject, "", ip, detail)
		return "", false
	}
	_ = s.store.ClearLoginFailures(username)
	s.store.Audit("login_success", u.Subject, "", ip, "")
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
		Secure:   s.secureCookies,
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
		HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode,
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

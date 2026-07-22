// Package server implements the HTTP OIDC/OAuth2 provider. Users, providers,
// applications, sessions, auth codes, tokens, grants, and signing keys are
// all persisted in the SQL store; only in-flight external-provider logins
// are kept in memory.
package server

import (
	"crypto/rsa"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/email"
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

// Config is everything New needs to build a Server. Keys must be non-empty
// with the active signing key first. Mailer, Logger, and the WebAuthn/DPoP
// settings are optional — sensible defaults are used when left zero.
type Config struct {
	Issuer           string
	Keys             []SigningKey
	Store            *store.Store
	Box              *secrets.Box
	Mailer           email.Mailer
	Logger           *slog.Logger
	RequireDPoPNonce bool
	WebAuthnRPName   string   // relying party display name shown by authenticators
	FrontendOrigins  []string // extra CORS origins for a separately-hosted frontend using /api/v1
}

type Server struct {
	issuer        string
	keys          []SigningKey // keys[0] is the active signing key
	store         *store.Store
	box           *secrets.Box
	mailer        email.Mailer
	log           *slog.Logger
	secureCookies bool

	requireDPoPNonce bool
	webauthn         *webauthnService
	metrics          *metrics
	frontendOrigins  []string

	loginLimiter *rateLimiter
	tokenLimiter *rateLimiter

	mu          sync.Mutex
	oauthStates map[string]*models.OAuthProxyState
	totpPending map[string]*pendingTOTP

	dpopMu     sync.Mutex
	dpopSeen   map[string]time.Time // DPoP proof jti → seen-at, replay cache
	dpopNonces map[string]time.Time // server-issued nonces awaiting use

	corsMu      sync.Mutex
	corsOrigins map[string]bool
	corsLoaded  time.Time
}

// pendingTOTP is the short-lived server-side state between "password
// verified" and "TOTP code verified" for accounts with 2FA enabled.
type pendingTOTP struct {
	Subject   string
	ExpiresAt time.Time
}

// New builds a Server from cfg. A nil Mailer becomes a no-op mailer (send
// calls succeed without delivering anything) so callers that genuinely don't
// want email features enabled don't have to construct one just to pass here;
// cli.go always passes a real Mailer (SMTP or the file-logging dev fallback).
func New(cfg Config) *Server {
	if cfg.Mailer == nil {
		cfg.Mailer = noopMailer{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s := &Server{
		issuer:           cfg.Issuer,
		keys:             cfg.Keys,
		store:            cfg.Store,
		box:              cfg.Box,
		mailer:           cfg.Mailer,
		log:              logger,
		secureCookies:    strings.HasPrefix(cfg.Issuer, "https://"),
		requireDPoPNonce: cfg.RequireDPoPNonce,
		frontendOrigins:  cfg.FrontendOrigins,
		loginLimiter:     newRateLimiter(10, time.Minute),
		tokenLimiter:     newRateLimiter(60, time.Minute),
		oauthStates:      make(map[string]*models.OAuthProxyState),
		totpPending:      make(map[string]*pendingTOTP),
		dpopSeen:         make(map[string]time.Time),
		dpopNonces:       make(map[string]time.Time),
	}
	rpName := cfg.WebAuthnRPName
	if rpName == "" {
		rpName = "Access-Nex"
	}
	s.webauthn = newWebAuthnService(s, rpName)
	s.metrics = newMetrics()
	return s
}

// noopMailer discards mail; used only as New's fallback when no Mailer is
// configured at all.
type noopMailer struct{}

func (noopMailer) Send(to, subject, body string) error { return nil }

func (s *Server) activeKey() SigningKey { return s.keys[0] }

// Handler returns the full route tree wrapped in security headers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Local OIDC/OAuth2 endpoints. There is no "/" route: this server is the
	// backend only now (see docs/FRONTEND.md) — the Python/FastAPI frontend
	// owns every browser-facing page and proxies everything else here.
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

	// External OAuth proxy
	mux.HandleFunc("/oauth/providers", s.handleOAuthProviders)
	mux.HandleFunc("/oauth/start", s.handleOAuthStart)
	mux.HandleFunc("/oauth/callback", s.handleOAuthCallback)

	// Portal (form submissions the frontend's pages post to; GET rendering
	// of /login, /login/2fa, and /portal itself is entirely the frontend's
	// job now, backed by /api/v1/* below)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /login/2fa", s.handleLoginTOTP)
	mux.HandleFunc("/portal/logout", s.handlePortalLogout)

	// Password reset + email verification
	mux.HandleFunc("POST /forgot-password", s.handleForgotPassword)
	mux.HandleFunc("POST /reset-password", s.handleResetPassword)
	mux.HandleFunc("/verify-email", s.handleVerifyEmail)
	mux.HandleFunc("POST /portal/verify-email/resend", s.handlePortalResendVerification)

	// Portal self-service (GET /portal/2fa's rendering is the frontend's,
	// backed by GET /api/v1/totp below)
	mux.HandleFunc("POST /portal/2fa/enroll", s.handleTOTPEnroll)
	mux.HandleFunc("POST /portal/2fa/confirm", s.handleTOTPConfirm)
	mux.HandleFunc("POST /portal/2fa/disable", s.handleTOTPDisable)
	mux.HandleFunc("POST /portal/password", s.handlePortalChangePassword)
	mux.HandleFunc("POST /portal/grants/revoke", s.handlePortalRevokeGrant)
	mux.HandleFunc("POST /portal/sessions/revoke", s.handlePortalRevokeSession)
	mux.HandleFunc("POST /portal/identities/unlink", s.handlePortalUnlinkIdentity)

	// WebAuthn / passkeys: portal registration + login second factor
	mux.HandleFunc("POST /portal/webauthn/register/begin", s.handleWebAuthnRegisterBegin)
	mux.HandleFunc("POST /portal/webauthn/register/finish", s.handleWebAuthnRegisterFinish)
	mux.HandleFunc("POST /portal/webauthn/delete", s.handlePortalWebAuthnDelete)
	mux.HandleFunc("POST /login/webauthn/begin", s.handleWebAuthnLoginBegin)
	mux.HandleFunc("POST /login/webauthn/finish", s.handleWebAuthnLoginFinish)

	// RFC 8628 device authorization grant (GET /device's rendering is the
	// frontend's, backed by GET /api/v1/device below)
	mux.HandleFunc("POST /device_authorize", s.handleDeviceAuthorize)
	mux.HandleFunc("POST /device", s.handleDeviceVerify)

	// Frontend support data — not part of the stable /api/v1 contract in
	// docs/openapi.yaml, just what the frontend's pages need to render
	// (see page_support.go).
	mux.HandleFunc("GET /api/v1/stats", s.apiV1PublicStats)
	mux.HandleFunc("GET /api/v1/apps/public", s.apiV1PublicApps)
	mux.HandleFunc("GET /api/v1/apps/configs", s.requireSessionAPI(s.apiV1AppConfigs))
	mux.HandleFunc("GET /api/v1/stats/active", s.requireSessionAPI(s.apiV1ActiveStats))
	mux.HandleFunc("GET /api/v1/totp", s.requireSessionAPI(s.apiV1TOTPStatus))
	mux.HandleFunc("GET /api/v1/device", s.requireSessionAPI(s.apiV1DeviceInfo))

	// Admin JSON API (session + is_admin required); the /admin console
	// itself is rendered by the frontend and drives this directly.
	mux.HandleFunc("GET /api/admin/users", s.requireAdminAPI(s.apiListUsers))
	mux.HandleFunc("POST /api/admin/users", s.requireAdminAPI(s.apiCreateUser))
	mux.HandleFunc("DELETE /api/admin/users/{username}", s.requireAdminAPI(s.apiDeleteUser))
	mux.HandleFunc("GET /api/admin/apps", s.requireAdminAPI(s.apiListApps))
	mux.HandleFunc("POST /api/admin/apps", s.requireAdminAPI(s.apiCreateApp))
	mux.HandleFunc("DELETE /api/admin/apps/{id}", s.requireAdminAPI(s.apiDeleteApp))
	mux.HandleFunc("GET /api/admin/providers", s.requireAdminAPI(s.apiListProviders))
	mux.HandleFunc("DELETE /api/admin/providers/{id}", s.requireAdminAPI(s.apiDeleteProvider))
	mux.HandleFunc("GET /api/admin/audit", s.requireAdminAPI(s.apiListAudit))

	// JSON account API for a separately-hosted frontend (see apiv1.go).
	s.registerAPIv1(mux)

	// Prometheus metrics — unauthenticated by design (standard practice);
	// keep this off the public internet at the network/reverse-proxy layer.
	mux.Handle("GET /metrics", s.handleMetrics())

	return s.withMetrics(mux, s.withSecurityHeaders(mux))
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
		// Explicitly configured origins for a separately-hosted frontend
		// (e.g. a Python SPA/BFF) driving the /api/v1 surface cross-origin.
		for _, o := range s.frontendOrigins {
			origins[o] = true
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
		s.log.Error("save session", "error", err)
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
			s.log.Error("delete session", "error", err)
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

// ── TOTP second-factor pending state ──────────────────────────────────────────

// verifyPassword checks a username/password pair, enforcing lockout and
// writing audit entries, but does not start a session — callers decide
// whether a second factor (TOTP) is required first.
func (s *Server) verifyPassword(username, password, ip string) (*models.User, bool) {
	u, err := s.store.GetUserByUsername(username)
	if err != nil || u.PasswordHash == "" {
		s.store.Audit("login_failed", "", "", ip, "unknown user or passwordless account: "+username)
		s.metrics.loginResults.WithLabelValues("failed").Inc()
		return nil, false
	}
	if !u.LockedUntil.IsZero() && time.Now().Before(u.LockedUntil) {
		s.store.Audit("login_locked", u.Subject, "", ip, "account locked until "+u.LockedUntil.Format(time.RFC3339))
		s.metrics.loginResults.WithLabelValues("locked").Inc()
		return nil, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		locked, _ := s.store.RegisterLoginFailure(username, maxLoginFails, lockoutDuration)
		detail := "wrong password"
		if locked {
			detail = "wrong password; account locked"
		}
		s.store.Audit("login_failed", u.Subject, "", ip, detail)
		s.metrics.loginResults.WithLabelValues("failed").Inc()
		return nil, false
	}
	_ = s.store.ClearLoginFailures(username)
	// Not counted as a metrics "success" here: password-correct doesn't mean
	// fully logged in when 2FA is enrolled. The login_success audit call
	// sites (after any 2FA step completes) record that outcome instead.
	return u, true
}

// newTOTPPending records that a user passed their password and now owes a
// TOTP code, returning an opaque token identifying that pending login.
func (s *Server) newTOTPPending(subject string) string {
	token := secrets.RandomToken(24)
	s.mu.Lock()
	s.totpPending[token] = &pendingTOTP{Subject: subject, ExpiresAt: time.Now().Add(5 * time.Minute)}
	s.mu.Unlock()
	return token
}

// consumeTOTPPending resolves and invalidates a pending-TOTP token.
func (s *Server) consumeTOTPPending(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.totpPending[token]
	if p == nil {
		return "", false
	}
	delete(s.totpPending, token)
	if time.Now().After(p.ExpiresAt) {
		return "", false
	}
	return p.Subject, true
}

// peekPendingSubject resolves a pending-login token without consuming it —
// used by the WebAuthn login "begin" step, which needs to know who's
// authenticating without invalidating the token (the "finish" step, or a
// TOTP code, consumes it later).
func (s *Server) peekPendingSubject(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.totpPending[token]
	if p == nil || time.Now().After(p.ExpiresAt) {
		return "", false
	}
	return p.Subject, true
}

// deletePendingSecondFactor explicitly invalidates a pending-login token
// (used once a second factor — WebAuthn — has actually succeeded).
func (s *Server) deletePendingSecondFactor(token string) {
	s.mu.Lock()
	delete(s.totpPending, token)
	s.mu.Unlock()
}

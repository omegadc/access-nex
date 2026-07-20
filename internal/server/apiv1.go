package server

// /api/v1: a JSON-only account API mirroring what the server-rendered portal
// pages already do (login, 2FA, password, grants, sessions, identities,
// password reset), so a separately-hosted frontend — in Python or any other
// language — can drive the full end-user experience without scraping HTML
// forms. The OIDC/OAuth2 endpoints (/authorize, /token, ...) are already
// JSON/redirect-based per spec and don't need a v1 wrapper; WebAuthn's
// begin/finish endpoints are already JSON too (see webauthn.go) and are
// considered part of this same API surface, just left at their existing
// paths rather than duplicated under /api/v1.
//
// Session auth: these endpoints use the same oidc_sid cookie as the portal.
// For a same-origin frontend (recommended — see README) that's it. For a
// cross-origin frontend, register its origin with --frontend-origin (CORS)
// and serve access-nex over HTTPS so the Secure, SameSite=Lax cookie is
// actually sent back; SameSite=Lax still allows the top-level navigations
// used by /authorize while blocking most cross-site request forgery.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/secrets"
)

// subjectCtxKey carries the authenticated subject through requireSessionAPI
// to the wrapped handler, avoiding a second subjectFromSession lookup.
type subjectCtxKey struct{}

func withSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectCtxKey{}, subject)
}

func subjectFrom(ctx context.Context) string {
	s, _ := ctx.Value(subjectCtxKey{}).(string)
	return s
}

func (s *Server) registerAPIv1(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/login", s.apiV1Login)
	mux.HandleFunc("POST /api/v1/login/totp", s.apiV1LoginTOTP)
	mux.HandleFunc("POST /api/v1/logout", s.apiV1Logout)
	mux.HandleFunc("GET /api/v1/me", s.requireSessionAPI(s.apiV1Me))

	mux.HandleFunc("GET /api/v1/grants", s.requireSessionAPI(s.apiV1ListGrants))
	mux.HandleFunc("DELETE /api/v1/grants/{client_id}", s.requireSessionAPI(s.apiV1RevokeGrant))

	mux.HandleFunc("GET /api/v1/sessions", s.requireSessionAPI(s.apiV1ListSessions))
	mux.HandleFunc("DELETE /api/v1/sessions/{id}", s.requireSessionAPI(s.apiV1RevokeSession))

	mux.HandleFunc("GET /api/v1/identities", s.requireSessionAPI(s.apiV1ListIdentities))
	mux.HandleFunc("DELETE /api/v1/identities/{id}", s.requireSessionAPI(s.apiV1UnlinkIdentity))

	mux.HandleFunc("POST /api/v1/password", s.requireSessionAPI(s.apiV1ChangePassword))
	mux.HandleFunc("POST /api/v1/email/resend-verification", s.requireSessionAPI(s.apiV1ResendVerification))

	mux.HandleFunc("POST /api/v1/forgot-password", s.apiV1ForgotPassword)
	mux.HandleFunc("POST /api/v1/reset-password", s.apiV1ResetPassword)
}

// requireSessionAPI is /api/v1's equivalent of requireAdminAPI: a valid
// session cookie is required, and mutating requests must carry the
// X-Access-Nex-Api header — combined with SameSite cookies and per-origin
// CORS, this blocks cross-site request forgery against the API.
func (s *Server) requireSessionAPI(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subject, ok := s.subjectFromSession(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Access-Nex-Api") != "1" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing X-Access-Nex-Api header"})
			return
		}
		r = r.WithContext(withSubject(r.Context(), subject))
		h(w, r)
	}
}

// ── Login / 2FA / logout ──────────────────────────────────────────────────────

func (s *Server) apiV1Login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if !s.loginLimiter.allow(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts — try again in a minute"})
		return
	}
	user, ok := s.verifyPassword(req.Username, req.Password, clientIP(r))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	methods := []string{}
	if user.TOTPEnabled {
		methods = append(methods, "totp")
	}
	if s.hasWebAuthnCredentials(user.Subject) {
		methods = append(methods, "webauthn")
	}
	if len(methods) > 0 {
		token := s.newTOTPPending(user.Subject)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "2fa_required", "token": token, "methods": methods,
		})
		return
	}
	s.store.Audit("login_success", user.Subject, "", clientIP(r), "")
	s.metrics.loginResults.WithLabelValues("success").Inc()
	s.startSession(w, user.Subject)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_in"})
}

func (s *Server) apiV1LoginTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct{ Token, Code string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	subject, ok := s.consumeTOTPPending(req.Token)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "login session expired — sign in again"})
		return
	}
	user := s.userBySubject(subject)
	if user == nil || !user.TOTPEnabled || !secrets.VerifyTOTP(user.TOTPSecret, req.Code) {
		s.store.Audit("login_2fa_failed", subject, "", clientIP(r), "")
		s.metrics.loginResults.WithLabelValues("2fa_failed").Inc()
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		return
	}
	s.store.Audit("login_success", subject, "", clientIP(r), "with 2FA")
	s.metrics.loginResults.WithLabelValues("success").Inc()
	s.startSession(w, subject)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_in"})
}

func (s *Server) apiV1Logout(w http.ResponseWriter, r *http.Request) {
	s.endSession(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

func (s *Server) apiV1Me(w http.ResponseWriter, r *http.Request) {
	user := s.userBySubject(subjectFrom(r.Context()))
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": user.Subject, "username": user.Username, "name": user.Name,
		"email": user.Email, "email_verified": user.EmailVerified,
		"is_admin": user.IsAdmin, "totp_enabled": user.TOTPEnabled,
		"provider_id": user.ProviderID,
	})
}

// ── Grants ────────────────────────────────────────────────────────────────────

func (s *Server) apiV1ListGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := s.store.ListGrants(subjectFrom(r.Context()))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type grantOut struct {
		ClientID  string   `json:"client_id"`
		AppName   string   `json:"app_name"`
		Scopes    []string `json:"scopes"`
		UpdatedAt string   `json:"updated_at"`
	}
	out := make([]grantOut, 0, len(grants))
	for _, g := range grants {
		name := g.ClientID
		if a, err := s.store.GetApp(g.ClientID); err == nil {
			name = a.Name
		}
		out = append(out, grantOut{g.ClientID, name, g.Scopes, g.UpdatedAt.Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

func (s *Server) apiV1RevokeGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	if err := s.store.DeleteGrant(subjectFrom(r.Context()), clientID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("grant_revoked", subjectFrom(r.Context()), clientID, clientIP(r), "via api/v1")
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func (s *Server) apiV1ListSessions(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	sessions, err := s.store.ListSessions(subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	currentID := ""
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		currentID = cookie.Value
	}
	type sessionOut struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
		Current   bool   `json:"current"`
	}
	out := make([]sessionOut, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, sessionOut{sess.ID, sess.CreatedAt.Format(time.RFC3339), sess.ExpiresAt.Format(time.RFC3339), sess.ID == currentID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) apiV1RevokeSession(w http.ResponseWriter, r *http.Request) {
	subject := subjectFrom(r.Context())
	id := r.PathValue("id")
	if err := s.store.DeleteSessionForSubject(subject, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("session_revoked", subject, "", clientIP(r), "via api/v1")
	if cookie, err := r.Cookie(sessionCookie); err == nil && cookie.Value == id {
		s.endSession(w, r)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ── Identities ────────────────────────────────────────────────────────────────

func (s *Server) apiV1ListIdentities(w http.ResponseWriter, r *http.Request) {
	user := s.userBySubject(subjectFrom(r.Context()))
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	identities, err := s.store.ListIdentities(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type identityOut struct {
		ID           int64  `json:"id"`
		ProviderID   string `json:"provider_id"`
		ProviderName string `json:"provider_name"`
		ExternalID   string `json:"external_id"`
		CreatedAt    string `json:"created_at"`
	}
	out := make([]identityOut, 0, len(identities))
	for _, id := range identities {
		name := id.ProviderID
		if p, err := s.store.GetProvider(id.ProviderID); err == nil {
			name = p.Name
		}
		out = append(out, identityOut{id.ID, id.ProviderID, name, id.ExternalID, id.CreatedAt.Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": out})
}

func (s *Server) apiV1UnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	user := s.userBySubject(subjectFrom(r.Context()))
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	identityID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid identity id"})
		return
	}
	if user.PasswordHash == "" {
		if count, err := s.store.CountIdentities(user.ID); err == nil && count <= 1 {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "cannot unlink your only sign-in method"})
			return
		}
	}
	if err := s.store.UnlinkIdentity(user.ID, identityID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("identity_unlinked", user.Subject, "", clientIP(r), "via api/v1")
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlinked"})
}

// ── Password & email verification ─────────────────────────────────────────────

func (s *Server) apiV1ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := s.userBySubject(subjectFrom(r.Context()))
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	var req struct{ CurrentPassword, NewPassword string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if user.PasswordHash != "" && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}
	if len(req.NewPassword) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.UpdatePasswordHash(user.Username, string(hash)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("password_changed", user.Subject, "", clientIP(r), "via api/v1")
	writeJSON(w, http.StatusOK, map[string]string{"status": "changed"})
}

func (s *Server) apiV1ResendVerification(w http.ResponseWriter, r *http.Request) {
	user := s.userBySubject(subjectFrom(r.Context()))
	if user == nil || user.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no email address on file"})
		return
	}
	if err := s.sendVerificationEmail(user.Subject, user.Email, user.Username); err != nil {
		s.log.Error("send verification email", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not send email"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Server) apiV1ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	// Always the same response, whether or not the address matched an
	// account — see handleForgotPassword's comment for why.
	if u, err := s.store.GetSoleUserByEmail(req.Email); err == nil && u.PasswordHash != "" {
		token := secrets.RandomToken(32)
		if err := s.store.SavePasswordReset(token, u.Subject); err == nil {
			link := s.issuer + "/reset-password?token=" + token
			body := "Someone (hopefully you) requested a password reset for your Access-Nex account.\n\n" +
				"Reset your password: " + link + "\n\nThis link expires in 1 hour.\n"
			if err := s.mailer.Send(u.Email, "Reset your Access-Nex password", body); err != nil {
				s.log.Error("send password reset email", "error", err)
			}
			s.store.Audit("password_reset_requested", u.Subject, "", clientIP(r), "via api/v1")
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "if_exists_email_sent"})
}

func (s *Server) apiV1ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Token, NewPassword string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	subject, err := s.store.ConsumePasswordReset(req.Token)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "link is invalid or has expired"})
		return
	}
	if len(req.NewPassword) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account no longer exists"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.UpdatePasswordHash(user.Username, string(hash)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("password_reset_completed", subject, "", clientIP(r), "via api/v1")
	writeJSON(w, http.StatusOK, map[string]string{"status": "changed"})
}

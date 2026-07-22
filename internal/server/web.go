package server

// Portal/login business logic. HTML rendering for these flows now lives in
// the Python/FastAPI frontend (see docs/FRONTEND.md); this file only
// validates input, manages sessions, and redirects the browser to whichever
// frontend page should be shown next, carrying whatever state that page
// needs as query parameters.

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/omegadc/access-nex/internal/secrets"
)

// ── Direct login (session portal, bypasses the OAuth flow) ───────────────────

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/portal"
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if rt := r.Form.Get("return_to"); rt != "" {
		returnTo = rt
	}
	if !s.loginLimiter.allow(clientIP(r)) {
		s.redirectToDirectLogin(w, r, returnTo, "Too many attempts — try again in a minute")
		return
	}
	user, ok := s.verifyPassword(r.Form.Get("username"), r.Form.Get("password"), clientIP(r))
	if !ok {
		s.redirectToDirectLogin(w, r, returnTo, "Invalid username or password")
		return
	}
	if user.TOTPEnabled || s.hasWebAuthnCredentials(user.Subject) {
		token := s.newTOTPPending(user.Subject)
		s.redirectToDirectTOTP(w, r, token, returnTo, "")
		return
	}
	s.store.Audit("login_success", user.Subject, "", clientIP(r), "")
	s.metrics.loginResults.WithLabelValues("success").Inc()
	s.startSession(w, user.Subject)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// handleLoginTOTP verifies the second factor for a direct portal login
// (started by handleLogin above).
func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.Form.Get("totp_token")
	returnTo := r.Form.Get("return_to")
	if returnTo == "" {
		returnTo = "/portal"
	}
	subject, ok := s.consumeTOTPPending(token)
	if !ok {
		s.redirectToDirectLogin(w, r, returnTo, "Session expired — sign in again")
		return
	}
	user := s.userBySubject(subject)
	if user == nil || !user.TOTPEnabled || !secrets.VerifyTOTP(user.TOTPSecret, r.Form.Get("totp_code")) {
		s.store.Audit("login_2fa_failed", subject, "", clientIP(r), "")
		s.metrics.loginResults.WithLabelValues("2fa_failed").Inc()
		s.redirectToDirectTOTP(w, r, s.newTOTPPending(subject), returnTo, "Invalid code — try again")
		return
	}
	s.store.Audit("login_success", subject, "", clientIP(r), "with 2FA")
	s.metrics.loginResults.WithLabelValues("success").Inc()
	s.startSession(w, subject)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// redirectToDirectLogin sends the browser to the frontend's direct-login
// page (as opposed to redirectToOAuthLogin, used mid-/authorize).
func (s *Server) redirectToDirectLogin(w http.ResponseWriter, r *http.Request, returnTo, errMsg string) {
	v := url.Values{}
	if returnTo != "" {
		v.Set("return_to", returnTo)
	}
	if errMsg != "" {
		v.Set("error", errMsg)
	}
	http.Redirect(w, r, "/login?"+v.Encode(), http.StatusFound)
}

// redirectToDirectTOTP sends the browser to the frontend's direct-login 2FA
// challenge page (as opposed to redirectToOAuthTOTP, used mid-/authorize).
func (s *Server) redirectToDirectTOTP(w http.ResponseWriter, r *http.Request, token, returnTo, errMsg string) {
	v := url.Values{}
	v.Set("token", token)
	if returnTo != "" {
		v.Set("return_to", returnTo)
	}
	if errMsg != "" {
		v.Set("error", errMsg)
	}
	http.Redirect(w, r, "/login/2fa?"+v.Encode(), http.StatusFound)
}

// ── OAuth-flow login/2FA/consent redirects (used from /authorize) ───────────

// redirectToOAuthLogin sends the browser to the frontend's login page with
// the original /authorize request round-tripped as query parameters, so the
// page's form can submit it straight back to /authorize.
func (s *Server) redirectToOAuthLogin(w http.ResponseWriter, r *http.Request, req authRequest, clientName, errMsg string) {
	v := requestValues(req)
	if clientName != "" {
		v.Set("client_name", clientName)
	}
	if errMsg != "" {
		v.Set("error", errMsg)
	}
	http.Redirect(w, r, "/login?"+v.Encode(), http.StatusFound)
}

// redirectToOAuthTOTP is redirectToOAuthLogin's equivalent for the mid-flow
// 2FA challenge.
func (s *Server) redirectToOAuthTOTP(w http.ResponseWriter, r *http.Request, req authRequest, clientName, token, errMsg string) {
	v := requestValues(req)
	v.Set("token", token)
	if clientName != "" {
		v.Set("client_name", clientName)
	}
	if errMsg != "" {
		v.Set("error", errMsg)
	}
	http.Redirect(w, r, "/login/2fa?"+v.Encode(), http.StatusFound)
}

// redirectToConsent sends the browser to the frontend's consent page.
func (s *Server) redirectToConsent(w http.ResponseWriter, r *http.Request, req authRequest, clientName string, scope []string) {
	v := requestValues(req)
	if clientName != "" {
		v.Set("client_name", clientName)
	}
	v.Set("scope", strings.Join(scope, " "))
	http.Redirect(w, r, "/consent?"+v.Encode(), http.StatusFound)
}

// requestValues re-encodes an authRequest's fields as url.Values, the
// building block for all three redirects above and for authorizeQuery.
func requestValues(req authRequest) url.Values {
	v := url.Values{}
	for k, val := range req.fields() {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v
}

// ── Portal ────────────────────────────────────────────────────────────────────

func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	subject, hadSession := s.subjectFromSession(r)
	s.endSession(w, r)
	if hadSession {
		go s.notifyBackchannelLogout(subject)
		if uris := s.frontchannelLogoutURIs(subject); len(uris) > 0 {
			s.redirectToLogoutPage(w, r, uris, "/")
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

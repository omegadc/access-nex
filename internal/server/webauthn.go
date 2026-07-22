package server

// WebAuthn / passkeys (FIDO2). Implemented as an alternative second factor
// alongside TOTP (not a passwordless first factor): after the password is
// verified, a user who has registered a security key/passkey can complete
// login with it instead of typing a TOTP code. Registration happens from
// the portal while already signed in.
//
// The actual protocol (attestation/assertion parsing, COSE key handling,
// challenge/signature verification) is delegated entirely to
// github.com/go-webauthn/webauthn — this is exactly the kind of
// cryptographic protocol surface (CBOR, COSE, attestation statement
// formats) that's worth a well-audited dependency rather than hand-rolling,
// unlike TOTP/DPoP which are simple enough to implement directly.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
)

type webauthnService struct {
	wa *webauthn.WebAuthn // nil if RP config couldn't be derived from the issuer; feature is then disabled

	mu       sync.Mutex
	sessions map[string]*webauthnCeremony
}

// webauthnCeremony is the server-side state for one in-flight
// registration or login ceremony, between "begin" and "finish".
type webauthnCeremony struct {
	Data      webauthn.SessionData
	Subject   string
	ExpiresAt time.Time
}

func newWebAuthnService(s *Server, rpDisplayName string) *webauthnService {
	rpID := "localhost"
	origins := []string{s.issuer}
	if u, err := url.Parse(s.issuer); err == nil && u.Hostname() != "" {
		rpID = u.Hostname()
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     origins,
	})
	if err != nil {
		// Config validation only fails for structurally invalid setups (e.g.
		// an unparsable issuer); log and disable the feature rather than
		// crash the server over what's meant to be an optional capability.
		s.log.Warn("webauthn disabled: could not build relying-party config", "error", err)
		return &webauthnService{sessions: make(map[string]*webauthnCeremony)}
	}
	return &webauthnService{wa: wa, sessions: make(map[string]*webauthnCeremony)}
}

func (w *webauthnService) enabled() bool { return w.wa != nil }

func (w *webauthnService) newCeremony(data webauthn.SessionData, subject string) string {
	token := secrets.RandomToken(24)
	w.mu.Lock()
	w.sessions[token] = &webauthnCeremony{Data: data, Subject: subject, ExpiresAt: time.Now().Add(5 * time.Minute)}
	w.mu.Unlock()
	return token
}

// consumeCeremony is single-use regardless of outcome: per the WebAuthn
// spec, a challenge must never be reused, whether the ceremony that
// consumed it succeeded or failed.
func (w *webauthnService) consumeCeremony(token string) (*webauthnCeremony, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.sessions[token]
	if c == nil {
		return nil, false
	}
	delete(w.sessions, token)
	if time.Now().After(c.ExpiresAt) {
		return nil, false
	}
	return c, true
}

// ── webauthn.User adapter ──────────────────────────────────────────────────────

type webauthnUser struct {
	u     *models.User
	creds []webauthn.Credential
}

func (u webauthnUser) WebAuthnID() []byte   { return []byte(u.u.Subject) }
func (u webauthnUser) WebAuthnName() string { return u.u.Username }
func (u webauthnUser) WebAuthnDisplayName() string {
	if u.u.Name != "" {
		return u.u.Name
	}
	return u.u.Username
}
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// hasWebAuthnCredentials reports whether subject can use a security key as
// their second factor — checked by the login challenge pages to decide
// whether to offer that option alongside TOTP.
func (s *Server) hasWebAuthnCredentials(subject string) bool {
	if !s.webauthn.enabled() {
		return false
	}
	user := s.userBySubject(subject)
	if user == nil {
		return false
	}
	n, err := s.store.CountWebAuthnCredentials(user.ID)
	return err == nil && n > 0
}

func (s *Server) loadWebAuthnUser(user *models.User) (webauthnUser, error) {
	rows, err := s.store.ListWebAuthnCredentials(user.ID)
	if err != nil {
		return webauthnUser{}, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, r := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(r.CredentialJSON, &c); err != nil {
			s.log.Warn("webauthn: skipping unreadable stored credential", "id", r.ID, "error", err)
			continue
		}
		creds = append(creds, c)
	}
	return webauthnUser{u: user, creds: creds}, nil
}

// ── Portal: register/manage credentials (requires an existing session) ────────

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok || !s.webauthn.enabled() {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	waUser, err := s.loadWebAuthnUser(user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	creation, sessionData, err := s.webauthn.wa.BeginRegistration(waUser)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	token := s.webauthn.newCeremony(*sessionData, subject)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "publicKey": creation.Response})
}

func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	var req struct {
		Token      string          `json:"token"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	ceremony, ok := s.webauthn.consumeCeremony(req.Token)
	if !ok || ceremony.Subject != subject {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "registration session expired — try again"})
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	waUser, err := s.loadWebAuthnUser(user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cred, err := s.webauthn.wa.CreateCredential(waUser, ceremony.Data, parsed)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	name := req.Name
	if name == "" {
		name = "Security key"
	}
	err = s.store.SaveWebAuthnCredential(&models.WebAuthnCredential{
		ID: b64(cred.ID), UserID: user.ID, Name: name, CredentialJSON: credJSON,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("webauthn_registered", subject, "", clientIP(r), name)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

func (s *Server) handlePortalWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteWebAuthnCredential(user.ID, r.Form.Get("credential_id")); err != nil {
		http.Error(w, "could not remove credential", http.StatusInternalServerError)
		return
	}
	s.store.Audit("webauthn_removed", subject, "", clientIP(r), r.Form.Get("credential_id"))
	http.Redirect(w, r, "/portal#security", http.StatusFound)
}

// ── Login: second-factor assertion, mirrors the TOTP pending-token flow ───────

func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	subject, ok := s.peekPendingSubject(req.Token)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "login session expired — start over"})
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown user"})
		return
	}
	waUser, err := s.loadWebAuthnUser(user)
	if err != nil || len(waUser.creds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no security keys registered"})
		return
	}
	assertion, sessionData, err := s.webauthn.wa.BeginLogin(waUser)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	waToken := s.webauthn.newCeremony(*sessionData, subject)
	writeJSON(w, http.StatusOK, map[string]any{"waToken": waToken, "publicKey": assertion.Response})
}

func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token      string          `json:"token"`   // pending-login token (identifies who's logging in)
		WAToken    string          `json:"waToken"` // this ceremony's challenge session
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	subject, ok := s.peekPendingSubject(req.Token)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "login session expired — start over"})
		return
	}
	ceremony, ok := s.webauthn.consumeCeremony(req.WAToken)
	if !ok || ceremony.Subject != subject {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "security key session expired — try again"})
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown user"})
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	waUser, err := s.loadWebAuthnUser(user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cred, err := s.webauthn.wa.ValidateLogin(waUser, ceremony.Data, parsed)
	if err != nil {
		s.store.Audit("login_2fa_failed", subject, "", clientIP(r), "webauthn: "+err.Error())
		s.metrics.loginResults.WithLabelValues("2fa_failed").Inc()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "verification failed"})
		return
	}
	// Persist the authenticator's updated signature counter so a cloned
	// authenticator (whose counter won't advance in lockstep) can be
	// detected on a future login.
	if credJSON, err := json.Marshal(cred); err == nil {
		_ = s.store.UpdateWebAuthnCredential(&models.WebAuthnCredential{ID: b64(cred.ID), CredentialJSON: credJSON})
	}

	s.deletePendingSecondFactor(req.Token)
	s.store.Audit("login_success", subject, "", clientIP(r), "with security key")
	s.metrics.loginResults.WithLabelValues("success").Inc()
	s.startSession(w, subject)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_in"})
}

// authorizeQuery re-encodes an authRequest's fields as a URL query string,
// used to rebuild the original /authorize URL so the browser can navigate
// straight back into the OAuth flow once a WebAuthn login sets the session
// cookie (the mid-flow challenge page is otherwise a dead end for GETs).
// The equivalent client-side ceremony (begin/get()/finish, base64url
// conversions) now lives in the Python frontend's static JS — see
// docs/FRONTEND.md — since it only ever talks to the JSON endpoints above.
func authorizeQuery(req authRequest) string {
	v := url.Values{}
	for k, val := range req.fields() {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v.Encode()
}

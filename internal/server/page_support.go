package server

// JSON endpoints that exist purely to give a server-rendering frontend (the
// Python/FastAPI frontend in this project, or any other) the data it needs
// to build pages that used to be inline HTML here in Go — home page counts,
// the public app directory, the portal's OAuth-config helper, 2FA
// enrollment state, and device-flow confirmation details. None of this is
// part of the stable contract in docs/openapi.yaml; it's frontend support
// data, kept in its own file so that boundary stays obvious.

import (
	"net/http"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
)

// GET /api/v1/stats — public counts shown on the home page.
func (s *Server) apiV1PublicStats(w http.ResponseWriter, r *http.Request) {
	users, apps, ext, err := s.store.Counts()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": s.issuer, "users": users, "apps": apps, "external_providers": ext,
	})
}

// GET /api/v1/stats/active — the signed-in user's server activity stats
// (portal "Live Server Stats" card).
func (s *Server) apiV1ActiveStats(w http.ResponseWriter, r *http.Request) {
	activeSessions, activeTokens, err := s.store.CountActive()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active_sessions": activeSessions, "active_tokens": activeTokens,
	})
}

// GET /api/v1/apps/public — unauthenticated app directory (no secrets), for
// the /apps page.
func (s *Server) apiV1PublicApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type appOut struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Public       bool     `json:"public"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	out := make([]appOut, 0, len(apps))
	for _, a := range apps {
		out = append(out, appOut{a.ID, a.Name, a.Public, a.RedirectURIs})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

// GET /api/v1/apps/configs — registered apps with enough detail (including
// the client secret for confidential apps) to fill in an OAuth client's
// settings, for the portal's "Client OAuth Configuration" helper.
//
// NOTE: this preserves the original server-rendered portal's behavior of
// showing every app's secret to any signed-in user, not just admins — that
// predates this refactor and isn't something introduced here. Worth
// revisiting (e.g. gating it like /api/admin/apps already is) if it wasn't
// intentional.
func (s *Server) apiV1AppConfigs(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type appOut struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Public       bool     `json:"public"`
		Secret       string   `json:"secret,omitempty"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	out := make([]appOut, 0, len(apps))
	for _, a := range apps {
		secret := a.Secret
		if a.Public {
			secret = ""
		}
		out = append(out, appOut{a.ID, a.Name, a.Public, secret, a.RedirectURIs})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out, "issuer": s.issuer})
}

// GET /api/v1/totp — this user's 2FA status for the portal's 2FA page:
// whether TOTP is enabled, a pending (unconfirmed) enrollment's QR code, and
// registered WebAuthn security keys.
func (s *Server) apiV1TOTPStatus(w http.ResponseWriter, r *http.Request) {
	user := s.userBySubject(subjectFrom(r.Context()))
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	resp := map[string]any{
		"enabled":          user.TOTPEnabled,
		"webauthn_enabled": s.webauthn.enabled(),
	}
	if !user.TOTPEnabled && user.TOTPSecret != "" {
		qr, err := qrDataURI(secrets.TOTPAuthURL("Access-Nex", user.Username, user.TOTPSecret))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate QR code"})
			return
		}
		resp["pending_secret"] = user.TOTPSecret
		resp["qr_data_uri"] = qr
	}
	if s.webauthn.enabled() {
		creds, err := s.store.ListWebAuthnCredentials(user.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		type credOut struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			CreatedAt string `json:"created_at"`
		}
		credsOut := make([]credOut, 0, len(creds))
		for _, c := range creds {
			credsOut = append(credsOut, credOut{c.ID, c.Name, c.CreatedAt.Format(time.RFC3339)})
		}
		resp["credentials"] = credsOut
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/v1/device?user_code=XXXX-XXXX — device-flow confirmation
// details, for the /device page's "connect this device?" step.
func (s *Server) apiV1DeviceInfo(w http.ResponseWriter, r *http.Request) {
	userCode := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("user_code")))
	if userCode == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_code is required"})
		return
	}
	d, err := s.store.GetDeviceCodeByUserCode(userCode)
	if err != nil || d.Status != models.DeviceStatusPending || time.Now().After(d.ExpiresAt) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "that code is invalid or has expired"})
		return
	}
	client := s.clientByID(d.ClientID)
	clientName := d.ClientID
	if client != nil {
		clientName = client.Name
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_code": userCode, "client_name": clientName, "scopes": d.Scope,
	})
}

package server

// RFC 8628 device authorization grant — the "enter this code at
// https://.../device" flow used by CLIs, TVs, and other input-constrained
// clients. Flow:
//
//  1. POST /device_authorize (device)      → device_code + user_code
//  2. GET  /device?user_code=XXXX-XXXX (browser, logged in) → approve/deny
//     (rendered by the Python frontend, backed by GET /api/v1/device — see
//     page_support.go)
//  3. POST /token grant_type=...device_code (device, polling) → tokens once approved

import (
	"crypto/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
)

const (
	deviceGrantType   = "urn:ietf:params:oauth:grant-type:device_code"
	deviceCodeTTL     = 10 * time.Minute
	devicePollSeconds = 5
	// Excludes 0/O/1/I/L to avoid characters that are easy to mistype when
	// copying a code off a screen.
	userCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
)

func generateUserCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = userCodeAlphabet[int(buf[i])%len(userCodeAlphabet)]
	}
	return string(buf[:4]) + "-" + string(buf[4:]), nil
}

// handleDeviceAuthorize starts a device flow for a registered client.
func (s *Server) handleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form body")
		return
	}
	clientID := r.Form.Get("client_id")
	client := s.clientByID(clientID)
	if client == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
		return
	}
	scope := parseScope(r.Form.Get("scope"))
	if len(scope) == 0 {
		scope = []string{"openid"}
	}

	deviceCode := secrets.RandomToken(32)
	userCode, err := generateUserCode()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not generate user code")
		return
	}
	d := &models.DeviceCode{
		DeviceCode:   deviceCode,
		UserCode:     userCode,
		ClientID:     clientID,
		Scope:        scope,
		IntervalSecs: devicePollSeconds,
		ExpiresAt:    time.Now().Add(deviceCodeTTL),
	}
	if err := s.store.SaveDeviceCode(d); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not save device code")
		return
	}
	s.store.Audit("device_authorize_started", "", clientID, clientIP(r), userCode)

	verificationURI := s.endpoint("/device")
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + userCode,
		"expires_in":                int(deviceCodeTTL.Seconds()),
		"interval":                  devicePollSeconds,
	})
}

// handleDeviceVerify is the approve/deny decision posted from the frontend's
// /device page (GET /api/v1/device supplies that page the code/client/scope
// details to render — see page_support.go).
func (s *Server) handleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	userCode := strings.ToUpper(strings.TrimSpace(r.Form.Get("user_code")))
	decision := r.Form.Get("decision")
	status := models.DeviceStatusDenied
	if decision == "approve" {
		status = models.DeviceStatusApproved
	}
	if err := s.store.ResolveDeviceCode(userCode, subject, status); err != nil {
		http.Redirect(w, r, "/device?error=invalid", http.StatusFound)
		return
	}
	s.store.Audit("device_"+status, subject, "", clientIP(r), userCode)
	http.Redirect(w, r, "/device/result?approved="+strconv.FormatBool(status == models.DeviceStatusApproved), http.StatusFound)
}

// handleDeviceCodeGrant implements the polling side of RFC 8628 at /token.
func (s *Server) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request, client *models.App, jkt string) {
	deviceCode := r.Form.Get("device_code")
	if deviceCode == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing device_code")
		return
	}
	d, err := s.store.GetDeviceCode(deviceCode)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Unknown device_code")
		return
	}
	if d.ClientID != client.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "device_code issued to a different client")
		return
	}
	if time.Now().After(d.ExpiresAt) {
		_ = s.store.DeleteDeviceCode(deviceCode)
		writeOAuthError(w, http.StatusBadRequest, "expired_token", "The device code has expired")
		return
	}
	tooFast, err := s.store.MarkDevicePolled(deviceCode)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not record poll")
		return
	}
	if tooFast {
		writeOAuthError(w, http.StatusBadRequest, "slow_down", "Polling too frequently")
		return
	}
	switch d.Status {
	case models.DeviceStatusDenied:
		_ = s.store.DeleteDeviceCode(deviceCode)
		writeOAuthError(w, http.StatusBadRequest, "access_denied", "The user denied the request")
		return
	case models.DeviceStatusPending:
		writeOAuthError(w, http.StatusBadRequest, "authorization_pending", "Waiting for user authorization")
		return
	}

	response, err := s.issueTokenResponse(client, d.Subject, d.Scope, nil, "", time.Now(), "", jkt)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	_ = s.store.DeleteDeviceCode(deviceCode)
	s.store.Audit("token_issued", d.Subject, client.ID, clientIP(r), "device_code")
	s.metrics.tokensIssued.WithLabelValues(deviceGrantType).Inc()
	writeJSON(w, http.StatusOK, response)
}

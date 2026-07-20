package server

// RFC 8628 device authorization grant — the "enter this code at
// https://.../device" flow used by CLIs, TVs, and other input-constrained
// clients. Flow:
//
//  1. POST /device_authorize (device)      → device_code + user_code
//  2. GET  /device?user_code=XXXX-XXXX (browser, logged in) → approve/deny
//  3. POST /token grant_type=...device_code (device, polling) → tokens once approved

import (
	"crypto/rand"
	"net/http"
	"net/url"
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

// handleDeviceVerify is the browser-facing page: enter the code, then
// approve or deny the device.
func (s *Server) handleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
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
			s.renderDevicePage(w, "", "That code is invalid or has expired.")
			return
		}
		s.store.Audit("device_"+status, subject, "", clientIP(r), userCode)
		s.renderDeviceResult(w, status == models.DeviceStatusApproved)
		return
	}

	userCode := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("user_code")))
	if userCode == "" {
		s.renderDevicePage(w, "", "")
		return
	}
	d, err := s.store.GetDeviceCodeByUserCode(userCode)
	if err != nil || d.Status != models.DeviceStatusPending || time.Now().After(d.ExpiresAt) {
		s.renderDevicePage(w, "", "That code is invalid or has expired.")
		return
	}
	client := s.clientByID(d.ClientID)
	clientName := d.ClientID
	if client != nil {
		clientName = client.Name
	}
	s.renderDeviceConfirm(w, userCode, clientName, d.Scope)
}

func (s *Server) renderDevicePage(w http.ResponseWriter, prefill, errMsg string) {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="error">` + esc(errMsg) + `</div>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Device Sign-In — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">Device Sign-In</div>` + errHTML + `
  <h1>Enter Code</h1>
  <p class="hint">Enter the code shown on your device.</p>
  <form method="GET" action="/device">
    <label for="c">Code</label>
    <input type="text" id="c" name="user_code" value="` + esc(prefill) + `" placeholder="XXXX-XXXX" style="text-transform:uppercase" required autofocus>
    <button type="submit">Continue</button>
  </form>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) renderDeviceConfirm(w http.ResponseWriter, userCode, clientName string, scopes []string) {
	scopeItems := ""
	for _, sc := range scopes {
		desc := scopeDescriptions[sc]
		if desc == "" {
			desc = "Scope: " + sc
		}
		scopeItems += `<li><strong>` + esc(sc) + `</strong> — ` + esc(desc) + `</li>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Device Sign-In — Access-Nex</title>` + loginStyle + `<style>
ul.scopes{margin:0 0 22px 0;padding:0;list-style:none}
ul.scopes li{padding:9px 12px;background:#f8f9ff;border-left:4px solid #667eea;border-radius:4px;margin-bottom:8px;font-size:14px}
.btnrow{display:flex;gap:10px}.btnrow button{flex:1}button.deny{background:#eee;color:#555}
</style></head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">Device Sign-In</div>
  <h1>Connect this device?</h1>
  <p class="hint"><strong>` + esc(clientName) + `</strong> wants access to:</p>
  <ul class="scopes">` + scopeItems + `</ul>
  <form method="post" action="/device">
    <input type="hidden" name="user_code" value="` + esc(userCode) + `">
    <div class="btnrow">
      <button type="submit" name="decision" value="approve">Allow</button>
      <button type="submit" name="decision" value="deny" class="deny">Deny</button>
    </div>
  </form>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) renderDeviceResult(w http.ResponseWriter, approved bool) {
	msg := "Device connected. You can close this window."
	if !approved {
		msg = "Request denied. You can close this window."
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Device Sign-In — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card"><div class="logo">🔐 Access-Nex</div><h1>` + esc(msg) + `</h1></div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
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
	writeJSON(w, http.StatusOK, response)
}

package server

// TOTP (RFC 6238) two-factor auth: enrollment with a scannable QR code (from
// the portal, while logged in) and the second login step (from /authorize
// and /login) once enabled.

import (
	"encoding/base64"
	"html/template"
	"net/http"

	"github.com/skip2/go-qrcode"

	"github.com/omegadc/access-nex/internal/secrets"
)

// renderTOTPChallenge is the second-factor entry page shown mid-OAuth-flow
// (from /authorize), mirroring renderLogin's hidden-field round-tripping.
// The totp_token field always renders (WebAuthn's JS locates it by name
// even when the TOTP code input itself is hidden for a WebAuthn-only user).
// {{.WebAuthnJS}} is pre-rendered HTML (a button + inline script), not
// escaped text, hence html/template.HTML rather than string.
var totpChallengeTemplate = template.Must(template.New("totp").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Two-Factor — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">Two-Factor Authentication</div>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <h1>Verify it's you</h1>
  {{if .ClientName}}<div class="app-info"><strong>Signing in to:</strong><br>{{.ClientName}}</div>{{end}}
  <form method="post" action="/authorize">
    {{range $k,$v := .Fields}}{{if $v}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}{{end}}
    <input type="hidden" name="totp_token" value="{{.Token}}">
    {{if .HasTOTP}}
    <p class="hint">Open your authenticator app and enter the current 6-digit code.</p>
    <label for="c">Code</label>
    <input type="text" id="c" name="totp_code" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" required autofocus>
    <button type="submit">Verify</button>
    {{end}}
  </form>
  {{.WebAuthnJS}}
</div></body></html>`))

func (s *Server) renderTOTPChallenge(w http.ResponseWriter, req authRequest, clientName, subject, token, errMsg string) {
	user := s.userBySubject(subject)
	data := struct {
		Error      string
		ClientName string
		Token      string
		Fields     map[string]string
		HasTOTP    bool
		WebAuthnJS template.HTML
	}{Error: errMsg, ClientName: clientName, Token: token, Fields: req.fields(), HasTOTP: user != nil && user.TOTPEnabled}
	if s.hasWebAuthnCredentials(subject) {
		redirectTo := "/authorize?" + authorizeQuery(req)
		onSuccess := `window.location.href = ` + jsonString(redirectTo) + `;`
		data.WebAuthnJS = template.HTML(webauthnSecurityKeyButton() + webauthnJSHelpers() + webauthnLoginScript("form", onSuccess))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := totpChallengeTemplate.Execute(w, data); err != nil {
		s.log.Error("render totp challenge", "error", err)
	}
}

// ── Portal enrollment ──────────────────────────────────────────────────────────

func (s *Server) handleTOTPPage(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login?return_to=/portal/2fa", http.StatusFound)
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		http.Redirect(w, r, "/login?return_to=/portal/2fa", http.StatusFound)
		return
	}

	var body string
	switch {
	case user.TOTPEnabled:
		body = `
    <p style="margin-bottom:20px;color:#155724;background:#d4edda;padding:10px 14px;border-radius:6px">✓ Two-factor authentication is enabled.</p>
    <form method="POST" action="/portal/2fa/disable">
      <label for="c">Enter a code to disable 2FA</label>
      <input type="text" id="c" name="totp_code" inputmode="numeric" maxlength="6" required>
      <button type="submit" style="background:#dc2626">Disable 2FA</button>
    </form>`
	case user.TOTPSecret != "":
		qr, err := qrDataURI(secrets.TOTPAuthURL("Access-Nex", user.Username, user.TOTPSecret))
		if err != nil {
			http.Error(w, "could not generate QR code", http.StatusInternalServerError)
			return
		}
		body = `
    <p class="hint">Scan this with your authenticator app (Google Authenticator, Authy, 1Password, …), then enter the 6-digit code it shows to confirm.</p>
    <img src="` + qr + `" alt="QR code" style="display:block;margin:0 auto 16px;width:200px;height:200px">
    <p style="text-align:center;font-family:monospace;font-size:13px;background:#f0f0f0;padding:8px;border-radius:6px;margin-bottom:20px;word-break:break-all">` + esc(user.TOTPSecret) + `</p>
    <form method="POST" action="/portal/2fa/confirm">
      <label for="c">Confirmation code</label>
      <input type="text" id="c" name="totp_code" inputmode="numeric" maxlength="6" required autofocus>
      <button type="submit">Confirm & Enable</button>
    </form>`
	default:
		body = `
    <p class="hint">Two-factor authentication adds a second step (a 6-digit code from an authenticator app) to your login.</p>
    <form method="POST" action="/portal/2fa/enroll"><button type="submit">Set Up 2FA</button></form>`
	}

	securityKeysBody := ""
	if s.webauthn.enabled() {
		creds, _ := s.store.ListWebAuthnCredentials(user.ID)
		rows := ""
		for _, c := range creds {
			rows += `<tr><td>` + esc(c.Name) + `</td><td>` + c.CreatedAt.Format("2006-01-02") + `</td><td>
			<form method="POST" action="/portal/webauthn/delete" style="margin:0">
			  <input type="hidden" name="credential_id" value="` + esc(c.ID) + `">
			  <button type="submit" class="del">Remove</button>
			</form></td></tr>`
		}
		if rows == "" {
			rows = `<tr><td colspan="3" style="text-align:center;color:#999;padding:16px">No security keys registered</td></tr>`
		}
		securityKeysBody = `
  <table style="margin-bottom:16px"><tr><th>Name</th><th>Added</th><th></th></tr>` + rows + `</table>
  <button class="btn" onclick="registerSecurityKey()">+ Add a Security Key</button>
  <p id="wa-reg-msg" style="margin-top:8px;font-size:13px;color:#888"></p>` + webauthnJSHelpers() + webauthnRegisterScript()
	}

	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Two-Factor — Access-Nex</title>` + pageStyle + `</head><body>
<div class="header"><h1>🔐 Two-Factor Authentication</h1></div>
<div class="container">
  <div class="section"><h2>Authenticator App (TOTP)</h2>` + body + `</div>
  <div class="section"><h2>Security Keys &amp; Passkeys</h2>
    <p class="hint" style="margin-bottom:14px">Use a hardware security key, or your device's built-in passkey support (Windows Hello, Touch ID, …), as a second factor.</p>` + securityKeysBody + `
  </div>
  <p style="margin-top:16px"><a href="/portal">← Back to portal</a></p>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
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
	secret, err := secrets.GenerateTOTPSecret()
	if err != nil {
		http.Error(w, "could not generate secret", http.StatusInternalServerError)
		return
	}
	if err := s.store.SetPendingTOTPSecret(user.Username, secret); err != nil {
		http.Error(w, "could not save secret", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/portal/2fa", http.StatusFound)
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
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
	if err := r.ParseForm(); err != nil || !secrets.VerifyTOTP(user.TOTPSecret, r.Form.Get("totp_code")) {
		http.Redirect(w, r, "/portal/2fa?error=invalid", http.StatusFound)
		return
	}
	if err := s.store.ConfirmTOTP(user.Username); err != nil {
		http.Error(w, "could not enable 2FA", http.StatusInternalServerError)
		return
	}
	s.store.Audit("2fa_enabled", subject, "", clientIP(r), "")
	http.Redirect(w, r, "/portal/2fa", http.StatusFound)
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
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
	if err := r.ParseForm(); err != nil || !secrets.VerifyTOTP(user.TOTPSecret, r.Form.Get("totp_code")) {
		http.Redirect(w, r, "/portal/2fa?error=invalid", http.StatusFound)
		return
	}
	if err := s.store.DisableTOTP(user.Username); err != nil {
		http.Error(w, "could not disable 2FA", http.StatusInternalServerError)
		return
	}
	s.store.Audit("2fa_disabled", subject, "", clientIP(r), "")
	http.Redirect(w, r, "/portal/2fa", http.StatusFound)
}

// qrDataURI renders text as a PNG QR code and returns it as a data: URI
// ready to drop straight into an <img src="...">.
func qrDataURI(text string) (string, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

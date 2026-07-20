package server

// HTML pages: home dashboard, direct login, user portal (with Portainer OAuth
// config helper), and the registered-applications list.

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
)

const pageStyle = `<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;color:#333}
.header{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:32px 20px;text-align:center}
.header h1{font-size:28px;margin-bottom:6px}.header p{opacity:.85}
.container{max-width:1000px;margin:32px auto;padding:0 20px 40px}
.section{background:#fff;border-radius:8px;padding:26px;margin-bottom:24px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
.section h2{color:#667eea;font-size:17px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}
.card{background:#f9f9f9;padding:16px;border-radius:6px;border-left:4px solid #667eea}
.card strong{display:block;color:#667eea;margin-bottom:6px;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.card span{font-size:20px;font-weight:700}
code{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:12px;font-family:monospace}
.ep{margin-bottom:8px;padding:9px 12px;background:#f0f0f0;border-radius:4px;font-family:monospace;font-size:13px}
.method{color:#667eea;font-weight:bold;margin-right:8px}
a{color:#667eea;text-decoration:none}a:hover{text-decoration:underline}
.btn{display:inline-block;padding:9px 20px;border-radius:6px;font-weight:600;font-size:14px;text-decoration:none;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:14px}
th{background:#f5f5f5;padding:11px 14px;text-align:left;font-weight:600;color:#667eea;border-bottom:2px solid #eee}
td{padding:11px 14px;border-bottom:1px solid #f0f0f0;vertical-align:top}
.badge{background:#d4edda;color:#155724;padding:3px 10px;border-radius:10px;font-size:12px;font-weight:600}
.del{background:#fee2e2;color:#dc2626;border:none;border-radius:5px;padding:6px 14px;cursor:pointer;font-size:13px}
.footer{text-align:center;padding:24px;color:#888;font-size:13px}
</style>`

const loginStyle = `<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:12px;padding:40px;width:100%;max-width:410px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.logo{font-size:26px;font-weight:700;color:#667eea;text-align:center}
.sub{font-size:11px;color:#aaa;text-align:center;text-transform:uppercase;letter-spacing:1px;margin-bottom:26px}
h1{font-size:20px;color:#333;margin-bottom:6px}
.hint{font-size:13px;color:#888;margin-bottom:22px}
.app-info{background:#f8f9ff;border-left:4px solid #667eea;padding:11px 14px;border-radius:4px;margin-bottom:20px;font-size:14px}
label{display:block;font-size:12px;font-weight:600;color:#555;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px}
input{width:100%;padding:11px 13px;border:1px solid #ddd;border-radius:6px;font-size:15px;margin-bottom:16px}
input:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.12)}
button{width:100%;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer}
.error{background:#fee2e2;border:1px solid #fca5a5;color:#dc2626;padding:11px 14px;border-radius:6px;font-size:14px;margin-bottom:18px}
.footer{text-align:center;margin-top:20px;font-size:12px;color:#aaa}.footer a{color:#667eea}
</style>`

// ── Home dashboard ────────────────────────────────────────────────────────────

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	users, apps, ext, err := s.store.Counts()
	if err != nil {
		log.Printf("home: counts: %v", err)
	}

	headerRight := `<div style="margin-top:16px"><a href="/login" class="btn" style="background:#fff;color:#667eea">Sign In</a></div>`
	if subject, ok := s.subjectFromSession(r); ok {
		if u := s.userBySubject(subject); u != nil {
			headerRight = `<div style="margin-top:16px;display:flex;align-items:center;justify-content:center;gap:14px">
			  <span style="background:rgba(255,255,255,.2);padding:6px 14px;border-radius:20px;font-size:14px">👤 ` + esc(u.Username) + `</span>
			  <a href="/portal" class="btn" style="background:#fff;color:#667eea">My Account</a>
			  <a href="/portal/logout" class="btn" style="background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.4)">Sign Out</a>
			</div>`
		}
	}

	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Access-Nex</title>` + pageStyle + `</head><body>
<div class="header"><h1>🔐 Access-Nex</h1><p>OAuth2 &amp; OpenID Connect Provider</p>` + headerRight + `</div>
<div class="container">
  <div class="section"><h2>Status</h2><div class="grid">
    <div class="card"><strong>Status</strong><span><span class="badge">✓ Running</span></span></div>
    <div class="card"><strong>Issuer</strong><span style="font-size:13px"><code>` + esc(s.issuer) + `</code></span></div>
    <div class="card"><strong>Users</strong><span>` + fmt.Sprint(users) + `</span></div>
    <div class="card"><strong>Applications</strong><span>` + fmt.Sprint(apps) + `</span></div>
    <div class="card"><strong>Ext. Providers</strong><span>` + fmt.Sprint(ext) + `</span></div>
  </div></div>
  <div class="section"><h2>OIDC / OAuth2 Endpoints</h2>
    <div class="ep"><span class="method">GET</span><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a> — Discovery</div>
    <div class="ep"><span class="method">GET/POST</span>/authorize — Authorization</div>
    <div class="ep"><span class="method">POST</span>/token — Token exchange</div>
    <div class="ep"><span class="method">GET</span>/userinfo — User claims</div>
    <div class="ep"><span class="method">GET</span><a href="/jwks">/jwks</a> — Public key set</div>
    <div class="ep"><span class="method">POST</span>/revoke &nbsp;/introspect &nbsp;/register &nbsp;/end_session</div>
  </div>
  <div class="section"><h2>OAuth Proxy (External Providers)</h2>
    <div class="ep"><span class="method">GET</span><a href="/oauth/providers">/oauth/providers</a> — list enabled external providers</div>
    <div class="ep"><span class="method">GET</span>/oauth/start?provider_id=X&amp;client_id=Y&amp;redirect_uri=Z — begin SSO</div>
    <div class="ep"><span class="method">GET</span>/oauth/callback — receive code → issue local auth code</div>
  </div>
  <div class="section"><h2>Quick Links</h2>
    <a class="btn" href="/apps">Applications</a>&nbsp;
    <a class="btn" href="/login">Login Portal</a>&nbsp;
    <a class="btn" href="/.well-known/openid-configuration">Discovery Doc</a>
  </div>
</div>
<div class="footer">Access-Nex — OAuth2 &amp; OIDC Provider</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

// ── Direct login (session portal, bypasses the OAuth flow) ───────────────────

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.subjectFromSession(r); ok {
		http.Redirect(w, r, "/portal", http.StatusFound)
		return
	}
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/portal"
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if rt := r.Form.Get("return_to"); rt != "" {
			returnTo = rt
		}
		if !s.loginLimiter.allow(clientIP(r)) {
			s.renderDirectLoginPage(w, "Too many attempts — try again in a minute", returnTo)
			return
		}
		user, ok := s.verifyPassword(r.Form.Get("username"), r.Form.Get("password"), clientIP(r))
		if !ok {
			s.renderDirectLoginPage(w, "Invalid username or password", returnTo)
			return
		}
		if user.TOTPEnabled {
			token := s.newTOTPPending(user.Subject)
			s.renderDirectTOTPPage(w, token, returnTo, "")
			return
		}
		s.store.Audit("login_success", user.Subject, "", clientIP(r), "")
		s.startSession(w, user.Subject)
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	s.renderDirectLoginPage(w, "", returnTo)
}

// handleLoginTOTP verifies the second factor for a direct portal login
// (started by handleLogin above).
func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
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
		s.renderDirectLoginPage(w, "Session expired — sign in again", returnTo)
		return
	}
	user := s.userBySubject(subject)
	if user == nil || !secrets.VerifyTOTP(user.TOTPSecret, r.Form.Get("totp_code")) {
		s.store.Audit("login_2fa_failed", subject, "", clientIP(r), "")
		s.renderDirectTOTPPage(w, s.newTOTPPending(subject), returnTo, "Invalid code — try again")
		return
	}
	s.store.Audit("login_success", subject, "", clientIP(r), "with 2FA")
	s.startSession(w, subject)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (s *Server) renderDirectTOTPPage(w http.ResponseWriter, token, returnTo, errMsg string) {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="error">` + esc(errMsg) + `</div>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Two-Factor — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">Two-Factor Authentication</div>` + errHTML + `
  <h1>Enter your code</h1>
  <p class="hint">Open your authenticator app and enter the current 6-digit code.</p>
  <form method="POST" action="/login/2fa">
    <input type="hidden" name="totp_token" value="` + esc(token) + `">
    <input type="hidden" name="return_to" value="` + esc(returnTo) + `">
    <label for="c">Code</label>
    <input type="text" id="c" name="totp_code" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" required autofocus>
    <button type="submit">Verify</button>
  </form>
  <div class="footer"><a href="/login">← Back to sign in</a></div>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) renderDirectLoginPage(w http.ResponseWriter, errMsg, returnTo string) {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="error">` + esc(errMsg) + `</div>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign In — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">Admin Portal</div>` + errHTML + `
  <h1>Sign In</h1>
  <p class="hint">Enter your access-nex credentials to validate your account and inspect session details.</p>
  <form method="POST" action="/login">
    <input type="hidden" name="return_to" value="` + esc(returnTo) + `">
    <label for="u">Username</label>
    <input type="text" id="u" name="username" autocomplete="username" required autofocus>
    <label for="p">Password</label>
    <input type="password" id="p" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer"><a href="/">← Back to home</a></div>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

// ── Portal ────────────────────────────────────────────────────────────────────

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login?return_to=/portal", http.StatusFound)
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		http.Redirect(w, r, "/login?return_to=/portal", http.StatusFound)
		return
	}

	activeSessions, activeTokens, err := s.store.CountActive()
	if err != nil {
		log.Printf("portal: count active: %v", err)
	}

	apps, _ := s.store.ListApps()
	appOptions := `<option value="">— select an app —</option>`
	for _, a := range apps {
		secret := a.Secret
		if a.Public {
			secret = ""
		}
		appOptions += `<option value="` + esc(a.ID) + `" data-secret="` + esc(secret) +
			`" data-uris="` + esc(strings.Join(a.RedirectURIs, ",")) + `">` +
			esc(a.Name) + ` (` + esc(a.ID) + `)</option>`
	}

	// Grants: apps the user has approved, with revoke buttons.
	grants, _ := s.store.ListGrants(subject)
	grantRows := `<tr><td colspan="3" style="text-align:center;color:#999;padding:20px">No applications authorized yet</td></tr>`
	if len(grants) > 0 {
		grantRows = ""
		for _, g := range grants {
			appName := g.ClientID
			if a, err := s.store.GetApp(g.ClientID); err == nil {
				appName = a.Name
			}
			grantRows += `<tr><td>` + esc(appName) + `</td><td>` + esc(strings.Join(g.Scopes, ", ")) + `</td><td>
			<form method="POST" action="/portal/grants/revoke" style="margin:0">
			  <input type="hidden" name="client_id" value="` + esc(g.ClientID) + `">
			  <button type="submit" class="del">Revoke</button>
			</form></td></tr>`
		}
	}

	// Sessions: this device's session is flagged so it isn't confused with others.
	currentSessionID := ""
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		currentSessionID = cookie.Value
	}
	sessions, _ := s.store.ListSessions(subject)
	sessionRows := ""
	for _, sess := range sessions {
		label := sess.ID
		if len(label) > 12 {
			label = label[:12] + "…"
		}
		here := ""
		if sess.ID == currentSessionID {
			here = ` <span class="badge">this device</span>`
		}
		sessionRows += `<tr><td><code>` + esc(label) + `</code>` + here + `</td><td>` + sess.CreatedAt.Format("2006-01-02 15:04") + `</td><td>` + sess.ExpiresAt.Format("2006-01-02 15:04") + `</td><td>
		<form method="POST" action="/portal/sessions/revoke" style="margin:0">
		  <input type="hidden" name="session_id" value="` + esc(sess.ID) + `">
		  <button type="submit" class="del">Sign Out</button>
		</form></td></tr>`
	}

	// Linked external identities.
	identities, _ := s.store.ListIdentities(user.ID)
	identityRows := `<tr><td colspan="3" style="text-align:center;color:#999;padding:20px">No linked accounts</td></tr>`
	if len(identities) > 0 {
		identityRows = ""
		for _, id := range identities {
			providerName := id.ProviderID
			if p, err := s.store.GetProvider(id.ProviderID); err == nil {
				providerName = p.Name
			}
			identityRows += `<tr><td>` + esc(providerName) + `</td><td>` + esc(id.ExternalID) + `</td><td>
			<form method="POST" action="/portal/identities/unlink" style="margin:0">
			  <input type="hidden" name="identity_id" value="` + fmt.Sprint(id.ID) + `">
			  <button type="submit" class="del">Unlink</button>
			</form></td></tr>`
		}
	}
	twoFAStatus := `<a href="/portal/2fa" class="btn">Set Up 2FA</a>`
	if user.TOTPEnabled {
		twoFAStatus = `<span class="badge">✓ Enabled</span> <a href="/portal/2fa" class="btn" style="margin-left:8px">Manage</a>`
	}

	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Portal — Access-Nex</title>` + pageStyle + `</head><body>
<div class="header"><h1>🔐 Access-Nex Portal</h1>
  <div style="margin-top:12px"><a href="/" class="btn" style="background:rgba(255,255,255,.2)">Home</a>
  <a href="/portal/logout" class="btn" style="background:rgba(255,255,255,.2)">Sign Out</a></div></div>
<div class="container">

  <div class="section"><h2>Signed-In User <span class="badge">✓ Validated</span></h2>
    <div class="grid">
      <div class="card"><strong>Display Name</strong><span style="font-size:15px">` + esc(user.Name) + `</span></div>
      <div class="card"><strong>Username</strong><span style="font-size:15px">` + esc(user.Username) + `</span></div>
      <div class="card"><strong>Email</strong><span style="font-size:15px">` + esc(user.Email) + `</span></div>
      <div class="card"><strong>Subject</strong><span style="font-size:12px"><code>` + esc(user.Subject) + `</code></span></div>
    </div></div>

  <div class="section"><h2>Live Server Stats</h2>
    <div class="grid">
      <div class="card"><strong>Active Sessions</strong><span>` + fmt.Sprint(activeSessions) + `</span></div>
      <div class="card"><strong>Active Tokens</strong><span>` + fmt.Sprint(activeTokens) + `</span></div>
    </div></div>

  <div class="section" id="security"><h2>Security</h2>
    <div class="grid" style="margin-bottom:20px">
      <div class="card"><strong>Two-Factor Auth</strong><span style="font-size:14px">` + twoFAStatus + `</span></div>
    </div>
    <form method="POST" action="/portal/password">
      <label for="cp">Current Password</label>
      <input type="password" id="cp" name="current_password" autocomplete="current-password">
      <label for="np">New Password</label>
      <input type="password" id="np" name="new_password" autocomplete="new-password" minlength="8" required>
      <button type="submit" class="btn">Change Password</button>
    </form>
  </div>

  <div class="section" id="grants"><h2>Authorized Applications</h2>
    <table><tr><th>Application</th><th>Scopes</th><th></th></tr>` + grantRows + `</table>
  </div>

  <div class="section" id="sessions"><h2>Active Sessions</h2>
    <table><tr><th>Session</th><th>Started</th><th>Expires</th><th></th></tr>` + sessionRows + `</table>
  </div>

  <div class="section" id="identities"><h2>Linked Accounts</h2>
    <p style="font-size:13px;color:#888;margin-bottom:14px">External sign-in providers linked to this account.</p>
    <table><tr><th>Provider</th><th>External ID</th><th></th></tr>` + identityRows + `</table>
  </div>

  <div class="section"><h2>Client OAuth Configuration</h2>
    <p style="font-size:14px;color:#666;margin-bottom:16px">
      Select a registered application to generate the OAuth settings to paste into a client
      (e.g. Portainer → Settings → Authentication → OAuth).</p>
    <select id="appSel" onchange="fillConfig()" style="width:100%;padding:9px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;margin-bottom:14px">` + appOptions + `</select>
    <div id="cfg" style="display:none">
      <table>
        <tr><th>Setting</th><th>Value</th></tr>
        <tr><td>Provider</td><td><code>Custom</code></td></tr>
        <tr><td>Client ID</td><td><code id="c-cid"></code></td></tr>
        <tr><td>Client Secret</td><td><code id="c-sec"></code></td></tr>
        <tr><td>Authorization URL</td><td><code>` + esc(s.issuer) + `/authorize</code></td></tr>
        <tr><td>Access Token URL</td><td><code>` + esc(s.issuer) + `/token</code></td></tr>
        <tr><td>Resource URL</td><td><code>` + esc(s.issuer) + `/userinfo</code></td></tr>
        <tr><td>Logout URL</td><td><code>` + esc(s.issuer) + `/end_session</code></td></tr>
        <tr><td>Redirect URL</td><td><code id="c-redir"></code></td></tr>
        <tr><td>User Identifier</td><td><code>email</code></td></tr>
        <tr><td>Scopes</td><td><code>openid profile email</code></td></tr>
        <tr><td>Token Auth Method</td><td><code>client_secret_post</code></td></tr>
      </table>
      <div style="margin-top:16px">
        <button class="btn" onclick="testFlow()">▶ Run OAuth Flow Test</button>
        <span id="flowResult" style="margin-left:12px;font-size:13px;color:#555"></span>
      </div>
    </div>
  </div>

</div>
<div class="footer">Access-Nex — OAuth2 &amp; OIDC Provider</div>
<script>
function fillConfig() {
  var sel = document.getElementById('appSel');
  var opt = sel.options[sel.selectedIndex];
  if (!opt.value) { document.getElementById('cfg').style.display='none'; return; }
  document.getElementById('c-cid').textContent = opt.value;
  document.getElementById('c-sec').textContent = opt.getAttribute('data-secret') || '(public client — no secret)';
  var uris = (opt.getAttribute('data-uris') || '').split(',');
  document.getElementById('c-redir').textContent = uris[0] || '';
  document.getElementById('cfg').style.display = 'block';
}
function testFlow() {
  var sel = document.getElementById('appSel');
  var opt = sel.options[sel.selectedIndex];
  if (!opt.value) { alert('Select an application first'); return; }
  var uris = (opt.getAttribute('data-uris') || '').split(',');
  if (!uris[0]) { alert('No redirect URI registered for this app'); return; }
  var state = Math.random().toString(36).slice(2);
  var url = '/authorize?response_type=code&client_id=' + encodeURIComponent(opt.value)
          + '&redirect_uri=' + encodeURIComponent(uris[0])
          + '&scope=openid+profile+email&state=' + state;
  document.getElementById('flowResult').textContent = 'Opening OAuth flow in new tab…';
  window.open(url, '_blank');
}
</script></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	subject, hadSession := s.subjectFromSession(r)
	s.endSession(w, r)
	if hadSession {
		go s.notifyBackchannelLogout(subject)
		if uris := s.frontchannelLogoutURIs(subject); len(uris) > 0 {
			s.renderFrontchannelLogoutPage(w, uris, "/")
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// ── Applications list ─────────────────────────────────────────────────────────

func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps()
	if err != nil {
		http.Error(w, "could not list applications", http.StatusInternalServerError)
		return
	}
	rows := ""
	if len(apps) == 0 {
		rows = `<tr><td colspan="4" style="text-align:center;padding:40px;color:#999">No applications registered</td></tr>`
	}
	for _, a := range apps {
		t := "Confidential"
		if a.Public {
			t = "Public (PKCE)"
		}
		uris := ""
		for _, u := range a.RedirectURIs {
			uris += `<div style="font-size:13px;margin-bottom:4px">` + esc(u) + `</div>`
		}
		rows += `<tr><td>` + esc(a.Name) + `</td><td><code>` + esc(a.ID) + `</code></td><td>` + t + `</td><td>` + uris + `</td></tr>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Apps — Access-Nex</title>` + pageStyle + `</head><body>
<div class="header"><h1>Registered Applications</h1></div>
<div class="container"><div class="section"><table>
<tr><th>Name</th><th>Client ID</th><th>Type</th><th>Redirect URIs</th></tr>` + rows + `</table>
<p style="margin-top:16px"><a href="/">← Back to home</a></p></div></div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

// ── OAuth /authorize login form ───────────────────────────────────────────────

var authorizeLoginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Access-Nex Sign In</title>` + loginStyle + `</head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">OAuth2 &amp; OIDC Provider</div>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <h1>Welcome</h1>
  {{if .ClientName}}<div class="app-info"><strong>Signing in to:</strong><br>{{.ClientName}}</div>{{end}}
  <p class="hint">Sign in with your Access-Nex account to continue</p>
  <form method="post" action="/authorize">
    {{range $k,$v := .Fields}}{{if $v}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}{{end}}
    <label for="username">Username</label>
    <input type="text" id="username" name="username" autocomplete="username" required autofocus>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer">Access-Nex | <a href="/">Home</a></div>
</div></body></html>`))

func (s *Server) renderLogin(w http.ResponseWriter, req authRequest, clientName, message string) {
	data := struct {
		Error      string
		ClientName string
		Fields     map[string]string
	}{Error: message, ClientName: clientName, Fields: req.fields()}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := authorizeLoginTemplate.Execute(w, data); err != nil {
		log.Printf("render login: %v", err)
	}
}

// ── Consent page ──────────────────────────────────────────────────────────────

var scopeDescriptions = map[string]string{
	"openid":         "Confirm your identity (OpenID Connect sign-in)",
	"profile":        "View your name and username",
	"email":          "View your email address",
	"offline_access": "Stay signed in (refresh tokens)",
}

// renderConsent shows "App X wants access to: ..." with approve/deny. The
// decision posts back to /authorize with all original parameters.
func (s *Server) renderConsent(w http.ResponseWriter, req authRequest, client *models.App, user *models.User, scopes []string) {
	hidden := ""
	for k, v := range req.fields() {
		if v != "" {
			hidden += `<input type="hidden" name="` + esc(k) + `" value="` + esc(v) + `">`
		}
	}
	scopeItems := ""
	for _, sc := range scopes {
		desc := scopeDescriptions[sc]
		if desc == "" {
			desc = "Scope: " + sc
		}
		scopeItems += `<li><strong>` + esc(sc) + `</strong> — ` + esc(desc) + `</li>`
	}
	username := ""
	if user != nil {
		username = user.Username
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize — Access-Nex</title>` + loginStyle + `<style>
ul.scopes{margin:0 0 22px 0;padding:0;list-style:none}
ul.scopes li{padding:9px 12px;background:#f8f9ff;border-left:4px solid #667eea;border-radius:4px;margin-bottom:8px;font-size:14px}
.btnrow{display:flex;gap:10px}
.btnrow button{flex:1}
button.deny{background:#eee;color:#555}
</style></head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">Authorization Request</div>
  <h1>` + esc(client.Name) + ` wants access to:</h1>
  <p class="hint">Signed in as <strong>` + esc(username) + `</strong></p>
  <ul class="scopes">` + scopeItems + `</ul>
  <form method="post" action="/authorize">` + hidden + `
    <div class="btnrow">
      <button type="submit" name="consent" value="approve">Allow</button>
      <button type="submit" name="consent" value="deny" class="deny">Deny</button>
    </div>
  </form>
  <div class="footer">Your decision is remembered for this application.</div>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

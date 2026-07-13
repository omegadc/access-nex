package server

// Admin JSON API + /admin web UI. Everything requires a logged-in session
// whose user has is_admin set. Mutating calls also require the custom
// X-Access-Nex-Admin header: combined with per-client CORS and SameSite=Lax
// cookies this blocks cross-site request forgery.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
)

// adminFromSession returns the session user if they are an admin.
func (s *Server) adminFromSession(r *http.Request) *models.User {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		return nil
	}
	u := s.userBySubject(subject)
	if u == nil || !u.IsAdmin {
		return nil
	}
	return u
}

func (s *Server) requireAdminPage(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminFromSession(r) == nil {
			http.Redirect(w, r, "/login?return_to=/admin", http.StatusFound)
			return
		}
		h(w, r)
	}
}

func (s *Server) requireAdminAPI(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		admin := s.adminFromSession(r)
		if admin == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin session required"})
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Access-Nex-Admin") != "1" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing X-Access-Nex-Admin header"})
			return
		}
		h(w, r)
	}
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (s *Server) apiListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type userOut struct {
		Username string `json:"username"`
		Subject  string `json:"subject"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		Source   string `json:"source"`
		IsAdmin  bool   `json:"is_admin"`
	}
	out := make([]userOut, 0, len(users))
	for _, u := range users {
		source := "local"
		if u.ProviderID != "" {
			source = u.ProviderID
		}
		out = append(out, userOut{u.Username, u.Subject, u.Email, u.Name, source, u.IsAdmin})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	u := &models.User{
		Subject:      fmt.Sprintf("user-%s-%d", req.Username, time.Now().UnixNano()),
		Username:     req.Username,
		PasswordHash: string(hash),
		Email:        req.Email,
		Name:         req.Name,
		IsAdmin:      req.IsAdmin,
	}
	if err := s.store.CreateUser(u); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("admin_user_created", u.Subject, "", clientIP(r), "by "+s.adminFromSession(r).Username)
	writeJSON(w, http.StatusCreated, map[string]string{"username": u.Username, "subject": u.Subject})
}

func (s *Server) apiDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	admin := s.adminFromSession(r)
	if username == admin.Username {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete your own account"})
		return
	}
	if err := s.store.DeleteUserByUsername(username); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	s.store.Audit("admin_user_deleted", "", "", clientIP(r), username+" by "+admin.Username)
	writeJSON(w, http.StatusOK, map[string]string{"deleted": username})
}

// ── Applications ──────────────────────────────────────────────────────────────

func (s *Server) apiListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type appOut struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Public       bool     `json:"public"`
		ProviderID   string   `json:"provider_id"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
		Enabled      bool     `json:"enabled"`
	}
	out := make([]appOut, 0, len(apps))
	for _, a := range apps {
		out = append(out, appOut{a.ID, a.Name, a.Public, a.ProviderID, a.RedirectURIs, a.Scopes, a.Enabled})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

func (s *Server) apiCreateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
		Public       bool     `json:"public"`
		ProviderID   string   `json:"provider_id"`
		Scopes       []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and redirect_uris required"})
		return
	}
	if req.ProviderID != "" && s.providerByID(req.ProviderID) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown provider_id"})
		return
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	app := &models.App{
		ID: fmt.Sprintf("client-%s-%d",
			strings.ToLower(strings.ReplaceAll(req.Name, " ", "-")), time.Now().UnixNano()),
		Name:         req.Name,
		Public:       req.Public,
		ProviderID:   req.ProviderID,
		RedirectURIs: req.RedirectURIs,
		Scopes:       scopes,
		Enabled:      true,
	}
	if !req.Public {
		app.Secret = secrets.RandomToken(32)
	}
	if err := s.store.CreateApp(app); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("admin_app_created", "", app.ID, clientIP(r), "by "+s.adminFromSession(r).Username)
	// The secret is shown once, here, like the CLI does.
	writeJSON(w, http.StatusCreated, map[string]string{"client_id": app.ID, "client_secret": app.Secret})
}

func (s *Server) apiDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteApp(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "app not found"})
		return
	}
	s.store.Audit("admin_app_deleted", "", id, clientIP(r), "by "+s.adminFromSession(r).Username)
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// ── Providers & audit log ─────────────────────────────────────────────────────

func (s *Server) apiListProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.store.ListExternalProviders(false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type provOut struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		AuthURL string `json:"authorization_url"`
		Enabled bool   `json:"enabled"`
	}
	out := make([]provOut, 0, len(providers))
	for _, p := range providers {
		out = append(out, provOut{p.ID, p.Name, p.Kind, p.AuthorizationURL, p.Enabled})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

func (s *Server) apiDeleteProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteProvider(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	s.store.Audit("admin_provider_deleted", "", "", clientIP(r), id+" by "+s.adminFromSession(r).Username)
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (s *Server) apiListAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.store.ListAudit(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type entryOut struct {
		At       string `json:"at"`
		Event    string `json:"event"`
		Subject  string `json:"subject"`
		ClientID string `json:"client_id"`
		IP       string `json:"ip"`
		Detail   string `json:"detail"`
	}
	out := make([]entryOut, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryOut{e.At.Format(time.RFC3339), e.Event, e.Subject, e.ClientID, e.IP, e.Detail})
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": out})
}

// ── Admin UI ──────────────────────────────────────────────────────────────────

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin — Access-Nex</title>` + pageStyle + `<style>
input,select{padding:8px 10px;border:1px solid #ddd;border-radius:6px;font-size:14px;margin:0 6px 8px 0}
.del{background:#fee2e2;color:#dc2626;border:none;border-radius:5px;padding:5px 12px;cursor:pointer;font-size:13px}
.msg{font-size:13px;color:#555;margin-left:8px}
</style></head><body>
<div class="header"><h1>🔐 Access-Nex Admin</h1>
  <div style="margin-top:12px"><a href="/" class="btn" style="background:rgba(255,255,255,.2)">Home</a>
  <a href="/portal" class="btn" style="background:rgba(255,255,255,.2)">Portal</a></div></div>
<div class="container">

  <div class="section"><h2>Users</h2>
    <div>
      <input id="nu-user" placeholder="username"><input id="nu-pass" type="password" placeholder="password">
      <input id="nu-email" placeholder="email"><input id="nu-name" placeholder="full name">
      <label style="font-size:13px"><input type="checkbox" id="nu-admin" style="margin:0 4px 0 0">admin</label>
      <button class="btn" onclick="createUser()">Add User</button><span class="msg" id="u-msg"></span>
    </div>
    <table id="users-table"><tr><th>Username</th><th>Email</th><th>Name</th><th>Source</th><th>Admin</th><th></th></tr></table>
  </div>

  <div class="section"><h2>Applications</h2>
    <div>
      <input id="na-name" placeholder="app name"><input id="na-uri" placeholder="redirect URI" size="34">
      <label style="font-size:13px"><input type="checkbox" id="na-public" style="margin:0 4px 0 0">public (PKCE)</label>
      <button class="btn" onclick="createApp()">Add App</button><span class="msg" id="a-msg"></span>
    </div>
    <table id="apps-table"><tr><th>Name</th><th>Client ID</th><th>Type</th><th>Redirect URIs</th><th></th></tr></table>
  </div>

  <div class="section"><h2>External Providers</h2>
    <p style="font-size:13px;color:#888;margin-bottom:10px">Add providers via the CLI: <code>access-nex provider add -t google ...</code></p>
    <table id="prov-table"><tr><th>Name</th><th>ID</th><th>Kind</th><th>Enabled</th><th></th></tr></table>
  </div>

  <div class="section"><h2>Audit Log <button class="btn" style="float:right;padding:5px 14px;font-size:12px" onclick="loadAudit()">Refresh</button></h2>
    <div style="overflow-x:auto"><table id="audit-table"><tr><th>Time</th><th>Event</th><th>Subject</th><th>Client</th><th>IP</th><th>Detail</th></tr></table></div>
  </div>

</div>
<div class="footer">Access-Nex — Admin Console</div>
<script>
const H = {'Content-Type':'application/json','X-Access-Nex-Admin':'1'};
const esc = t => { const d=document.createElement('div'); d.textContent=t??''; return d.innerHTML; };

async function loadUsers(){
  const res = await fetch('/api/admin/users'); const data = await res.json();
  const t = document.getElementById('users-table');
  t.innerHTML = '<tr><th>Username</th><th>Email</th><th>Name</th><th>Source</th><th>Admin</th><th></th></tr>';
  for (const u of data.users||[]) t.innerHTML += '<tr><td>'+esc(u.username)+'</td><td>'+esc(u.email)+'</td><td>'+esc(u.name)+
    '</td><td>'+esc(u.source)+'</td><td>'+(u.is_admin?'✓':'')+'</td><td><button class="del" onclick="delUser(\''+esc(u.username)+'\')">delete</button></td></tr>';
}
async function createUser(){
  const body = {username:v('nu-user'),password:v('nu-pass'),email:v('nu-email'),name:v('nu-name'),is_admin:document.getElementById('nu-admin').checked};
  const res = await fetch('/api/admin/users',{method:'POST',headers:H,body:JSON.stringify(body)});
  const d = await res.json();
  document.getElementById('u-msg').textContent = res.ok ? 'created '+d.username : (d.error||'failed');
  loadUsers();
}
async function delUser(name){
  if (!confirm('Delete user '+name+'?')) return;
  await fetch('/api/admin/users/'+encodeURIComponent(name),{method:'DELETE',headers:H});
  loadUsers();
}
async function loadApps(){
  const res = await fetch('/api/admin/apps'); const data = await res.json();
  const t = document.getElementById('apps-table');
  t.innerHTML = '<tr><th>Name</th><th>Client ID</th><th>Type</th><th>Redirect URIs</th><th></th></tr>';
  for (const a of data.apps||[]) t.innerHTML += '<tr><td>'+esc(a.name)+'</td><td><code>'+esc(a.id)+'</code></td><td>'+(a.public?'Public':'Confidential')+
    '</td><td>'+(a.redirect_uris||[]).map(esc).join('<br>')+'</td><td><button class="del" onclick="delApp(\''+esc(a.id)+'\')">delete</button></td></tr>';
}
async function createApp(){
  const body = {name:v('na-name'),redirect_uris:[v('na-uri')],public:document.getElementById('na-public').checked};
  const res = await fetch('/api/admin/apps',{method:'POST',headers:H,body:JSON.stringify(body)});
  const d = await res.json();
  document.getElementById('a-msg').textContent = res.ok ? ('created; secret: '+(d.client_secret||'(public)')) : (d.error||'failed');
  loadApps();
}
async function delApp(id){
  if (!confirm('Delete app '+id+'?')) return;
  await fetch('/api/admin/apps/'+encodeURIComponent(id),{method:'DELETE',headers:H});
  loadApps();
}
async function loadProviders(){
  const res = await fetch('/api/admin/providers'); const data = await res.json();
  const t = document.getElementById('prov-table');
  t.innerHTML = '<tr><th>Name</th><th>ID</th><th>Kind</th><th>Enabled</th><th></th></tr>';
  for (const p of data.providers||[]) t.innerHTML += '<tr><td>'+esc(p.name)+'</td><td><code>'+esc(p.id)+'</code></td><td>'+esc(p.kind)+
    '</td><td>'+(p.enabled?'✓':'✗')+'</td><td><button class="del" onclick="delProv(\''+esc(p.id)+'\')">delete</button></td></tr>';
}
async function delProv(id){
  if (!confirm('Delete provider '+id+'?')) return;
  await fetch('/api/admin/providers/'+encodeURIComponent(id),{method:'DELETE',headers:H});
  loadProviders();
}
async function loadAudit(){
  const res = await fetch('/api/admin/audit?limit=50'); const data = await res.json();
  const t = document.getElementById('audit-table');
  t.innerHTML = '<tr><th>Time</th><th>Event</th><th>Subject</th><th>Client</th><th>IP</th><th>Detail</th></tr>';
  for (const e of data.audit||[]) t.innerHTML += '<tr><td style="white-space:nowrap;font-size:12px">'+esc(e.at)+'</td><td>'+esc(e.event)+
    '</td><td style="font-size:12px">'+esc(e.subject)+'</td><td style="font-size:12px">'+esc(e.client_id)+'</td><td>'+esc(e.ip)+'</td><td style="font-size:12px">'+esc(e.detail)+'</td></tr>';
}
const v = id => document.getElementById(id).value;
loadUsers(); loadApps(); loadProviders(); loadAudit();
</script></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

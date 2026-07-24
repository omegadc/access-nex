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

// providerReq carries the fields the CLI's provider add/update flags accept;
// empty fields are left untouched on update, mirroring applyProviderFlags.
type providerReq struct {
	Name             string   `json:"name"`
	Template         string   `json:"template"`
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret"`
	RedirectURL      string   `json:"redirect_url"`
	AuthorizationURL string   `json:"authorization_url"`
	AccessTokenURL   string   `json:"access_token_url"`
	ResourceURL      string   `json:"resource_url"`
	LogoutURL        string   `json:"logout_url"`
	UserIdentifier   string   `json:"user_identifier"`
	Scopes           []string `json:"scopes"`
}

func (req *providerReq) applyOverrides(p *models.Provider) {
	if req.RedirectURL != "" {
		p.RedirectURL = req.RedirectURL
	}
	if req.AuthorizationURL != "" {
		p.AuthorizationURL = req.AuthorizationURL
	}
	if req.AccessTokenURL != "" {
		p.AccessTokenURL = req.AccessTokenURL
	}
	if req.ResourceURL != "" {
		p.ResourceURL = req.ResourceURL
	}
	if req.LogoutURL != "" {
		p.LogoutURL = req.LogoutURL
	}
	if req.UserIdentifier != "" {
		p.UserIdentifier = req.UserIdentifier
	}
	if len(req.Scopes) > 0 {
		p.Scopes = req.Scopes
	}
}

// apiCreateProvider is the web counterpart of `provider add`.
func (s *Server) apiCreateProvider(w http.ResponseWriter, r *http.Request) {
	var req providerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.Name == "" || req.ClientID == "" || req.ClientSecret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name, client_id and client_secret required"})
		return
	}
	p := &models.Provider{
		ID: fmt.Sprintf("provider-%s-%d",
			strings.ToLower(strings.ReplaceAll(req.Name, " ", "-")), time.Now().UnixNano()),
		Name:           req.Name,
		Kind:           models.ProviderKindOAuth2,
		Template:       req.Template,
		ClientID:       req.ClientID,
		UserIdentifier: "id",
		Scopes:         []string{"openid", "profile", "email"},
		Enabled:        true,
	}
	if tmpl := models.ProviderTemplates[req.Template]; tmpl != nil {
		p.Kind = tmpl.Kind
		p.AuthorizationURL = tmpl.AuthorizationURL
		p.AccessTokenURL = tmpl.AccessTokenURL
		p.ResourceURL = tmpl.ResourceURL
		p.LogoutURL = tmpl.LogoutURL
		p.UserIdentifier = tmpl.UserIdentifier
		p.Scopes = tmpl.Scopes
	}
	req.applyOverrides(p)
	var err error
	if p.ClientSecretEnc, err = s.box.Encrypt(req.ClientSecret); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encrypt secret"})
		return
	}
	if err := s.store.CreateProvider(p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("admin_provider_created", "", "", clientIP(r), p.ID+" by "+s.adminFromSession(r).Username)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": p.ID, "name": p.Name, "kind": p.Kind, "template": p.Template, "scopes": p.Scopes,
	})
}

// externalProvider loads a provider by ID, refusing the internal "self" row.
func (s *Server) externalProvider(id string) *models.Provider {
	p, err := s.store.GetProvider(id)
	if err != nil || p.Kind == models.ProviderKindInternal {
		return nil
	}
	return p
}

// apiShowProvider is the web counterpart of `provider show`. The client
// secret is decrypted only to be masked, exactly like the CLI does.
func (s *Server) apiShowProvider(w http.ResponseWriter, r *http.Request) {
	p := s.externalProvider(r.PathValue("id"))
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	secret := "[unable to decrypt]"
	if plain, err := s.box.Decrypt(p.ClientSecretEnc); err == nil {
		secret = maskSecret(plain)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                p.ID,
		"name":              p.Name,
		"kind":              p.Kind,
		"template":          p.Template,
		"client_id":         p.ClientID,
		"client_secret":     secret,
		"redirect_url":      p.RedirectURL,
		"authorization_url": p.AuthorizationURL,
		"access_token_url":  p.AccessTokenURL,
		"resource_url":      p.ResourceURL,
		"logout_url":        p.LogoutURL,
		"user_identifier":   p.UserIdentifier,
		"scopes":            p.Scopes,
		"enabled":           p.Enabled,
		"created_at":        p.CreatedAt.Format(time.RFC3339),
		"updated_at":        p.UpdatedAt.Format(time.RFC3339),
	})
}

// apiUpdateProvider is the web counterpart of `provider update`.
func (s *Server) apiUpdateProvider(w http.ResponseWriter, r *http.Request) {
	p := s.externalProvider(r.PathValue("id"))
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	var req providerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Name != "" {
		p.Name = req.Name
	}
	if req.ClientID != "" {
		p.ClientID = req.ClientID
	}
	if req.ClientSecret != "" {
		enc, err := s.box.Encrypt(req.ClientSecret)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encrypt secret"})
			return
		}
		p.ClientSecretEnc = enc
	}
	req.applyOverrides(p)
	if err := s.store.UpdateProvider(p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.store.Audit("admin_provider_updated", "", "", clientIP(r), p.ID+" by "+s.adminFromSession(r).Username)
	writeJSON(w, http.StatusOK, map[string]string{"updated": p.ID})
}

func maskSecret(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:4] + "****"
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

// The /admin console itself is now rendered by the Python/FastAPI frontend
// (see docs/FRONTEND.md); it drives the JSON API above directly from the
// browser, exactly like the page this replaced did.

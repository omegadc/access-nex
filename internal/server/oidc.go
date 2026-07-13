package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
)

type authRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                        s.issuer,
		"authorization_endpoint":                        s.endpoint("/authorize"),
		"token_endpoint":                                s.endpoint("/token"),
		"userinfo_endpoint":                             s.endpoint("/userinfo"),
		"jwks_uri":                                      s.endpoint("/jwks"),
		"revocation_endpoint":                           s.endpoint("/revoke"),
		"introspection_endpoint":                        s.endpoint("/introspect"),
		"registration_endpoint":                         s.endpoint("/register"),
		"end_session_endpoint":                          s.endpoint("/end_session"),
		"response_types_supported":                      []string{"code"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                              []string{"openid", "profile", "email", "offline_access"},
		"claims_supported":                              []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "name", "preferred_username"},
		"code_challenge_methods_supported":              []string{"S256", "plain"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := s.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "kid": s.keyID, "alg": "RS256",
			"n": b64(pub.N.Bytes()),
			"e": b64(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// ── /authorize ────────────────────────────────────────────────────────────────

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	req := authRequest{
		ResponseType:        r.Form.Get("response_type"),
		ClientID:            r.Form.Get("client_id"),
		RedirectURI:         r.Form.Get("redirect_uri"),
		Scope:               r.Form.Get("scope"),
		State:               r.Form.Get("state"),
		Nonce:               r.Form.Get("nonce"),
		CodeChallenge:       r.Form.Get("code_challenge"),
		CodeChallengeMethod: r.Form.Get("code_challenge_method"),
		Prompt:              r.Form.Get("prompt"),
	}

	client := s.clientByID(req.ClientID)
	if client == nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	if req.RedirectURI == "" && len(client.RedirectURIs) == 1 {
		req.RedirectURI = client.RedirectURIs[0]
	}
	if !redirectAllowed(client, req.RedirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	if req.Scope == "" {
		req.Scope = "openid"
	}
	if req.ResponseType != "code" {
		s.redirectWithOAuthError(w, r, req.RedirectURI, "unsupported_response_type", "Only code is supported", req.State)
		return
	}
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" &&
		req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
		s.redirectWithOAuthError(w, r, req.RedirectURI, "invalid_request", "Unsupported code_challenge_method", req.State)
		return
	}

	if subject, ok := s.subjectFromSession(r); ok {
		s.issueAuthorizationCode(w, r, req, subject)
		return
	}
	if req.Prompt == "none" {
		s.redirectWithOAuthError(w, r, req.RedirectURI, "login_required", "Login required", req.State)
		return
	}
	if r.Method == http.MethodPost {
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if subject, ok := s.authenticateUser(username, password); ok {
			s.startSession(w, subject)
			s.issueAuthorizationCode(w, r, req, subject)
			return
		}
		s.renderLogin(w, req, client.Name, "Invalid username or password")
		return
	}
	s.renderLogin(w, req, client.Name, "")
}

func (s *Server) issueAuthorizationCode(w http.ResponseWriter, r *http.Request, req authRequest, subject string) {
	code := secrets.RandomToken(32)
	scope := parseScope(req.Scope)
	if len(scope) == 0 {
		scope = []string{"openid"}
	}
	s.mu.Lock()
	s.authCodes[code] = &models.AuthCode{
		Code: code, ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		Subject: subject, Scope: scope, Nonce: req.Nonce,
		CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt: time.Now().Add(5 * time.Minute), AuthTime: time.Now(),
	}
	s.mu.Unlock()
	redirectURL, _ := url.Parse(req.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("iss", s.issuer)
	if req.State != "" {
		q.Set("state", req.State)
	}
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (s *Server) redirectWithOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, code, description, state string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ── /token ────────────────────────────────────────────────────────────────────

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form body")
		return
	}
	client, authErr := s.authenticateClient(r)
	if authErr != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="access-nex"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", authErr)
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r, client)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r, client)
	case "client_credentials":
		s.handleClientCredentialsGrant(w, r, client)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant_type")
	}
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client *models.App) {
	codeValue := r.Form.Get("code")
	if codeValue == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing code")
		return
	}
	s.mu.Lock()
	code := s.authCodes[codeValue]
	if code != nil {
		delete(s.authCodes, codeValue)
	}
	s.mu.Unlock()
	if code == nil || time.Now().After(code.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired code")
		return
	}
	if code.ClientID != client.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Code issued to different client")
		return
	}
	if r.Form.Get("redirect_uri") != code.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if client.Public && code.CodeChallenge == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Public clients must use PKCE")
		return
	}
	if code.CodeChallenge != "" && !verifyPKCE(code.CodeChallenge, code.CodeChallengeMethod, r.Form.Get("code_verifier")) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid code_verifier")
		return
	}
	response, err := s.issueTokenResponse(client.ID, code.Subject, code.Scope, code.Nonce, code.AuthTime, true)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client *models.App) {
	refreshToken := r.Form.Get("refresh_token")
	if refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing refresh_token")
		return
	}
	s.mu.Lock()
	refresh := s.refreshTokens[refreshToken]
	valid := refresh != nil && !refresh.Revoked && refresh.ClientID == client.ID && time.Now().Before(refresh.ExpiresAt)
	if valid {
		refresh.Revoked = true // single-use: rotate on every refresh
	}
	s.mu.Unlock()
	if !valid {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh_token")
		return
	}
	response, err := s.issueTokenResponse(client.ID, refresh.Subject, refresh.Scope, "", time.Now(), true)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, client *models.App) {
	if client.Public {
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized_client", "Public clients cannot use client_credentials")
		return
	}
	scope := parseScope(r.Form.Get("scope"))
	if len(scope) == 0 {
		scope = []string{"profile"}
	}
	record, err := s.issueAccessToken(client.ID, client.ID, scope)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": record.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(record.ExpiresAt).Seconds()),
		"scope":        strings.Join(scope, " "),
	})
}

// ── Token issuance ────────────────────────────────────────────────────────────

func (s *Server) issueTokenResponse(clientID, subject string, scope []string, nonce string, authTime time.Time, includeRefresh bool) (map[string]any, error) {
	access, err := s.issueAccessToken(clientID, subject, scope)
	if err != nil {
		return nil, err
	}
	resp := map[string]any{
		"access_token": access.Token, "token_type": "Bearer",
		"expires_in": int(time.Until(access.ExpiresAt).Seconds()),
		"scope":      strings.Join(scope, " "),
	}
	if hasScope(scope, "openid") {
		idToken, err := s.issueIDToken(clientID, subject, scope, nonce, authTime, access.Token)
		if err != nil {
			return nil, err
		}
		resp["id_token"] = idToken
	}
	if includeRefresh && hasScope(scope, "offline_access") {
		refreshToken := secrets.RandomToken(48)
		expires := time.Now().Add(30 * 24 * time.Hour)
		s.mu.Lock()
		s.refreshTokens[refreshToken] = &models.RefreshRecord{
			Token: refreshToken, ClientID: clientID, Subject: subject,
			Scope: scope, ExpiresAt: expires,
		}
		s.mu.Unlock()
		resp["refresh_token"] = refreshToken
	}
	return resp, nil
}

func (s *Server) issueAccessToken(clientID, subject string, scope []string) (*models.TokenRecord, error) {
	now := time.Now()
	expires := now.Add(time.Hour)
	jti := secrets.RandomToken(24)
	claims := map[string]any{
		"iss": s.issuer, "sub": subject, "aud": clientID, "client_id": clientID,
		"scope": strings.Join(scope, " "), "exp": expires.Unix(), "iat": now.Unix(),
		"jti": jti, "token_use": "access",
	}
	token, err := s.signJWT(claims)
	if err != nil {
		return nil, err
	}
	record := &models.TokenRecord{Token: token, JTI: jti, ClientID: clientID, Subject: subject, Scope: scope, ExpiresAt: expires}
	s.mu.Lock()
	s.accessTokens[token] = record
	s.mu.Unlock()
	return record, nil
}

func (s *Server) issueIDToken(clientID, subject string, scope []string, nonce string, authTime time.Time, accessToken string) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss": s.issuer, "sub": subject, "aud": clientID,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"auth_time": authTime.Unix(), "at_hash": accessTokenHash(accessToken),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if hasScope(scope, "profile") || hasScope(scope, "email") {
		if user := s.userBySubject(subject); user != nil {
			if hasScope(scope, "profile") {
				claims["name"] = user.Name
				claims["preferred_username"] = user.Username
			}
			if hasScope(scope, "email") {
				claims["email"] = user.Email
				claims["email_verified"] = true
			}
		}
	}
	return s.signJWT(claims)
}

func (s *Server) signJWT(claims map[string]any) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": s.keyID}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(signature), nil
}

// ── /revoke, /introspect, /userinfo, /register, /end_session ─────────────────

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form body")
		return
	}
	client, authErr := s.authenticateClient(r)
	if authErr != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="access-nex"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", authErr)
		return
	}
	token := r.Form.Get("token")
	s.mu.Lock()
	if a := s.accessTokens[token]; a != nil && a.ClientID == client.ID {
		a.Revoked = true
	}
	if rf := s.refreshTokens[token]; rf != nil && rf.ClientID == client.ID {
		rf.Revoked = true
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form body")
		return
	}
	if _, authErr := s.authenticateClient(r); authErr != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="access-nex"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", authErr)
		return
	}
	token := r.Form.Get("token")
	now := time.Now()
	s.mu.Lock()
	access := s.accessTokens[token]
	refresh := s.refreshTokens[token]
	s.mu.Unlock()
	if access != nil && !access.Revoked && now.Before(access.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{
			"active": true, "scope": strings.Join(access.Scope, " "),
			"client_id": access.ClientID, "sub": access.Subject,
			"token_type": "Bearer", "exp": access.ExpiresAt.Unix(),
			"iss": s.issuer, "jti": access.JTI,
		})
		return
	}
	if refresh != nil && !refresh.Revoked && now.Before(refresh.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{
			"active": true, "scope": strings.Join(refresh.Scope, " "),
			"client_id": refresh.ClientID, "sub": refresh.Subject,
			"token_type": "refresh_token", "exp": refresh.ExpiresAt.Unix(), "iss": s.issuer,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"active": false})
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Missing bearer token")
		return
	}
	s.mu.Lock()
	record := s.accessTokens[token]
	s.mu.Unlock()
	if record == nil || record.Revoked || time.Now().After(record.ExpiresAt) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
		return
	}
	user := s.userBySubject(record.Subject)
	if user == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Unknown subject")
		return
	}
	if !hasScope(record.Scope, "openid") {
		writeOAuthError(w, http.StatusForbidden, "insufficient_scope", "userinfo requires openid scope")
		return
	}
	claims := map[string]any{"sub": user.Subject}
	if hasScope(record.Scope, "profile") {
		claims["name"] = user.Name
		claims["preferred_username"] = user.Username
	}
	if hasScope(record.Scope, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}
	writeJSON(w, http.StatusOK, claims)
}

// handleRegister implements RFC 7591 dynamic client registration; the created
// client is persisted to the applications table.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST")
		return
	}
	var req struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "Invalid JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "All redirect URIs must be absolute")
			return
		}
	}
	public := req.TokenEndpointAuthMethod == "none"
	app := &models.App{
		ID:           "client-" + secrets.RandomToken(16),
		Name:         req.ClientName,
		RedirectURIs: req.RedirectURIs,
		Public:       public,
		Scopes:       []string{"openid", "profile", "email"},
		Enabled:      true,
	}
	if !public {
		app.Secret = secrets.RandomToken(32)
	}
	if err := s.store.CreateApp(app); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not persist client")
		return
	}

	resp := map[string]any{
		"client_id":                  app.ID,
		"client_name":                app.Name,
		"redirect_uris":              app.RedirectURIs,
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_id_issued_at":        time.Now().Unix(),
	}
	if public {
		resp["token_endpoint_auth_method"] = "none"
	} else {
		resp["client_secret"] = app.Secret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	s.endSession(w, r)
	if u := r.URL.Query().Get("post_logout_redirect_uri"); u != "" {
		http.Redirect(w, r, u, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
	"github.com/omegadc/access-nex/internal/store"
)

type authRequest struct {
	ResponseType        string
	ResponseMode        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

// fields returns the request as hidden-form fields so the login and consent
// pages can round-trip it.
func (req authRequest) fields() map[string]string {
	return map[string]string{
		"response_type": req.ResponseType, "response_mode": req.ResponseMode,
		"client_id": req.ClientID, "redirect_uri": req.RedirectURI,
		"scope": req.Scope, "state": req.State, "nonce": req.Nonce,
		"code_challenge": req.CodeChallenge, "code_challenge_method": req.CodeChallengeMethod,
		"prompt": req.Prompt,
	}
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
		"response_modes_supported":                      []string{"query", "form_post"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"id_token_encryption_alg_values_supported":      []string{"RSA-OAEP-256"},
		"id_token_encryption_enc_values_supported":      []string{"A256GCM"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                              []string{"openid", "profile", "email", "offline_access"},
		"claims_supported":                              []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "name", "preferred_username"},
		"code_challenge_methods_supported":              []string{"S256", "plain"},
		"prompt_values_supported":                       []string{"none", "login", "consent", "select_account"},
	})
}

// handleJWKS publishes every non-retired signing key so tokens signed before
// a rotation keep verifying.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	keys := make([]map[string]any, 0, len(s.keys))
	for _, sk := range s.keys {
		pub := sk.Key.PublicKey
		keys = append(keys, map[string]any{
			"kty": "RSA", "use": "sig", "kid": sk.Kid, "alg": "RS256",
			"n": b64(pub.N.Bytes()),
			"e": b64(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
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
		ResponseMode:        r.Form.Get("response_mode"),
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
		s.deliverAuthError(w, r, req, "unsupported_response_type", "Only code is supported")
		return
	}
	if req.ResponseMode != "" && req.ResponseMode != "query" && req.ResponseMode != "form_post" {
		s.deliverAuthError(w, r, req, "invalid_request", "Unsupported response_mode")
		return
	}
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" &&
		req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
		s.deliverAuthError(w, r, req, "invalid_request", "Unsupported code_challenge_method")
		return
	}

	prompts := parseScope(req.Prompt)
	forceLogin := hasScope(prompts, "login") || hasScope(prompts, "select_account")
	forceConsent := hasScope(prompts, "consent")
	promptNone := hasScope(prompts, "none")

	// Consent decision submitted from the consent page.
	if r.Method == http.MethodPost && r.Form.Get("consent") != "" {
		subject, ok := s.subjectFromSession(r)
		if !ok {
			s.renderLogin(w, req, client.Name, "Session expired — sign in again")
			return
		}
		scope := parseScope(req.Scope)
		if r.Form.Get("consent") != "approve" {
			s.store.Audit("consent_denied", subject, client.ID, clientIP(r), strings.Join(scope, " "))
			s.deliverAuthError(w, r, req, "access_denied", "User denied the request")
			return
		}
		if err := s.store.SaveGrant(subject, client.ID, scope); err != nil {
			s.deliverAuthError(w, r, req, "server_error", "Could not save grant")
			return
		}
		s.store.Audit("consent_granted", subject, client.ID, clientIP(r), strings.Join(scope, " "))
		s.issueAuthorizationCode(w, r, req, subject)
		return
	}

	// Establish who the user is. prompt=login / select_account forces
	// re-authentication even when a session exists.
	subject, loggedIn := "", false
	if !forceLogin {
		subject, loggedIn = s.subjectFromSession(r)
	}
	if !loggedIn {
		if promptNone {
			s.deliverAuthError(w, r, req, "login_required", "Login required")
			return
		}
		if r.Method == http.MethodPost && r.Form.Get("username") != "" {
			if !s.loginLimiter.allow(clientIP(r)) {
				s.renderLogin(w, req, client.Name, "Too many attempts — try again in a minute")
				return
			}
			sub, ok := s.authenticateUser(r.Form.Get("username"), r.Form.Get("password"), clientIP(r))
			if !ok {
				s.renderLogin(w, req, client.Name, "Invalid username or password")
				return
			}
			s.startSession(w, sub)
			subject = sub
			// prompt=login is satisfied by the fresh authentication.
			forceLogin = false
		} else {
			s.renderLogin(w, req, client.Name, "")
			return
		}
	}

	// Consent: skip only when a remembered grant covers all requested scopes.
	scope := parseScope(req.Scope)
	granted, err := s.store.HasGrant(subject, client.ID, scope)
	if err != nil {
		s.deliverAuthError(w, r, req, "server_error", "Could not check grant")
		return
	}
	if forceConsent || !granted {
		if promptNone {
			s.deliverAuthError(w, r, req, "consent_required", "Consent required")
			return
		}
		s.renderConsent(w, req, client, s.userBySubject(subject), scope)
		return
	}
	s.issueAuthorizationCode(w, r, req, subject)
}

func (s *Server) issueAuthorizationCode(w http.ResponseWriter, r *http.Request, req authRequest, subject string) {
	code := secrets.RandomToken(32)
	scope := parseScope(req.Scope)
	if len(scope) == 0 {
		scope = []string{"openid"}
	}
	err := s.store.SaveAuthCode(&models.AuthCode{
		Code: code, ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		Subject: subject, Scope: scope, Nonce: req.Nonce,
		CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt: time.Now().Add(5 * time.Minute), AuthTime: time.Now(),
	})
	if err != nil {
		s.deliverAuthError(w, r, req, "server_error", "Could not issue code")
		return
	}
	params := map[string]string{"code": code, "iss": s.issuer}
	if req.State != "" {
		params["state"] = req.State
	}
	s.deliverAuthResponse(w, r, req, params)
}

// deliverAuthResponse returns parameters to the client's redirect URI using
// the requested response_mode: query redirect (default) or form_post.
func (s *Server) deliverAuthResponse(w http.ResponseWriter, r *http.Request, req authRequest, params map[string]string) {
	if req.ResponseMode == "form_post" {
		inputs := ""
		for k, v := range params {
			inputs += `<input type="hidden" name="` + esc(k) + `" value="` + esc(v) + `">`
		}
		page := `<!doctype html><html><head><meta charset="utf-8"><title>Redirecting…</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="` + esc(req.RedirectURI) + `">` + inputs + `
<noscript><button type="submit">Continue</button></noscript></form></body></html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
		return
	}
	u, _ := url.Parse(req.RedirectURI)
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) deliverAuthError(w http.ResponseWriter, r *http.Request, req authRequest, code, description string) {
	params := map[string]string{"error": code, "error_description": description}
	if req.State != "" {
		params["state"] = req.State
	}
	s.deliverAuthResponse(w, r, req, params)
}

// ── /token ────────────────────────────────────────────────────────────────────

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST")
		return
	}
	if !s.tokenLimiter.allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "slow_down", "Rate limit exceeded")
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

// parseAudiences validates the optional `audience` parameter: every value
// must be a registered, enabled application.
func (s *Server) parseAudiences(r *http.Request) ([]string, error) {
	audiences := parseScope(strings.Join(r.Form["audience"], " "))
	for _, aud := range audiences {
		if s.clientByID(aud) == nil {
			return nil, errors.New("unknown audience: " + aud)
		}
	}
	return audiences, nil
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client *models.App) {
	codeValue := r.Form.Get("code")
	if codeValue == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing code")
		return
	}
	code, err := s.store.ConsumeAuthCode(codeValue)
	if err != nil || time.Now().After(code.ExpiresAt) {
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
	audiences, err := s.parseAudiences(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	response, err := s.issueTokenResponse(client, code.Subject, code.Scope, audiences, code.Nonce, code.AuthTime, "")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	s.store.Audit("token_issued", code.Subject, client.ID, clientIP(r), "authorization_code")
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client *models.App) {
	refreshToken := r.Form.Get("refresh_token")
	if refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing refresh_token")
		return
	}
	refresh, err := s.store.ConsumeRefreshToken(refreshToken, client.ID)
	if err != nil {
		if errors.Is(err, store.ErrRefreshReuse) {
			s.store.Audit("refresh_reuse_detected", refresh.Subject, client.ID, clientIP(r),
				"family "+refresh.Family+" revoked")
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh_token")
		return
	}
	// The replacement refresh token stays in the same family so replay of
	// the old token can revoke every descendant.
	response, err := s.issueTokenResponse(client, refresh.Subject, refresh.Scope, nil, "", time.Now(), refresh.Family)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	s.store.Audit("token_refreshed", refresh.Subject, client.ID, clientIP(r), "")
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
	audiences, err := s.parseAudiences(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	record, err := s.issueAccessToken(client.ID, client.ID, scope, audiences)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	s.store.Audit("token_issued", client.ID, client.ID, clientIP(r), "client_credentials")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": record.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(record.ExpiresAt).Seconds()),
		"scope":        strings.Join(scope, " "),
	})
}

// ── Token issuance ────────────────────────────────────────────────────────────

func (s *Server) issueTokenResponse(client *models.App, subject string, scope, audiences []string, nonce string, authTime time.Time, refreshFamily string) (map[string]any, error) {
	access, err := s.issueAccessToken(client.ID, subject, scope, audiences)
	if err != nil {
		return nil, err
	}
	resp := map[string]any{
		"access_token": access.Token, "token_type": "Bearer",
		"expires_in": int(time.Until(access.ExpiresAt).Seconds()),
		"scope":      strings.Join(scope, " "),
	}
	if hasScope(scope, "openid") {
		idToken, err := s.issueIDToken(client.ID, subject, scope, nonce, authTime, access.Token)
		if err != nil {
			return nil, err
		}
		// Encrypt the ID token (JWE) when the client registered a key for it.
		if client.IDTokenEncKey != "" {
			pub, err := secrets.ParsePublicKeyPEM(client.IDTokenEncKey)
			if err != nil {
				return nil, err
			}
			if idToken, err = encryptJWE(pub, idToken); err != nil {
				return nil, err
			}
		}
		resp["id_token"] = idToken
	}
	if hasScope(scope, "offline_access") {
		refreshToken := secrets.RandomToken(48)
		family := refreshFamily
		if family == "" {
			family = "fam-" + secrets.RandomToken(16)
		}
		err := s.store.SaveRefreshToken(&models.RefreshRecord{
			Token: refreshToken, ClientID: client.ID, Subject: subject,
			Scope: scope, Family: family, ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		})
		if err != nil {
			return nil, err
		}
		resp["refresh_token"] = refreshToken
	}
	return resp, nil
}

func (s *Server) issueAccessToken(clientID, subject string, scope, audiences []string) (*models.TokenRecord, error) {
	now := time.Now()
	expires := now.Add(time.Hour)
	jti := secrets.RandomToken(24)

	// aud is the client itself plus any validated extra audiences; a single
	// value is emitted as a string, several as an array (RFC 7519 §4.1.3).
	audClaim := any(clientID)
	if len(audiences) > 0 {
		audClaim = append([]string{clientID}, audiences...)
	}
	claims := map[string]any{
		"iss": s.issuer, "sub": subject, "aud": audClaim, "client_id": clientID,
		"scope": strings.Join(scope, " "), "exp": expires.Unix(), "iat": now.Unix(),
		"jti": jti, "token_use": "access",
	}
	token, err := s.signJWT(claims)
	if err != nil {
		return nil, err
	}
	record := &models.TokenRecord{
		Token: token, JTI: jti, ClientID: clientID, Subject: subject,
		Scope: scope, Audiences: audiences, ExpiresAt: expires,
	}
	if err := s.store.SaveAccessToken(record); err != nil {
		return nil, err
	}
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
	active := s.activeKey()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": active.Kid}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, active.Key, crypto.SHA256, digest[:])
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
	if err := s.store.RevokeToken(token, client.ID); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not revoke token")
		return
	}
	s.store.Audit("token_revoked", "", client.ID, clientIP(r), "")
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
	access, _ := s.store.GetAccessToken(token)
	refresh, _ := s.store.GetRefreshToken(token)
	if access != nil && !access.Revoked && now.Before(access.ExpiresAt) {
		aud := any(access.ClientID)
		if len(access.Audiences) > 0 {
			aud = append([]string{access.ClientID}, access.Audiences...)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"active": true, "scope": strings.Join(access.Scope, " "),
			"client_id": access.ClientID, "sub": access.Subject, "aud": aud,
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
	record, err := s.store.GetAccessToken(token)
	if err != nil || record.Revoked || time.Now().After(record.ExpiresAt) {
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
	s.store.Audit("client_registered", "", app.ID, clientIP(r), app.Name)

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

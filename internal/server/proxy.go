package server

// External OAuth proxy: lets an application registered with access-nex sign
// its users in through an external provider (Google, Microsoft, GitHub, ...).
// Flow: /oauth/start redirects to the provider → /oauth/callback exchanges
// the provider's code, provisions a local user in the users table, and issues
// a local auth code the calling app can exchange at /token.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
)

// handleOAuthProviders returns the list of enabled external providers.
func (s *Server) handleOAuthProviders(w http.ResponseWriter, r *http.Request) {
	type info struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		Type   string   `json:"type"`
		Scopes []string `json:"scopes"`
	}
	providers, err := s.store.ListExternalProviders(true)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not list providers")
		return
	}
	list := make([]info, 0, len(providers))
	for _, p := range providers {
		list = append(list, info{ID: p.ID, Name: p.Name, Type: p.Kind, Scopes: p.Scopes})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": list})
}

// handleOAuthStart redirects the user to an external provider.
// Query params: provider_id, client_id, redirect_uri, state?, nonce?, scope?
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	providerID := q.Get("provider_id")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	if providerID == "" || clientID == "" || redirectURI == "" {
		http.Error(w, "provider_id, client_id and redirect_uri are required", http.StatusBadRequest)
		return
	}
	ep := s.providerByID(providerID)
	if ep == nil {
		http.Error(w, "unknown provider_id", http.StatusBadRequest)
		return
	}
	client := s.clientByID(clientID)
	if client == nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	if !redirectAllowed(client, redirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}
	if ep.AuthorizationURL == "" {
		http.Error(w, "provider has no authorization_url configured", http.StatusBadRequest)
		return
	}

	scopes := ep.Scopes
	if sc := q.Get("scope"); sc != "" {
		scopes = parseScope(sc)
	}
	nonce := q.Get("nonce")

	proxyState := "proxy-" + secrets.RandomToken(24)
	s.mu.Lock()
	s.oauthStates[proxyState] = &models.OAuthProxyState{
		ProviderID:  providerID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       q.Get("state"),
		Nonce:       nonce,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	s.mu.Unlock()

	authURL, err := url.Parse(ep.AuthorizationURL)
	if err != nil {
		http.Error(w, "invalid provider authorization_url", http.StatusInternalServerError)
		return
	}
	aq := authURL.Query()
	aq.Set("client_id", ep.ClientID)
	aq.Set("response_type", "code")
	aq.Set("redirect_uri", s.providerCallbackURL(ep))
	aq.Set("state", proxyState)
	aq.Set("scope", strings.Join(scopes, " "))
	if nonce != "" && ep.Kind == models.ProviderKindOIDC {
		aq.Set("nonce", nonce)
	}
	authURL.RawQuery = aq.Encode()
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// providerCallbackURL is the redirect registered with the external provider.
func (s *Server) providerCallbackURL(ep *models.Provider) string {
	if ep.RedirectURL != "" {
		return ep.RedirectURL
	}
	return s.issuer + "/oauth/callback"
}

// handleOAuthCallback receives the redirect back from an external provider.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")
	errParam := q.Get("error")

	if state == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	pending := s.oauthStates[state]
	if pending != nil {
		delete(s.oauthStates, state)
	}
	s.mu.Unlock()

	if pending == nil || time.Now().After(pending.ExpiresAt) {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	if errParam != "" {
		redir, _ := url.Parse(pending.RedirectURI)
		rq := redir.Query()
		rq.Set("error", errParam)
		if d := q.Get("error_description"); d != "" {
			rq.Set("error_description", d)
		}
		if pending.State != "" {
			rq.Set("state", pending.State)
		}
		redir.RawQuery = rq.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
		return
	}

	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	ep := s.providerByID(pending.ProviderID)
	if ep == nil {
		http.Error(w, "provider no longer configured", http.StatusInternalServerError)
		return
	}
	clientSecret, err := s.box.Decrypt(ep.ClientSecretEnc)
	if err != nil {
		log.Printf("oauth callback: decrypt secret: %v", err)
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}

	extTokens, err := exchangeCodeWithProvider(ep.AccessTokenURL, ep.ClientID, clientSecret, code, s.providerCallbackURL(ep))
	if err != nil {
		log.Printf("oauth callback: token exchange: %v", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	accessToken, _ := extTokens["access_token"].(string)
	if accessToken == "" {
		log.Printf("oauth callback: no access_token in response from %s", ep.AccessTokenURL)
		http.Error(w, "no access_token in provider response", http.StatusBadGateway)
		return
	}

	userInfo := map[string]any{}
	if ep.ResourceURL != "" {
		userInfo, err = fetchUserInfo(ep.ResourceURL, accessToken)
		if err != nil {
			log.Printf("oauth callback: userinfo: %v", err)
			http.Error(w, "failed to fetch user info", http.StatusBadGateway)
			return
		}
	}

	subject, err := s.provisionExternalUser(ep, userInfo)
	if err != nil {
		log.Printf("oauth callback: provision user: %v", err)
		http.Error(w, "failed to provision user", http.StatusInternalServerError)
		return
	}

	localCode := secrets.RandomToken(32)
	err = s.store.SaveAuthCode(&models.AuthCode{
		Code:        localCode,
		ClientID:    pending.ClientID,
		RedirectURI: pending.RedirectURI,
		Subject:     subject,
		Scope:       pending.Scopes,
		Nonce:       pending.Nonce,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		AuthTime:    time.Now(),
	})
	if err != nil {
		log.Printf("oauth callback: save code: %v", err)
		http.Error(w, "failed to issue code", http.StatusInternalServerError)
		return
	}

	redir, _ := url.Parse(pending.RedirectURI)
	rq := redir.Query()
	rq.Set("code", localCode)
	rq.Set("iss", s.issuer)
	if pending.State != "" {
		rq.Set("state", pending.State)
	}
	redir.RawQuery = rq.Encode()
	http.Redirect(w, r, redir.String(), http.StatusFound)
}

// provisionExternalUser maps the provider's userinfo document to a row in the
// users table, creating it on first login.
func (s *Server) provisionExternalUser(ep *models.Provider, userInfo map[string]any) (string, error) {
	externalID := fmt.Sprintf("%v", userInfo[ep.UserIdentifier])
	email, _ := userInfo["email"].(string)
	name, _ := userInfo["name"].(string)
	login, _ := userInfo["login"].(string) // GitHub
	if login == "" {
		login, _ = userInfo["preferred_username"].(string)
	}
	subject, _, err := s.store.EnsureExternalUser(ep.ID, externalID, login, email, name)
	return subject, err
}

// exchangeCodeWithProvider POSTs to a token endpoint to exchange an auth code.
func exchangeCodeWithProvider(tokenURL, clientID, clientSecret, code, redirectURI string) (map[string]any, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return doJSON(req)
}

// fetchUserInfo calls the provider's resource/userinfo endpoint.
func fetchUserInfo(resourceURL, accessToken string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, resourceURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	return doJSON(req)
}

func doJSON(req *http.Request) (map[string]any, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d: %s", req.URL, resp.StatusCode, body)
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %v", err)
	}
	return result, nil
}

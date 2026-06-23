package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig holds configuration needed to connect to an OIDC provider.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string // defaults to openid, profile, email
}

// OIDCClient wraps an OIDC provider + OAuth2 config for use in Go applications
// that want to delegate authentication to access-nex (or any OIDC provider).
type OIDCClient struct {
	Provider     *oidc.Provider
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	ctx          context.Context
}

// NewOIDCClient discovers the provider metadata from IssuerURL and returns a
// ready-to-use OIDCClient.
func NewOIDCClient(cfg OIDCConfig) (*OIDCClient, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider at %s: %w", cfg.IssuerURL, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return &OIDCClient{
		Provider:     provider,
		OAuth2Config: oauth2Cfg,
		Verifier:     verifier,
		ctx:          ctx,
	}, nil
}

// GenerateState returns a cryptographically random state token for CSRF protection.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// AuthURL returns the authorization URL to redirect the user to.
func (c *OIDCClient) AuthURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.OAuth2Config.AuthCodeURL(state, opts...)
}

// Exchange exchanges an authorization code for an OAuth2 token set.
func (c *OIDCClient) Exchange(code string) (*oauth2.Token, error) {
	return c.OAuth2Config.Exchange(c.ctx, code)
}

// IDTokenClaims holds the standard OIDC ID token claims.
type IDTokenClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// VerifyIDToken verifies and extracts claims from a raw ID token string.
func (c *OIDCClient) VerifyIDToken(rawIDToken string) (*IDTokenClaims, error) {
	idToken, err := c.Verifier.Verify(c.ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify ID token: %w", err)
	}
	var claims IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract ID token claims: %w", err)
	}
	if claims.Subject == "" {
		return nil, errors.New("ID token missing sub claim")
	}
	return &claims, nil
}

// UserInfo fetches user information from the provider's UserInfo endpoint.
func (c *OIDCClient) UserInfo(token *oauth2.Token) (*IDTokenClaims, error) {
	userInfo, err := c.Provider.UserInfo(c.ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	var claims IDTokenClaims
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract userinfo claims: %w", err)
	}
	return &claims, nil
}

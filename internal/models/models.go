// Package models defines the shared data types stored in the SQL database
// and the runtime (in-memory) types used by the OIDC server.
package models

import "time"

// Provider kinds stored in the providers.kind column.
const (
	ProviderKindInternal = "internal" // the local access-nex OIDC provider
	ProviderKindOIDC     = "oidc"     // external OpenID Connect provider
	ProviderKindOAuth2   = "oauth2"   // external plain-OAuth2 provider
)

// User is a row in the users table. Local accounts have a PasswordHash and no
// ProviderID; accounts provisioned from an external provider have ProviderID
// and ExternalID set and an empty PasswordHash (they cannot password-login).
type User struct {
	ID           int64
	Subject      string // OIDC "sub" claim, unique
	Username     string
	PasswordHash string
	Email        string
	Name         string
	ProviderID   string // "" = local account
	ExternalID   string // user's ID at the external provider
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// App is a row in the applications table: an OAuth2/OIDC client registration.
// ProviderID selects which provider authenticates its users ("" = self).
type App struct {
	ID           string
	Name         string
	Secret       string // empty for public (PKCE) clients
	Public       bool
	ProviderID   string
	RedirectURIs []string
	Scopes       []string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Provider is a row in the providers table. It unifies the local provider
// (Kind=internal, only Issuer relevant) and external providers such as
// Google or Microsoft (Kind=oidc/oauth2, endpoint URLs + credentials).
type Provider struct {
	ID               string
	Name             string
	Kind             string
	Template         string // template it was created from ("google", ...)
	Issuer           string // internal provider only
	ClientID         string
	ClientSecretEnc  string // AES-GCM encrypted, base64
	AuthorizationURL string
	AccessTokenURL   string
	ResourceURL      string // userinfo endpoint
	LogoutURL        string
	UserIdentifier   string // JSON field used as the user ID ("sub", "id")
	Scopes           []string
	RedirectURL      string // callback registered at the external provider
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ── Runtime types (kept in memory by the server, not persisted) ───────────────

type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Subject             string
	Scope               []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	AuthTime            time.Time
}

type TokenRecord struct {
	Token     string
	JTI       string
	ClientID  string
	Subject   string
	Scope     []string
	ExpiresAt time.Time
	Revoked   bool
}

type RefreshRecord struct {
	Token     string
	ClientID  string
	Subject   string
	Scope     []string
	ExpiresAt time.Time
	Revoked   bool
}

type Session struct {
	ID        string
	Subject   string
	ExpiresAt time.Time
}

// OAuthProxyState tracks an in-flight login against an external provider.
type OAuthProxyState struct {
	ProviderID  string
	ClientID    string
	RedirectURI string
	State       string // original caller state to echo back
	Nonce       string
	Scopes      []string
	ExpiresAt   time.Time
}

// ── Built-in external provider templates ─────────────────────────────────────

type ProviderTemplate struct {
	Name             string
	Kind             string
	AuthorizationURL string
	AccessTokenURL   string
	ResourceURL      string
	LogoutURL        string
	UserIdentifier   string
	Scopes           []string
}

var ProviderTemplates = map[string]*ProviderTemplate{
	"google": {
		Name:             "Google",
		Kind:             ProviderKindOIDC,
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
		AccessTokenURL:   "https://oauth2.googleapis.com/token",
		ResourceURL:      "https://www.googleapis.com/oauth2/v2/userinfo",
		LogoutURL:        "https://accounts.google.com/logout",
		UserIdentifier:   "sub",
		Scopes:           []string{"openid", "profile", "email"},
	},
	"github": {
		Name:             "GitHub",
		Kind:             ProviderKindOAuth2,
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		AccessTokenURL:   "https://github.com/login/oauth/access_token",
		ResourceURL:      "https://api.github.com/user",
		UserIdentifier:   "id",
		Scopes:           []string{"read:user", "user:email"},
	},
	"microsoft": {
		Name:             "Microsoft",
		Kind:             ProviderKindOIDC,
		AuthorizationURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		AccessTokenURL:   "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		ResourceURL:      "https://graph.microsoft.com/v1.0/me",
		LogoutURL:        "https://login.microsoftonline.com/common/oauth2/v2.0/logout",
		UserIdentifier:   "sub",
		Scopes:           []string{"openid", "profile", "email"},
	},
	"discord": {
		Name:             "Discord",
		Kind:             ProviderKindOAuth2,
		AuthorizationURL: "https://discord.com/api/oauth2/authorize",
		AccessTokenURL:   "https://discord.com/api/oauth2/token",
		ResourceURL:      "https://discord.com/api/users/@me",
		UserIdentifier:   "id",
		Scopes:           []string{"identify", "email"},
	},
	"okta": {
		Name:           "Okta",
		Kind:           ProviderKindOIDC,
		UserIdentifier: "sub",
		Scopes:         []string{"openid", "profile", "email"},
	},
}

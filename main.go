package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultAddr   = ":8080"
	defaultIssuer = "http://localhost:8080"
	configDir     = ".access-nex"
	usersFile     = "users.json"
	appsFile      = "apps.json"
	providerFile  = "provider.json"
	providersFile = "providers.json"
)

// ── Core types ─────────────────────────────────────────────────────────────────

// Provider is the in-memory OIDC server state.
type Provider struct {
	issuer string
	key    *rsa.PrivateKey
	keyID  string

	mu            sync.Mutex
	clients       map[string]*Client
	users         map[string]*User
	authCodes     map[string]*AuthCode
	accessTokens  map[string]*TokenRecord
	refreshTokens map[string]*RefreshRecord
	sessions      map[string]*Session

	extProviders map[string]*ExternalProvider
	oauthStates  map[string]*oauthProxyState
}

// Client is the internal OIDC server representation of a registered app.
type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret,omitempty"`
	Name         string   `json:"name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	Public       bool     `json:"public,omitempty"`
}

// App is the unified CLI/disk format: OAuth client registration + optional
// external-provider linkage. Stored in apps.json.
type App struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Public       bool     `json:"public,omitempty"`
	Secret       string   `json:"secret,omitempty"`
	ProviderID   string   `json:"provider_id,omitempty"` // "" → use self (access-nex)
	Scopes       []string `json:"scopes,omitempty"`
	Enabled      bool     `json:"enabled"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

func (a *App) toClient() *Client {
	return &Client{
		ID:           a.ID,
		Secret:       a.Secret,
		Name:         a.Name,
		RedirectURIs: a.RedirectURIs,
		Public:       a.Public,
	}
}

// ExternalProvider stores config for a remote OAuth/OIDC provider. Stored in providers.json.
type ExternalProvider struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Template         string   `json:"template,omitempty"`
	Type             string   `json:"type"` // "oidc" | "oauth2"
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret_encrypted"`
	AuthorizationURL string   `json:"authorization_url"`
	AccessTokenURL   string   `json:"access_token_url"`
	ResourceURL      string   `json:"resource_url,omitempty"`
	LogoutURL        string   `json:"logout_url,omitempty"`
	UserIdentifier   string   `json:"user_identifier"`
	Scopes           []string `json:"scopes"`
	RedirectURL      string   `json:"redirect_url"`
	Enabled          bool     `json:"enabled"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
}

// oauthProxyState tracks an in-flight external OAuth flow.
type oauthProxyState struct {
	ProviderID  string
	ClientID    string
	RedirectURI string
	State       string // original caller state to echo back
	Nonce       string
	Scopes      []string
	ExpiresAt   time.Time
}

type User struct {
	Subject  string `json:"sub"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

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

// ── Built-in provider templates ────────────────────────────────────────────────

type ProviderTemplate struct {
	Name             string
	Type             string
	AuthorizationURL string
	AccessTokenURL   string
	ResourceURL      string
	LogoutURL        string
	UserIdentifier   string
	Scopes           []string
}

var providerTemplates = map[string]*ProviderTemplate{
	"google": {
		Name:             "Google",
		Type:             "oidc",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
		AccessTokenURL:   "https://oauth2.googleapis.com/token",
		ResourceURL:      "https://www.googleapis.com/oauth2/v2/userinfo",
		LogoutURL:        "https://accounts.google.com/logout",
		UserIdentifier:   "sub",
		Scopes:           []string{"openid", "profile", "email"},
	},
	"github": {
		Name:             "GitHub",
		Type:             "oauth2",
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		AccessTokenURL:   "https://github.com/login/oauth/access_token",
		ResourceURL:      "https://api.github.com/user",
		UserIdentifier:   "id",
		Scopes:           []string{"read:user", "user:email"},
	},
	"microsoft": {
		Name:             "Microsoft",
		Type:             "oidc",
		AuthorizationURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		AccessTokenURL:   "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		ResourceURL:      "https://graph.microsoft.com/v1.0/me",
		LogoutURL:        "https://login.microsoftonline.com/common/oauth2/v2.0/logout",
		UserIdentifier:   "sub",
		Scopes:           []string{"openid", "profile", "email"},
	},
	"discord": {
		Name:             "Discord",
		Type:             "oauth2",
		AuthorizationURL: "https://discord.com/api/oauth2/authorize",
		AccessTokenURL:   "https://discord.com/api/oauth2/token",
		ResourceURL:      "https://discord.com/api/users/@me",
		UserIdentifier:   "id",
		Scopes:           []string{"identify", "email"},
	},
	"okta": {
		Name:           "Okta",
		Type:           "oidc",
		UserIdentifier: "sub",
		Scopes:         []string{"openid", "profile", "email"},
	},
}

// ── CLI ────────────────────────────────────────────────────────────────────────

var (
	configPath string

	rootCmd = &cobra.Command{
		Use:   "access-nex",
		Short: "OIDC/OAuth2 provider and management CLI",
	}

	// ── user ──────────────────────────────────────────────────────────────────

	userCmd    = &cobra.Command{Use: "user", Short: "Manage users"}
	userAddCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a new user",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, _ := cmd.Flags().GetString("username")
			p, _ := cmd.Flags().GetString("password")
			e, _ := cmd.Flags().GetString("email")
			n, _ := cmd.Flags().GetString("name")
			if u == "" {
				return fmt.Errorf("username is required")
			}
			if p == "" {
				return fmt.Errorf("password is required")
			}
			return addUser(u, p, e, n)
		},
	}
	userListCmd = &cobra.Command{
		Use:  "list",
		RunE: func(cmd *cobra.Command, args []string) error { return listUsers() },
	}
	userDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Delete a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, _ := cmd.Flags().GetString("username")
			if u == "" {
				return fmt.Errorf("username is required")
			}
			return deleteUser(u)
		},
	}

	// ── app (unified: client registration + external provider linkage) ─────────

	appCmd = &cobra.Command{Use: "app", Short: "Manage applications (OAuth clients + integrations)"}

	appCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create an application",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			uris, _ := cmd.Flags().GetStringSlice("redirect-uri")
			pub, _ := cmd.Flags().GetBool("public")
			prov, _ := cmd.Flags().GetString("provider")
			sc, _ := cmd.Flags().GetString("scopes")
			if name == "" {
				return fmt.Errorf("name is required")
			}
			if len(uris) == 0 {
				return fmt.Errorf("at least one --redirect-uri is required")
			}
			return createApp(name, uris, pub, prov, sc)
		},
	}
	appListCmd = &cobra.Command{
		Use:  "list",
		RunE: func(cmd *cobra.Command, args []string) error { return listApps() },
	}
	appShowCmd = &cobra.Command{
		Use:   "show",
		Short: "Show application details",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}
			return showApp(id)
		},
	}
	appUpdateCmd = &cobra.Command{
		Use:   "update",
		Short: "Update an application",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}
			name, _ := cmd.Flags().GetString("name")
			uris, _ := cmd.Flags().GetStringSlice("redirect-uri")
			prov, _ := cmd.Flags().GetString("provider")
			sc, _ := cmd.Flags().GetString("scopes")
			return updateApp(id, name, uris, prov, sc)
		},
	}
	appDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Delete an application",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}
			return deleteApp(id)
		},
	}

	// ── provider ───────────────────────────────────────────────────────────────
	// provider self init/info  → local OIDC server
	// provider add/list/show/update/delete → external OAuth/OIDC providers

	providerCmd     = &cobra.Command{Use: "provider", Short: "Manage OIDC/OAuth2 providers (self + external)"}
	providerSelfCmd = &cobra.Command{Use: "self", Short: "Manage the local (self-hosted) OIDC provider"}

	providerSelfInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize the local OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			issuer, _ := cmd.Flags().GetString("issuer")
			if issuer == "" {
				issuer = defaultIssuer
			}
			return initializeProvider(issuer)
		},
	}
	providerSelfInfoCmd = &cobra.Command{
		Use:  "info",
		RunE: func(cmd *cobra.Command, args []string) error { return showProviderInfo() },
	}

	providerAddCmd = &cobra.Command{
		Use:   "add",
		Short: "Add an external OAuth/OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			tmpl, _ := cmd.Flags().GetString("type")
			cid, _ := cmd.Flags().GetString("client-id")
			csec, _ := cmd.Flags().GetString("client-secret")
			rurl, _ := cmd.Flags().GetString("redirect-url")
			aurl, _ := cmd.Flags().GetString("authorization-url")
			turl, _ := cmd.Flags().GetString("access-token-url")
			resurl, _ := cmd.Flags().GetString("resource-url")
			lurl, _ := cmd.Flags().GetString("logout-url")
			uid, _ := cmd.Flags().GetString("user-identifier")
			sc, _ := cmd.Flags().GetString("scopes")
			if name == "" {
				return fmt.Errorf("name is required")
			}
			if cid == "" {
				return fmt.Errorf("client-id is required")
			}
			if csec == "" {
				return fmt.Errorf("client-secret is required")
			}
			return addExternalProvider(name, tmpl, cid, csec, rurl, aurl, turl, resurl, lurl, uid, sc)
		},
	}
	providerListCmd = &cobra.Command{
		Use:  "list",
		RunE: func(cmd *cobra.Command, args []string) error { return listProviders() },
	}
	providerShowCmd = &cobra.Command{
		Use:   "show",
		Short: "Show external provider details",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}
			return showExternalProvider(id)
		},
	}
	providerUpdateCmd = &cobra.Command{
		Use:   "update",
		Short: "Update an external provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}
			name, _ := cmd.Flags().GetString("name")
			cid, _ := cmd.Flags().GetString("client-id")
			csec, _ := cmd.Flags().GetString("client-secret")
			rurl, _ := cmd.Flags().GetString("redirect-url")
			aurl, _ := cmd.Flags().GetString("authorization-url")
			turl, _ := cmd.Flags().GetString("access-token-url")
			resurl, _ := cmd.Flags().GetString("resource-url")
			lurl, _ := cmd.Flags().GetString("logout-url")
			uid, _ := cmd.Flags().GetString("user-identifier")
			sc, _ := cmd.Flags().GetString("scopes")
			return updateExternalProvider(id, name, cid, csec, rurl, aurl, turl, resurl, lurl, uid, sc)
		},
	}
	providerDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Delete an external provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}
			return deleteExternalProvider(id)
		},
	}

	serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start the OIDC/OAuth2 server",
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			return startServer(addr)
		},
	}

	shutdownCmd = &cobra.Command{
		Use:   "shutdown",
		Short: "Print instructions to stop the running server",
		RunE:  func(cmd *cobra.Command, args []string) error { return shutdownServer() },
	}
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "config directory (default .access-nex)")

	// user
	userCmd.AddCommand(userAddCmd, userListCmd, userDeleteCmd)
	userAddCmd.Flags().StringP("username", "u", "", "Username")
	userAddCmd.Flags().StringP("password", "p", "", "Password")
	userAddCmd.Flags().StringP("email", "e", "", "Email")
	userAddCmd.Flags().StringP("name", "n", "", "Full name")
	userDeleteCmd.Flags().StringP("username", "u", "", "Username to delete")

	// app
	appCmd.AddCommand(appCreateCmd, appListCmd, appShowCmd, appUpdateCmd, appDeleteCmd)
	appCreateCmd.Flags().StringP("name", "n", "", "Application name")
	appCreateCmd.Flags().StringSliceP("redirect-uri", "r", []string{}, "Redirect URI (repeatable)")
	appCreateCmd.Flags().Bool("public", false, "Public client (PKCE, no secret)")
	appCreateCmd.Flags().StringP("provider", "p", "", "External provider ID (omit to use access-nex itself)")
	appCreateCmd.Flags().StringP("scopes", "s", "", "Comma-separated scopes")
	appShowCmd.Flags().StringP("id", "i", "", "Application ID")
	appUpdateCmd.Flags().StringP("id", "i", "", "Application ID")
	appUpdateCmd.Flags().StringP("name", "n", "", "Name")
	appUpdateCmd.Flags().StringSliceP("redirect-uri", "r", []string{}, "Redirect URIs")
	appUpdateCmd.Flags().StringP("provider", "p", "", "External provider ID")
	appUpdateCmd.Flags().StringP("scopes", "s", "", "Scopes")
	appDeleteCmd.Flags().StringP("id", "i", "", "Application ID")

	// provider self
	providerSelfCmd.AddCommand(providerSelfInitCmd, providerSelfInfoCmd)
	providerSelfInitCmd.Flags().StringP("issuer", "i", defaultIssuer, "Issuer URL")

	// provider external
	sharedProviderFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringP("client-id", "c", "", "OAuth Client ID")
		cmd.Flags().StringP("client-secret", "s", "", "OAuth Client Secret")
		cmd.Flags().StringP("redirect-url", "r", "", "Redirect/callback URL registered with the provider")
		cmd.Flags().String("authorization-url", "", "Authorization endpoint URL")
		cmd.Flags().String("access-token-url", "", "Token endpoint URL")
		cmd.Flags().String("resource-url", "", "UserInfo/resource endpoint URL")
		cmd.Flags().String("logout-url", "", "Logout endpoint URL")
		cmd.Flags().String("user-identifier", "", "JSON field used as user ID (e.g. sub, id)")
		cmd.Flags().String("scopes", "", "Comma-separated scopes")
	}
	providerAddCmd.Flags().StringP("name", "n", "", "Provider name")
	providerAddCmd.Flags().StringP("type", "t", "custom", "Template: google|github|microsoft|discord|okta|custom")
	sharedProviderFlags(providerAddCmd)

	providerShowCmd.Flags().StringP("id", "i", "", "Provider ID")
	providerUpdateCmd.Flags().StringP("id", "i", "", "Provider ID")
	providerUpdateCmd.Flags().StringP("name", "n", "", "Provider name")
	sharedProviderFlags(providerUpdateCmd)
	providerDeleteCmd.Flags().StringP("id", "i", "", "Provider ID")

	providerCmd.AddCommand(providerSelfCmd, providerAddCmd, providerListCmd, providerShowCmd, providerUpdateCmd, providerDeleteCmd)

	serverCmd.Flags().StringP("addr", "a", defaultAddr, "Listen address")

	rootCmd.AddCommand(userCmd, appCmd, providerCmd, serverCmd, shutdownCmd)
}

func initConfig() {
	if configPath == "" {
		configPath = configDir
	}
	if err := os.MkdirAll(configPath, 0755); err != nil {
		log.Fatal(err)
	}
}

// ── User management ────────────────────────────────────────────────────────────

func addUser(username, password, email, name string) error {
	users, err := loadUsers()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if users == nil {
		users = make(map[string]*User)
	}
	if _, exists := users[username]; exists {
		return fmt.Errorf("user %s already exists", username)
	}
	subject := fmt.Sprintf("user-%s-%d", username, time.Now().UnixNano())
	users[username] = &User{Subject: subject, Username: username, Password: password, Email: email, Name: name}
	if err := saveUsers(users); err != nil {
		return err
	}
	fmt.Printf("✓ User '%s' created (subject: %s)\n", username, subject)
	return nil
}

func listUsers() error {
	users, err := loadUsers()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No users found")
			return nil
		}
		return err
	}
	if len(users) == 0 {
		fmt.Println("No users found")
		return nil
	}
	fmt.Printf("\n%-20s %-40s %-25s %-20s\n", "Username", "Subject", "Email", "Name")
	fmt.Println(strings.Repeat("-", 110))
	for _, u := range users {
		fmt.Printf("%-20s %-40s %-25s %-20s\n", u.Username, u.Subject, u.Email, u.Name)
	}
	fmt.Println()
	return nil
}

func deleteUser(username string) error {
	users, err := loadUsers()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("user not found")
		}
		return err
	}
	if _, exists := users[username]; !exists {
		return fmt.Errorf("user %s not found", username)
	}
	delete(users, username)
	if err := saveUsers(users); err != nil {
		return err
	}
	fmt.Printf("✓ User '%s' deleted\n", username)
	return nil
}

// ── App management ─────────────────────────────────────────────────────────────

func createApp(name string, redirectURIs []string, public bool, providerID, scopesStr string) error {
	apps, err := loadApps()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if apps == nil {
		apps = make(map[string]*App)
	}

	id := fmt.Sprintf("client-%s-%d",
		strings.ToLower(strings.ReplaceAll(name, " ", "-")),
		time.Now().UnixNano())

	var secret string
	if !public {
		secret = randomToken(32)
	}

	scopes := parseScope(scopesStr)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	apps[id] = &App{
		ID:           id,
		Name:         name,
		RedirectURIs: redirectURIs,
		Public:       public,
		Secret:       secret,
		ProviderID:   providerID,
		Scopes:       scopes,
		Enabled:      true,
		CreatedAt:    time.Now().Format(time.RFC3339),
		UpdatedAt:    time.Now().Format(time.RFC3339),
	}
	if err := saveApps(apps); err != nil {
		return err
	}

	prov := providerID
	if prov == "" {
		prov = "self (access-nex)"
	}
	fmt.Printf("\n✓ Application '%s' created\n", name)
	fmt.Printf("  Client ID:     %s\n", id)
	if !public {
		fmt.Printf("  Client Secret: %s\n", secret)
	} else {
		fmt.Printf("  Type:          Public (PKCE)\n")
	}
	fmt.Printf("  Provider:      %s\n", prov)
	fmt.Printf("  Scopes:        %s\n", strings.Join(scopes, ", "))
	fmt.Printf("  Redirect URIs:\n")
	for _, u := range redirectURIs {
		fmt.Printf("    - %s\n", u)
	}
	fmt.Println()
	return nil
}

func listApps() error {
	apps, err := loadApps()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No applications found")
			return nil
		}
		return err
	}
	if len(apps) == 0 {
		fmt.Println("No applications found")
		return nil
	}
	fmt.Printf("\n%-38s %-22s %-12s %-20s\n", "Client ID", "Name", "Type", "Provider")
	fmt.Println(strings.Repeat("-", 96))
	for _, a := range apps {
		t := "Confidential"
		if a.Public {
			t = "Public"
		}
		prov := a.ProviderID
		if prov == "" {
			prov = "self"
		}
		fmt.Printf("%-38s %-22s %-12s %-20s\n", a.ID, a.Name, t, prov)
	}
	fmt.Println()
	return nil
}

func showApp(id string) error {
	apps, err := loadApps()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("app not found")
		}
		return err
	}
	a, ok := apps[id]
	if !ok {
		return fmt.Errorf("app %s not found", id)
	}
	t := "Confidential"
	if a.Public {
		t = "Public (PKCE)"
	}
	prov := a.ProviderID
	if prov == "" {
		prov = "self (access-nex)"
	}
	fmt.Printf("\nApplication: %s\n", a.Name)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  ID:            %s\n", a.ID)
	fmt.Printf("  Type:          %s\n", t)
	fmt.Printf("  Provider:      %s\n", prov)
	fmt.Printf("  Scopes:        %s\n", strings.Join(a.Scopes, ", "))
	fmt.Printf("  Enabled:       %v\n", a.Enabled)
	if !a.Public {
		fmt.Printf("  Secret:        %s\n", maskSecret(a.Secret))
	}
	fmt.Printf("  Redirect URIs:\n")
	for _, u := range a.RedirectURIs {
		fmt.Printf("    - %s\n", u)
	}
	fmt.Printf("  Created:       %s\n", a.CreatedAt)
	fmt.Printf("  Updated:       %s\n\n", a.UpdatedAt)
	return nil
}

func updateApp(id, name string, redirectURIs []string, providerID, scopesStr string) error {
	apps, err := loadApps()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("app not found")
		}
		return err
	}
	a, ok := apps[id]
	if !ok {
		return fmt.Errorf("app %s not found", id)
	}
	if name != "" {
		a.Name = name
	}
	if len(redirectURIs) > 0 {
		a.RedirectURIs = redirectURIs
	}
	if providerID != "" {
		a.ProviderID = providerID
	}
	if scopesStr != "" {
		a.Scopes = parseScope(scopesStr)
	}
	a.UpdatedAt = time.Now().Format(time.RFC3339)
	apps[id] = a
	if err := saveApps(apps); err != nil {
		return err
	}
	fmt.Printf("✓ Application '%s' updated\n", a.Name)
	return nil
}

func deleteApp(id string) error {
	apps, err := loadApps()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("app not found")
		}
		return err
	}
	a, ok := apps[id]
	if !ok {
		return fmt.Errorf("app %s not found", id)
	}
	delete(apps, id)
	if err := saveApps(apps); err != nil {
		return err
	}
	fmt.Printf("✓ Application '%s' deleted\n", a.Name)
	return nil
}

// ── Self-provider management ───────────────────────────────────────────────────

func initializeProvider(issuer string) error {
	issuer = strings.TrimRight(issuer, "/")
	if err := saveProvider(map[string]interface{}{"issuer": issuer, "keyID": "dev-key-1"}); err != nil {
		return err
	}
	fmt.Printf("\n✓ Local OIDC Provider initialized\n")
	fmt.Printf("  Issuer:    %s\n", issuer)
	fmt.Printf("  Discovery: %s/.well-known/openid-configuration\n", issuer)
	fmt.Printf("  OAuth proxy: %s/oauth/start\n\n", issuer)
	return nil
}

func showProviderInfo() error {
	data, err := loadProvider()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Provider not initialized. Run 'provider self init' first.")
			return nil
		}
		return err
	}
	issuer, _ := data["issuer"].(string)
	keyID, _ := data["keyID"].(string)
	users, _ := loadUsers()
	apps, _ := loadApps()
	ext, _ := loadExternalProviders()
	fmt.Printf("\nLocal Provider:\n")
	fmt.Printf("  Issuer:           %s\n", issuer)
	fmt.Printf("  Key ID:           %s\n", keyID)
	fmt.Printf("  Users:            %d\n", len(users))
	fmt.Printf("  Applications:     %d\n", len(apps))
	fmt.Printf("  Ext. Providers:   %d\n", len(ext))
	fmt.Println()
	return nil
}

// ── External provider management ──────────────────────────────────────────────

func addExternalProvider(name, tmpl, clientID, clientSecret, redirectURL, authURL, tokenURL, resourceURL, logoutURL, userID, scopesStr string) error {
	providers, err := loadExternalProviders()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if providers == nil {
		providers = make(map[string]*ExternalProvider)
	}

	id := fmt.Sprintf("provider-%s-%d",
		strings.ToLower(strings.ReplaceAll(name, " ", "-")),
		time.Now().UnixNano())

	ep := &ExternalProvider{
		ID:             id,
		Name:           name,
		Template:       tmpl,
		Type:           "oauth2",
		ClientID:       clientID,
		UserIdentifier: "id",
		Scopes:         []string{"openid", "profile", "email"},
		Enabled:        true,
		CreatedAt:      time.Now().Format(time.RFC3339),
		UpdatedAt:      time.Now().Format(time.RFC3339),
	}

	if pt := providerTemplates[tmpl]; pt != nil {
		ep.Type = pt.Type
		ep.AuthorizationURL = pt.AuthorizationURL
		ep.AccessTokenURL = pt.AccessTokenURL
		ep.ResourceURL = pt.ResourceURL
		ep.LogoutURL = pt.LogoutURL
		ep.UserIdentifier = pt.UserIdentifier
		ep.Scopes = pt.Scopes
	}

	if authURL != "" {
		ep.AuthorizationURL = authURL
	}
	if tokenURL != "" {
		ep.AccessTokenURL = tokenURL
	}
	if resourceURL != "" {
		ep.ResourceURL = resourceURL
	}
	if logoutURL != "" {
		ep.LogoutURL = logoutURL
	}
	if userID != "" {
		ep.UserIdentifier = userID
	}
	if scopesStr != "" {
		ep.Scopes = parseScope(scopesStr)
	}
	if redirectURL != "" {
		ep.RedirectURL = redirectURL
	}

	enc, err := encryptSecret(clientSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %v", err)
	}
	ep.ClientSecret = enc

	providers[id] = ep
	if err := saveExternalProviders(providers); err != nil {
		return err
	}

	fmt.Printf("\n✓ Provider '%s' added\n", name)
	fmt.Printf("  ID:         %s\n", id)
	fmt.Printf("  Template:   %s\n", tmpl)
	fmt.Printf("  Type:       %s\n", ep.Type)
	fmt.Printf("  Client ID:  %s\n", clientID)
	if ep.AuthorizationURL != "" {
		fmt.Printf("  Auth URL:   %s\n", ep.AuthorizationURL)
	}
	fmt.Printf("  Scopes:     %s\n\n", strings.Join(ep.Scopes, ", "))
	return nil
}

func listProviders() error {
	data, err := loadProvider()
	selfIssuer := "(not initialized — run: provider self init)"
	if err == nil {
		if v, ok := data["issuer"].(string); ok {
			selfIssuer = v
		}
	}

	fmt.Printf("\n%-12s %-22s %-8s %s\n", "ID", "Name", "Type", "Auth URL / Issuer")
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-12s %-22s %-8s %s\n", "self", "Local (access-nex)", "oidc", selfIssuer)

	providers, err := loadExternalProviders()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, ep := range providers {
		status := ""
		if !ep.Enabled {
			status = " [disabled]"
		}
		fmt.Printf("%s %-22s %-8s %s%s\n",
			ep.ID, ep.Name, ep.Type,
			trunc(ep.AuthorizationURL, 55), status)
	}
	fmt.Println()
	return nil
}

func showExternalProvider(id string) error {
	providers, err := loadExternalProviders()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("provider not found")
		}
		return err
	}
	ep, ok := providers[id]
	if !ok {
		return fmt.Errorf("provider %s not found", id)
	}
	secret, err := decryptSecret(ep.ClientSecret)
	if err != nil {
		secret = "[unable to decrypt]"
	}
	fmt.Printf("\nProvider: %s\n", ep.Name)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  ID:                %s\n", ep.ID)
	fmt.Printf("  Template:          %s\n", ep.Template)
	fmt.Printf("  Type:              %s\n", ep.Type)
	fmt.Printf("  Client ID:         %s\n", ep.ClientID)
	fmt.Printf("  Client Secret:     %s\n", maskSecret(secret))
	fmt.Printf("  Redirect URL:      %s\n", ep.RedirectURL)
	fmt.Printf("  Authorization URL: %s\n", ep.AuthorizationURL)
	fmt.Printf("  Access Token URL:  %s\n", ep.AccessTokenURL)
	fmt.Printf("  Resource URL:      %s\n", ep.ResourceURL)
	fmt.Printf("  Logout URL:        %s\n", ep.LogoutURL)
	fmt.Printf("  User Identifier:   %s\n", ep.UserIdentifier)
	fmt.Printf("  Scopes:            %s\n", strings.Join(ep.Scopes, ", "))
	fmt.Printf("  Enabled:           %v\n", ep.Enabled)
	fmt.Printf("  Created:           %s\n", ep.CreatedAt)
	fmt.Printf("  Updated:           %s\n\n", ep.UpdatedAt)
	return nil
}

func updateExternalProvider(id, name, clientID, clientSecret, redirectURL, authURL, tokenURL, resourceURL, logoutURL, userID, scopesStr string) error {
	providers, err := loadExternalProviders()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("provider not found")
		}
		return err
	}
	ep, ok := providers[id]
	if !ok {
		return fmt.Errorf("provider %s not found", id)
	}
	if name != "" {
		ep.Name = name
	}
	if clientID != "" {
		ep.ClientID = clientID
	}
	if clientSecret != "" {
		enc, err := encryptSecret(clientSecret)
		if err != nil {
			return err
		}
		ep.ClientSecret = enc
	}
	if redirectURL != "" {
		ep.RedirectURL = redirectURL
	}
	if authURL != "" {
		ep.AuthorizationURL = authURL
	}
	if tokenURL != "" {
		ep.AccessTokenURL = tokenURL
	}
	if resourceURL != "" {
		ep.ResourceURL = resourceURL
	}
	if logoutURL != "" {
		ep.LogoutURL = logoutURL
	}
	if userID != "" {
		ep.UserIdentifier = userID
	}
	if scopesStr != "" {
		ep.Scopes = parseScope(scopesStr)
	}
	ep.UpdatedAt = time.Now().Format(time.RFC3339)
	providers[id] = ep
	if err := saveExternalProviders(providers); err != nil {
		return err
	}
	fmt.Printf("✓ Provider '%s' updated\n", ep.Name)
	return nil
}

func deleteExternalProvider(id string) error {
	providers, err := loadExternalProviders()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("provider not found")
		}
		return err
	}
	ep, ok := providers[id]
	if !ok {
		return fmt.Errorf("provider %s not found", id)
	}
	delete(providers, id)
	if err := saveExternalProviders(providers); err != nil {
		return err
	}
	fmt.Printf("✓ Provider '%s' deleted\n", ep.Name)
	return nil
}

// ── Server startup ─────────────────────────────────────────────────────────────

func startServer(addr string) error {
	providerData, err := loadProvider()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("provider not initialized — run 'provider self init' first")
		}
		return err
	}
	issuer, _ := providerData["issuer"].(string)
	if issuer == "" {
		issuer = defaultIssuer
	}

	p, err := NewProvider(issuer)
	if err != nil {
		return err
	}

	users, _ := loadUsers()
	for k, v := range users {
		p.users[k] = v
	}

	apps, _ := loadApps()
	for _, a := range apps {
		p.clients[a.ID] = a.toClient()
	}

	extProviders, _ := loadExternalProviders()
	for id, ep := range extProviders {
		if ep.Enabled {
			p.extProviders[id] = ep
		}
	}

	mux := http.NewServeMux()
	p.routes(mux)

	fmt.Printf("\n✓ OIDC/OAuth2 provider starting on %s\n", addr)
	fmt.Printf("  Issuer:          %s\n", issuer)
	fmt.Printf("  Users:           %d\n", len(p.users))
	fmt.Printf("  Applications:    %d\n", len(p.clients))
	fmt.Printf("  Ext. Providers:  %d\n", len(p.extProviders))
	fmt.Printf("  OAuth Proxy:     %s/oauth/start\n", issuer)
	fmt.Printf("  Discovery:       %s/.well-known/openid-configuration\n\n", issuer)

	return http.ListenAndServe(addr, withSecurityHeaders(mux))
}

func NewProvider(issuer string) (*Provider, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Provider{
		issuer:        issuer,
		key:           privKey,
		keyID:         "dev-key-1",
		clients:       make(map[string]*Client),
		users:         make(map[string]*User),
		authCodes:     make(map[string]*AuthCode),
		accessTokens:  make(map[string]*TokenRecord),
		refreshTokens: make(map[string]*RefreshRecord),
		sessions:      make(map[string]*Session),
		extProviders:  make(map[string]*ExternalProvider),
		oauthStates:   make(map[string]*oauthProxyState),
	}, nil
}

func (p *Provider) routes(mux *http.ServeMux) {
	// Local OIDC/OAuth2 endpoints
	mux.HandleFunc("/", p.handleHome)
	mux.HandleFunc("/healthz", p.handleHealth)
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/jwks", p.handleJWKS)
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	mux.HandleFunc("/revoke", p.handleRevoke)
	mux.HandleFunc("/introspect", p.handleIntrospect)
	mux.HandleFunc("/userinfo", p.handleUserInfo)
	mux.HandleFunc("/register", p.handleRegister)
	mux.HandleFunc("/end_session", p.handleEndSession)
	mux.HandleFunc("/account", p.handleAccount)
	mux.HandleFunc("/apps", p.handleListApps)

	// External OAuth proxy: start a flow with an external provider, get back a
	// local auth code exchangeable at /token.
	mux.HandleFunc("/oauth/providers", p.handleOAuthProviders)
	mux.HandleFunc("/oauth/start", p.handleOAuthStart)
	mux.HandleFunc("/oauth/callback", p.handleOAuthCallback)

	// Built-in admin portal: direct session login to test user validation.
	mux.HandleFunc("/login", p.handleLogin)
	mux.HandleFunc("/portal", p.handlePortal)
	mux.HandleFunc("/portal/logout", p.handlePortalLogout)
}

// ── External OAuth proxy handlers ─────────────────────────────────────────────

// handleOAuthProviders returns the list of enabled external providers.
func (p *Provider) handleOAuthProviders(w http.ResponseWriter, r *http.Request) {
	type info struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		Type   string   `json:"type"`
		Scopes []string `json:"scopes"`
	}
	p.mu.Lock()
	list := make([]info, 0, len(p.extProviders))
	for _, ep := range p.extProviders {
		list = append(list, info{ID: ep.ID, Name: ep.Name, Type: ep.Type, Scopes: ep.Scopes})
	}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"providers": list})
}

// handleOAuthStart redirects the user to an external provider.
// Query params: provider_id, client_id, redirect_uri, state (optional), nonce (optional), scope (optional)
func (p *Provider) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	providerID := q.Get("provider_id")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	originalState := q.Get("state")
	nonce := q.Get("nonce")
	scopeStr := q.Get("scope")

	if providerID == "" {
		http.Error(w, "provider_id is required", http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	ep := p.extProviders[providerID]
	client := p.clients[clientID]
	p.mu.Unlock()

	if ep == nil {
		http.Error(w, "unknown provider_id", http.StatusBadRequest)
		return
	}
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
	if scopeStr != "" {
		scopes = parseScope(scopeStr)
	}

	proxyState := "proxy-" + randomToken(24)
	p.mu.Lock()
	p.oauthStates[proxyState] = &oauthProxyState{
		ProviderID:  providerID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       originalState,
		Nonce:       nonce,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	p.mu.Unlock()

	// The callback URL access-nex registered with the external provider.
	callbackURL := p.issuer + "/oauth/callback"
	if ep.RedirectURL != "" {
		callbackURL = ep.RedirectURL
	}

	authURL, err := url.Parse(ep.AuthorizationURL)
	if err != nil {
		http.Error(w, "invalid provider authorization_url", http.StatusInternalServerError)
		return
	}
	aq := authURL.Query()
	aq.Set("client_id", ep.ClientID)
	aq.Set("response_type", "code")
	aq.Set("redirect_uri", callbackURL)
	aq.Set("state", proxyState)
	aq.Set("scope", strings.Join(scopes, " "))
	if nonce != "" && ep.Type == "oidc" {
		aq.Set("nonce", nonce)
	}
	authURL.RawQuery = aq.Encode()
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// handleOAuthCallback receives the callback from an external provider,
// exchanges the code, provisions a local user, and issues a local auth code
// that the calling app can exchange at /token.
func (p *Provider) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")
	errParam := q.Get("error")

	if state == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	pending := p.oauthStates[state]
	if pending != nil {
		delete(p.oauthStates, state)
	}
	p.mu.Unlock()

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

	p.mu.Lock()
	ep := p.extProviders[pending.ProviderID]
	p.mu.Unlock()
	if ep == nil {
		http.Error(w, "provider no longer configured", http.StatusInternalServerError)
		return
	}

	secret, err := decryptSecret(ep.ClientSecret)
	if err != nil {
		log.Printf("oauth callback: decrypt secret: %v", err)
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}

	callbackURL := p.issuer + "/oauth/callback"
	if ep.RedirectURL != "" {
		callbackURL = ep.RedirectURL
	}

	extTokens, err := exchangeCodeWithProvider(ep.AccessTokenURL, ep.ClientID, secret, code, callbackURL)
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

	var userInfo map[string]interface{}
	if ep.ResourceURL != "" {
		userInfo, err = fetchUserInfo(ep.ResourceURL, accessToken)
		if err != nil {
			log.Printf("oauth callback: userinfo: %v", err)
			http.Error(w, "failed to fetch user info", http.StatusBadGateway)
			return
		}
	} else {
		userInfo = make(map[string]interface{})
	}

	subject, isNew := p.provisionExternalUser(pending.ProviderID, ep.UserIdentifier, userInfo)
	if isNew {
		p.mu.Lock()
		snapshot := make(map[string]*User, len(p.users))
		for k, v := range p.users {
			snapshot[k] = v
		}
		p.mu.Unlock()
		_ = saveUsers(snapshot)
	}

	localCode := randomToken(32)
	p.mu.Lock()
	p.authCodes[localCode] = &AuthCode{
		Code:        localCode,
		ClientID:    pending.ClientID,
		RedirectURI: pending.RedirectURI,
		Subject:     subject,
		Scope:       pending.Scopes,
		Nonce:       pending.Nonce,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		AuthTime:    time.Now(),
	}
	p.mu.Unlock()

	redir, _ := url.Parse(pending.RedirectURI)
	rq := redir.Query()
	rq.Set("code", localCode)
	rq.Set("iss", p.issuer)
	if pending.State != "" {
		rq.Set("state", pending.State)
	}
	redir.RawQuery = rq.Encode()
	http.Redirect(w, r, redir.String(), http.StatusFound)
}

// provisionExternalUser finds or creates a local user for an external identity.
// Returns (subject, isNew). Caller must NOT hold p.mu.
func (p *Provider) provisionExternalUser(providerID, userIdentifier string, userInfo map[string]interface{}) (string, bool) {
	externalID := fmt.Sprintf("%v", userInfo[userIdentifier])
	subject := fmt.Sprintf("ext:%s:%s", providerID, externalID)

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, u := range p.users {
		if u.Subject == subject {
			return subject, false
		}
	}

	email, _ := userInfo["email"].(string)
	name, _ := userInfo["name"].(string)
	login, _ := userInfo["login"].(string) // GitHub
	if login == "" {
		login, _ = userInfo["preferred_username"].(string)
	}
	if login == "" && email != "" {
		parts := strings.SplitN(email, "@", 2)
		login = parts[0]
	}
	suffix := externalID
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	if login == "" {
		login = "ext-" + suffix
	}

	username := login
	if _, exists := p.users[username]; exists {
		username = login + "-" + suffix
	}

	p.users[username] = &User{
		Subject:  subject,
		Username: username,
		Email:    email,
		Name:     name,
	}
	return subject, true
}

// exchangeCodeWithProvider POSTs to a token endpoint to exchange an auth code.
func exchangeCodeWithProvider(tokenURL, clientID, clientSecret, code, redirectURI string) (map[string]interface{}, error) {
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, body)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid token response: %v", err)
	}
	return result, nil
}

// fetchUserInfo calls the provider's resource/userinfo endpoint.
func fetchUserInfo(resourceURL, accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, resourceURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint %d: %s", resp.StatusCode, body)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid userinfo response: %v", err)
	}
	return result, nil
}

// ── OIDC server handlers (unchanged logic) ─────────────────────────────────────

func (p *Provider) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	subject, loggedIn := p.subjectFromSession(r)
	var sessionUser *User
	if loggedIn {
		sessionUser = p.userBySubject(subject)
	}

	p.mu.Lock()
	extCount := len(p.extProviders)
	appCount := len(p.clients)
	userCount := len(p.users)
	p.mu.Unlock()

	// Header right-hand side: sign-in button or user info
	var headerRight string
	if loggedIn && sessionUser != nil {
		headerRight = `<div style="margin-top:16px;display:flex;align-items:center;justify-content:center;gap:16px">
		  <span style="background:rgba(255,255,255,.2);padding:6px 14px;border-radius:20px;font-size:14px">
		    👤 ` + html2string(sessionUser.Name) + ` (` + html2string(sessionUser.Username) + `)
		  </span>
		  <a href="/portal" style="background:#fff;color:#667eea;padding:7px 18px;border-radius:6px;font-weight:600;font-size:14px;text-decoration:none">My Account</a>
		  <a href="/portal/logout" style="background:rgba(255,255,255,.15);color:#fff;padding:7px 18px;border-radius:6px;font-size:14px;text-decoration:none;border:1px solid rgba(255,255,255,.4)">Sign Out</a>
		</div>`
	} else {
		headerRight = `<div style="margin-top:20px">
		  <a href="/login" style="background:#fff;color:#667eea;padding:10px 28px;border-radius:6px;font-weight:700;font-size:15px;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.2)">Sign In</a>
		</div>`
	}

	html := `<!doctype html><html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Access-Nex</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;color:#333}
    .header{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:40px 20px;text-align:center}
    .header h1{font-size:36px;margin-bottom:8px}.header p{font-size:17px;opacity:.85}
    .container{max-width:1000px;margin:40px auto;padding:20px}
    .section{background:#fff;border-radius:8px;padding:28px;margin-bottom:28px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
    .section h2{color:#667eea;margin-bottom:18px;font-size:17px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
    .card{background:#f9f9f9;padding:18px;border-radius:6px;border-left:4px solid #667eea}
    .card strong{display:block;color:#667eea;margin-bottom:6px;font-size:13px;text-transform:uppercase;letter-spacing:.5px}
    .card span{font-size:22px;font-weight:700;color:#333}
    code{background:#eee;padding:2px 6px;border-radius:3px;font-size:12px;font-family:monospace}
    .ep{margin-bottom:8px;padding:9px 12px;background:#f0f0f0;border-radius:4px;font-family:monospace;font-size:13px}
    .method{color:#667eea;font-weight:bold;margin-right:8px}
    .badge{background:#d4edda;color:#155724;padding:3px 10px;border-radius:10px;font-size:12px;font-weight:600}
    a{color:#667eea;text-decoration:none}a:hover{text-decoration:underline}
    .footer{text-align:center;padding:24px;color:#888;font-size:13px}
    .btn{display:inline-block;padding:9px 20px;border-radius:6px;font-weight:600;font-size:14px;text-decoration:none}
    .btn-primary{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff}
  </style></head><body>
  <div class="header">
    <h1>🔐 Access-Nex</h1>
    <p>OAuth2 &amp; OpenID Connect Provider</p>
    ` + headerRight + `
  </div>
  <div class="container">
    <div class="section"><h2>Status</h2><div class="grid">
      <div class="card"><strong>Status</strong><span><span class="badge">✓ Running</span></span></div>
      <div class="card"><strong>Issuer</strong><span style="font-size:13px"><code>` + p.issuer + `</code></span></div>
      <div class="card"><strong>Users</strong><span>` + fmt.Sprintf("%d", userCount) + `</span></div>
      <div class="card"><strong>Applications</strong><span>` + fmt.Sprintf("%d", appCount) + `</span></div>
      <div class="card"><strong>Ext. Providers</strong><span>` + fmt.Sprintf("%d", extCount) + `</span></div>
    </div></div>

    <div class="section"><h2>OIDC / OAuth2 Endpoints</h2>
      <div class="ep"><span class="method">GET</span><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a> — Discovery</div>
      <div class="ep"><span class="method">GET/POST</span>/authorize — Authorization</div>
      <div class="ep"><span class="method">POST</span>/token — Token exchange</div>
      <div class="ep"><span class="method">GET</span>/userinfo — User claims</div>
      <div class="ep"><span class="method">GET</span>/jwks — Public key set</div>
      <div class="ep"><span class="method">POST</span>/revoke &nbsp;/introspect &nbsp;/register &nbsp;/end_session</div>
    </div>

    <div class="section"><h2>OAuth Proxy (External Providers)</h2>
      <div class="ep"><span class="method">GET</span><a href="/oauth/providers">/oauth/providers</a> — list enabled external providers</div>
      <div class="ep"><span class="method">GET</span>/oauth/start?provider_id=X&amp;client_id=Y&amp;redirect_uri=Z — begin SSO</div>
      <div class="ep"><span class="method">GET</span>/oauth/callback — receive code → issue local JWT</div>
    </div>

    <div class="section"><h2>Quick Links</h2><div class="grid">
      <div class="card"><strong>Applications</strong><a class="btn btn-primary" style="margin-top:10px;display:inline-block" href="/apps">View Apps</a></div>
      <div class="card"><strong>Sign In &amp; Test</strong><a class="btn btn-primary" style="margin-top:10px;display:inline-block" href="/login">Login Portal</a></div>
      <div class="card"><strong>Ext. Providers</strong><a class="btn btn-primary" style="margin-top:10px;display:inline-block" href="/oauth/providers">JSON</a></div>
      <div class="card"><strong>Discovery Doc</strong><a class="btn btn-primary" style="margin-top:10px;display:inline-block" href="/.well-known/openid-configuration">OpenID Config</a></div>
    </div></div>
  </div>
  <div class="footer">Access-Nex — OAuth2 &amp; OIDC Provider</div>
</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleLogin renders and processes the direct session login form.
// This bypasses the full OAuth flow so you can quickly validate that a user
// credential works and inspect the session/claims in the portal.
func (p *Provider) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Already logged in → go straight to portal
	if subject, ok := p.subjectFromSession(r); ok && subject != "" {
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
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		rt := r.Form.Get("return_to")
		if rt != "" {
			returnTo = rt
		}

		if subject, ok := p.authenticateUser(username, password); ok {
			sessionID := randomToken(32)
			expires := time.Now().Add(8 * time.Hour)
			p.mu.Lock()
			p.sessions[sessionID] = &Session{ID: sessionID, Subject: subject, ExpiresAt: expires}
			p.mu.Unlock()
			http.SetCookie(w, &http.Cookie{
				Name:     "oidc_sid",
				Value:    sessionID,
				Path:     "/",
				Expires:  expires,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
		p.renderDirectLoginPage(w, "Invalid username or password", returnTo)
		return
	}

	p.renderDirectLoginPage(w, "", returnTo)
}

func (p *Provider) renderDirectLoginPage(w http.ResponseWriter, errMsg, returnTo string) {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="error">` + html2string(errMsg) + `</div>`
	}
	page := `<!doctype html><html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sign In — Access-Nex</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{background:#fff;border-radius:12px;padding:44px;width:100%;max-width:400px;box-shadow:0 24px 64px rgba(0,0,0,.3)}
    .logo{font-size:26px;font-weight:700;color:#667eea;text-align:center}
    .sub{font-size:11px;color:#aaa;text-align:center;text-transform:uppercase;letter-spacing:1px;margin-bottom:32px}
    h2{font-size:20px;color:#333;margin-bottom:6px;text-align:center}
    .hint{font-size:13px;color:#888;text-align:center;margin-bottom:28px}
    label{display:block;font-size:12px;font-weight:600;color:#555;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px}
    input[type=text],input[type=password]{width:100%;padding:11px 13px;border:1px solid #ddd;border-radius:6px;font-size:15px;margin-bottom:16px;transition:border .2s}
    input:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.12)}
    button{width:100%;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;margin-top:6px}
    button:hover{opacity:.92}
    .error{background:#fee2e2;border:1px solid #fca5a5;color:#dc2626;padding:11px 14px;border-radius:6px;font-size:14px;margin-bottom:20px}
    .footer{text-align:center;margin-top:22px;font-size:12px;color:#aaa}
    .footer a{color:#667eea}
  </style>
</head><body>
  <div class="card">
    <div class="logo">🔐 Access-Nex</div>
    <div class="sub">Admin Portal</div>
    ` + errHTML + `
    <h2>Sign In</h2>
    <p class="hint">Enter your access-nex credentials to validate your account and inspect session details.</p>
    <form method="POST" action="/login">
      <input type="hidden" name="return_to" value="` + html2string(returnTo) + `">
      <label for="u">Username</label>
      <input type="text" id="u" name="username" placeholder="username" autocomplete="username" required autofocus>
      <label for="p">Password</label>
      <input type="password" id="p" name="password" placeholder="password" autocomplete="current-password" required>
      <button type="submit">Sign In</button>
    </form>
    <div class="footer"><a href="/">← Back to home</a></div>
  </div>
</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

// handlePortal shows the logged-in user's session details, live token counts,
// and a ready-to-copy OAuth configuration block for Portainer.
func (p *Provider) handlePortal(w http.ResponseWriter, r *http.Request) {
	subject, ok := p.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login?return_to=/portal", http.StatusFound)
		return
	}
	user := p.userBySubject(subject)
	if user == nil {
		http.Redirect(w, r, "/login?return_to=/portal", http.StatusFound)
		return
	}

	// Snapshot counts under lock
	p.mu.Lock()
	activeTokens := 0
	now := time.Now()
	for _, t := range p.accessTokens {
		if !t.Revoked && now.Before(t.ExpiresAt) {
			activeTokens++
		}
	}
	activeSessions := 0
	for _, s := range p.sessions {
		if now.Before(s.ExpiresAt) {
			activeSessions++
		}
	}
	// Find registered apps and pick any that has portainer-ish redirect URIs
	// so we can pre-fill the Portainer config block.
	type appSnap struct {
		id     string
		name   string
		secret string
		uris   []string
	}
	var apps []appSnap
	for _, c := range p.clients {
		apps = append(apps, appSnap{id: c.ID, name: c.Name, secret: c.Secret, uris: c.RedirectURIs})
	}
	p.mu.Unlock()

	// Build the app selector for the Portainer config section
	appOptionsHTML := `<option value="">— select an app —</option>`
	for _, a := range apps {
		appOptionsHTML += `<option value="` + html2string(a.id) + `" data-secret="` + html2string(a.secret) + `" data-uris="` + html2string(strings.Join(a.uris, ",")) + `">` + html2string(a.name) + ` (` + html2string(a.id) + `)</option>`
	}

	// Build the Portainer config rows (filled by JS when the user picks an app)
	portainerBlock := `
    <div class="section">
      <h2>Portainer OAuth Configuration</h2>
      <p style="font-size:14px;color:#666;margin-bottom:18px">
        Select a registered application below to generate the exact OAuth settings
        to paste into Portainer → Settings → Authentication → OAuth.
      </p>
      <div style="margin-bottom:16px">
        <label style="font-size:13px;font-weight:600;color:#555;display:block;margin-bottom:6px">Application</label>
        <select id="appSel" onchange="fillPortainer()" style="width:100%;padding:9px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px">
          ` + appOptionsHTML + `
        </select>
      </div>
      <div id="portainerConfig" style="display:none">
        <table style="width:100%;border-collapse:collapse;font-size:14px">
          <tr style="background:#f5f5f5"><th style="padding:10px 14px;text-align:left;font-weight:600;color:#444;border-bottom:2px solid #ddd">Portainer Setting</th><th style="padding:10px 14px;text-align:left;border-bottom:2px solid #ddd">Value</th></tr>
          <tr><td class="k">Provider</td><td><code>Custom</code></td></tr>
          <tr><td class="k">Client ID</td><td><code id="pc-cid"></code></td></tr>
          <tr><td class="k">Client Secret</td><td><code id="pc-sec"></code></td></tr>
          <tr><td class="k">Authorization URL</td><td><code>` + p.issuer + `/authorize</code></td></tr>
          <tr><td class="k">Access Token URL</td><td><code>` + p.issuer + `/token</code></td></tr>
          <tr><td class="k">Resource URL</td><td><code>` + p.issuer + `/userinfo</code></td></tr>
          <tr><td class="k">Logout URL</td><td><code>` + p.issuer + `/end_session</code></td></tr>
          <tr><td class="k">Redirect URL</td><td><code id="pc-redir"></code> <span style="font-size:12px;color:#888">(must match Portainer's base URL)</span></td></tr>
          <tr><td class="k">User Identifier</td><td><code>email</code></td></tr>
          <tr><td class="k">Scopes</td><td><code>openid profile email</code></td></tr>
          <tr><td class="k">Token Auth Method</td><td><code>client_secret_post</code></td></tr>
        </table>
        <p style="margin-top:14px;font-size:13px;color:#888">
          ⚠️ The Redirect URL in Portainer must exactly match one of the redirect URIs registered
          for the application above. If Portainer runs on a different host/port, update the app with
          <code>access-nex app update --id CLIENT_ID --redirect-uri http://portainer-host:9000/</code>
        </p>
        <div style="margin-top:16px">
          <button onclick="testFlow()" style="padding:9px 20px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600">
            ▶ Run OAuth Flow Test
          </button>
          <span id="flowResult" style="margin-left:14px;font-size:13px;color:#555"></span>
        </div>
      </div>
    </div>`

	page := `<!doctype html><html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Portal — Access-Nex</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;color:#333}
    .header{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:28px 20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
    .header h1{font-size:22px;font-weight:700}
    .header-actions a{color:#fff;font-size:14px;padding:6px 14px;border-radius:6px;text-decoration:none;background:rgba(255,255,255,.2);margin-left:8px}
    .header-actions a:hover{background:rgba(255,255,255,.35)}
    .container{max-width:960px;margin:32px auto;padding:0 20px 40px}
    .section{background:#fff;border-radius:8px;padding:26px;margin-bottom:24px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
    .section h2{color:#667eea;font-size:17px;margin-bottom:18px}
    .profile{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
    .field label{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#888;font-weight:600;display:block;margin-bottom:4px}
    .field span{font-size:15px;color:#333}
    .field code{font-family:monospace;font-size:12px;background:#f0f0f0;padding:3px 8px;border-radius:4px;word-break:break-all}
    .stat{text-align:center;background:#f9f9f9;border-radius:6px;padding:18px;border-left:4px solid #667eea}
    .stat .n{font-size:28px;font-weight:700;color:#667eea}
    .stat small{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:.5px}
    .grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px}
    table td.k{padding:10px 14px;font-weight:600;color:#555;border-bottom:1px solid #f0f0f0;white-space:nowrap;width:220px}
    table td{padding:10px 14px;border-bottom:1px solid #f0f0f0}
    table tr:last-child td{border-bottom:none}
    code{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:12px;font-family:monospace}
    .badge-ok{background:#d1fae5;color:#065f46;padding:3px 10px;border-radius:10px;font-size:12px;font-weight:600}
    .footer{text-align:center;color:#aaa;font-size:13px;margin-top:20px}
    a{color:#667eea;text-decoration:none}a:hover{text-decoration:underline}
  </style>
</head><body>
  <div class="header">
    <h1>🔐 Access-Nex Portal</h1>
    <div class="header-actions">
      <a href="/">Home</a>
      <a href="/portal/logout">Sign Out</a>
    </div>
  </div>
  <div class="container">

    <div class="section">
      <h2>Signed-In User <span class="badge-ok">✓ Validated</span></h2>
      <div class="profile">
        <div class="field"><label>Display Name</label><span>` + html2string(user.Name) + `</span></div>
        <div class="field"><label>Username</label><span>` + html2string(user.Username) + `</span></div>
        <div class="field"><label>Email</label><span>` + html2string(user.Email) + `</span></div>
        <div class="field"><label>Subject (sub)</label><code>` + html2string(user.Subject) + `</code></div>
      </div>
    </div>

    <div class="section">
      <h2>Live Server Stats</h2>
      <div class="grid3">
        <div class="stat"><div class="n">` + fmt.Sprintf("%d", activeSessions) + `</div><small>Active Sessions</small></div>
        <div class="stat"><div class="n">` + fmt.Sprintf("%d", activeTokens) + `</div><small>Active Tokens</small></div>
      </div>
    </div>

    ` + portainerBlock + `

  </div>
  <div class="footer">Access-Nex — OAuth2 &amp; OIDC Provider</div>

  <script>
  function fillPortainer() {
    var sel = document.getElementById('appSel');
    var opt = sel.options[sel.selectedIndex];
    if (!opt.value) { document.getElementById('portainerConfig').style.display='none'; return; }
    document.getElementById('pc-cid').textContent = opt.value;
    document.getElementById('pc-sec').textContent = opt.getAttribute('data-secret') || '(public client — no secret)';
    var uris = (opt.getAttribute('data-uris') || '').split(',');
    document.getElementById('pc-redir').textContent = uris[0] || '';
    document.getElementById('portainerConfig').style.display = 'block';
  }
  function testFlow() {
    var sel = document.getElementById('appSel');
    var opt = sel.options[sel.selectedIndex];
    if (!opt.value) { alert('Select an application first'); return; }
    var uris = (opt.getAttribute('data-uris') || '').split(',');
    var redirectUri = uris[0];
    if (!redirectUri) { alert('No redirect URI registered for this app'); return; }
    var state = Math.random().toString(36).slice(2);
    var url = '/authorize?response_type=code&client_id=' + encodeURIComponent(opt.value)
            + '&redirect_uri=' + encodeURIComponent(redirectUri)
            + '&scope=openid+profile+email&state=' + state;
    document.getElementById('flowResult').textContent = 'Opening OAuth flow in new tab…';
    window.open(url, '_blank');
  }
  </script>
</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (p *Provider) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("oidc_sid"); err == nil {
		p.mu.Lock()
		delete(p.sessions, cookie.Value)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_sid",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (p *Provider) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                        p.issuer,
		"authorization_endpoint":                        p.endpoint("/authorize"),
		"token_endpoint":                                p.endpoint("/token"),
		"userinfo_endpoint":                             p.endpoint("/userinfo"),
		"jwks_uri":                                      p.endpoint("/jwks"),
		"revocation_endpoint":                           p.endpoint("/revoke"),
		"introspection_endpoint":                        p.endpoint("/introspect"),
		"registration_endpoint":                         p.endpoint("/register"),
		"end_session_endpoint":                          p.endpoint("/end_session"),
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

func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "kid": p.keyID, "alg": "RS256",
			"n": b64(pub.N.Bytes()),
			"e": b64(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
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
	client, redirectURI, err := p.validateAuthorizeRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.RedirectURI = redirectURI
	if req.ResponseType != "code" {
		p.redirectWithOAuthError(w, r, req.RedirectURI, "unsupported_response_type", "Only code is supported", req.State)
		return
	}
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" &&
		req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
		p.redirectWithOAuthError(w, r, req.RedirectURI, "invalid_request", "Unsupported code_challenge_method", req.State)
		return
	}
	if subject, ok := p.subjectFromSession(r); ok {
		p.issueAuthorizationCode(w, r, req, subject)
		return
	}
	if req.Prompt == "none" {
		p.redirectWithOAuthError(w, r, req.RedirectURI, "login_required", "Login required", req.State)
		return
	}
	if r.Method == http.MethodPost {
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if subject, ok := p.authenticateUser(username, password); ok {
			sessionID := randomToken(32)
			expires := time.Now().Add(8 * time.Hour)
			p.mu.Lock()
			p.sessions[sessionID] = &Session{ID: sessionID, Subject: subject, ExpiresAt: expires}
			p.mu.Unlock()
			http.SetCookie(w, &http.Cookie{
				Name: "oidc_sid", Value: sessionID, Path: "/",
				Expires: expires, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
			p.issueAuthorizationCode(w, r, req, subject)
			return
		}
		p.renderLogin(w, req, client.Name, "Invalid username or password")
		return
	}
	p.renderLogin(w, req, client.Name, "")
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form body")
		return
	}
	client, authErr := p.authenticateClient(r)
	if authErr != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="access-nex"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", authErr)
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r, client)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r, client)
	case "client_credentials":
		p.handleClientCredentialsGrant(w, r, client)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant_type")
	}
}

func (p *Provider) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client *Client) {
	codeValue := r.Form.Get("code")
	if codeValue == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing code")
		return
	}
	p.mu.Lock()
	code := p.authCodes[codeValue]
	if code != nil {
		delete(p.authCodes, codeValue)
	}
	p.mu.Unlock()
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
	response, err := p.issueTokenResponse(client.ID, code.Subject, code.Scope, code.Nonce, code.AuthTime, true)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client *Client) {
	refreshToken := r.Form.Get("refresh_token")
	if refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing refresh_token")
		return
	}
	p.mu.Lock()
	refresh := p.refreshTokens[refreshToken]
	valid := refresh != nil && !refresh.Revoked && refresh.ClientID == client.ID && time.Now().Before(refresh.ExpiresAt)
	if valid {
		refresh.Revoked = true
	}
	p.mu.Unlock()
	if !valid {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh_token")
		return
	}
	response, err := p.issueTokenResponse(client.ID, refresh.Subject, refresh.Scope, "", time.Now(), true)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *Provider) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, client *Client) {
	if client.Public {
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized_client", "Public clients cannot use client_credentials")
		return
	}
	scope := parseScope(r.Form.Get("scope"))
	if len(scope) == 0 {
		scope = []string{"profile"}
	}
	record, err := p.issueAccessToken(client.ID, client.ID, scope)
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

func (p *Provider) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form body")
		return
	}
	client, authErr := p.authenticateClient(r)
	if authErr != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="access-nex"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", authErr)
		return
	}
	token := r.Form.Get("token")
	p.mu.Lock()
	if a := p.accessTokens[token]; a != nil && a.ClientID == client.ID {
		a.Revoked = true
	}
	if rf := p.refreshTokens[token]; rf != nil && rf.ClientID == client.ID {
		rf.Revoked = true
	}
	p.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (p *Provider) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form body")
		return
	}
	if _, authErr := p.authenticateClient(r); authErr != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="access-nex"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", authErr)
		return
	}
	token := r.Form.Get("token")
	now := time.Now()
	p.mu.Lock()
	access := p.accessTokens[token]
	refresh := p.refreshTokens[token]
	p.mu.Unlock()
	if access != nil && !access.Revoked && now.Before(access.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{
			"active": true, "scope": strings.Join(access.Scope, " "),
			"client_id": access.ClientID, "sub": access.Subject,
			"token_type": "Bearer", "exp": access.ExpiresAt.Unix(),
			"iat": now.Add(-time.Hour).Unix(), "iss": p.issuer, "jti": access.JTI,
		})
		return
	}
	if refresh != nil && !refresh.Revoked && now.Before(refresh.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{
			"active": true, "scope": strings.Join(refresh.Scope, " "),
			"client_id": refresh.ClientID, "sub": refresh.Subject,
			"token_type": "refresh_token", "exp": refresh.ExpiresAt.Unix(), "iss": p.issuer,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"active": false})
}

func (p *Provider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Missing bearer token")
		return
	}
	p.mu.Lock()
	record := p.accessTokens[token]
	var user *User
	if record != nil {
		for _, u := range p.users {
			if u.Subject == record.Subject {
				user = u
				break
			}
		}
	}
	p.mu.Unlock()
	if record == nil || record.Revoked || time.Now().After(record.ExpiresAt) || user == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
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

func (p *Provider) handleRegister(w http.ResponseWriter, r *http.Request) {
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
	client := &Client{
		ID:           "client-" + randomToken(16),
		Name:         req.ClientName,
		RedirectURIs: req.RedirectURIs,
		Public:       public,
	}
	if !public {
		client.Secret = randomToken(32)
	}
	p.mu.Lock()
	p.clients[client.ID] = client
	p.mu.Unlock()

	resp := map[string]any{
		"client_id":                  client.ID,
		"client_name":                client.Name,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_id_issued_at":        time.Now().Unix(),
	}
	if public {
		resp["token_endpoint_auth_method"] = "none"
	} else {
		resp["client_secret"] = client.Secret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (p *Provider) handleEndSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("oidc_sid"); err == nil {
		p.mu.Lock()
		delete(p.sessions, cookie.Value)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: "oidc_sid", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	if u := r.URL.Query().Get("post_logout_redirect_uri"); u != "" {
		http.Redirect(w, r, u, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

func (p *Provider) handleAccount(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	p.mu.Lock()
	record := p.accessTokens[token]
	var user *User
	if record != nil {
		for _, u := range p.users {
			if u.Subject == record.Subject {
				user = u
				break
			}
		}
	}
	p.mu.Unlock()
	if record == nil || record.Revoked || time.Now().After(record.ExpiresAt) || user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	html := `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Account</title>
  <style>body{font-family:sans-serif;background:#f5f5f5}.header{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:30px 20px}
  .container{max-width:600px;margin:40px auto;padding:20px}.card{background:#fff;border-radius:8px;padding:30px;box-shadow:0 2px 8px rgba(0,0,0,.1)}
  label{color:#667eea;font-weight:600;display:block;margin-bottom:4px}p{margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid #eee}</style>
  </head><body><div class="header"><h1>Your Account</h1></div>
  <div class="container"><div class="card">
  <label>Name</label><p>` + html2string(user.Name) + `</p>
  <label>Username</label><p>` + html2string(user.Username) + `</p>
  <label>Email</label><p>` + html2string(user.Email) + `</p>
  <label>Subject</label><p style="font-family:monospace;font-size:12px">` + html2string(user.Subject) + `</p>
  </div></div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (p *Provider) handleListApps(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	apps := make(map[string]*Client, len(p.clients))
	for k, v := range p.clients {
		apps[k] = v
	}
	p.mu.Unlock()

	rows := ""
	if len(apps) == 0 {
		rows = `<tr><td colspan="4" style="text-align:center;padding:40px;color:#999">No applications registered</td></tr>`
	} else {
		for _, a := range apps {
			t, tc := "Confidential", "confidential"
			if a.Public {
				t, tc = "Public", "public"
			}
			uris := ""
			for _, u := range a.RedirectURIs {
				uris += `<div style="font-size:13px;margin-bottom:4px">` + html2string(u) + `</div>`
			}
			rows += `<tr><td>` + html2string(a.Name) + `</td>
			<td><code style="font-size:12px">` + html2string(a.ID) + `</code></td>
			<td><span class="ct ` + tc + `">` + t + `</span></td>
			<td>` + uris + `</td></tr>`
		}
	}
	html := `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Apps</title>
  <style>body{font-family:sans-serif;background:#f5f5f5}.header{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:30px 20px}
  .container{max-width:900px;margin:40px auto;padding:20px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)}
  th{background:#f5f5f5;padding:15px;text-align:left;font-weight:600;color:#667eea;border-bottom:2px solid #eee}
  td{padding:15px;border-bottom:1px solid #eee}
  .ct{display:inline-block;padding:4px 12px;border-radius:4px;font-size:12px;font-weight:600}
  .confidential{background:#e3f2fd;color:#1976d2}.public{background:#f3e5f5;color:#7b1fa2}
  code{font-family:monospace}</style></head><body>
  <div class="header"><h1>Registered Applications</h1></div>
  <div class="container"><table><thead><tr>
  <th>Name</th><th>Client ID</th><th>Type</th><th>Redirect URIs</th>
  </tr></thead><tbody>` + rows + `</tbody></table></div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// ── OIDC server helpers ────────────────────────────────────────────────────────

func (p *Provider) validateAuthorizeRequest(req authRequest) (*Client, string, error) {
	p.mu.Lock()
	client := p.clients[req.ClientID]
	p.mu.Unlock()
	if client == nil {
		return nil, "", fmt.Errorf("unknown client_id")
	}
	redirectURI := req.RedirectURI
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	if !redirectAllowed(client, redirectURI) {
		return nil, "", fmt.Errorf("invalid redirect_uri")
	}
	if req.Scope == "" {
		req.Scope = "openid"
	}
	return client, redirectURI, nil
}

func (p *Provider) issueAuthorizationCode(w http.ResponseWriter, r *http.Request, req authRequest, subject string) {
	code := randomToken(32)
	scope := parseScope(req.Scope)
	if len(scope) == 0 {
		scope = []string{"openid"}
	}
	p.mu.Lock()
	p.authCodes[code] = &AuthCode{
		Code: code, ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		Subject: subject, Scope: scope, Nonce: req.Nonce,
		CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt: time.Now().Add(5 * time.Minute), AuthTime: time.Now(),
	}
	p.mu.Unlock()
	redirectURL, _ := url.Parse(req.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("iss", p.issuer)
	if req.State != "" {
		q.Set("state", req.State)
	}
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (p *Provider) issueTokenResponse(clientID, subject string, scope []string, nonce string, authTime time.Time, includeRefresh bool) (map[string]any, error) {
	access, err := p.issueAccessToken(clientID, subject, scope)
	if err != nil {
		return nil, err
	}
	resp := map[string]any{
		"access_token": access.Token, "token_type": "Bearer",
		"expires_in": int(time.Until(access.ExpiresAt).Seconds()),
		"scope":      strings.Join(scope, " "),
	}
	if hasScope(scope, "openid") {
		idToken, err := p.issueIDToken(clientID, subject, scope, nonce, authTime, access.Token)
		if err != nil {
			return nil, err
		}
		resp["id_token"] = idToken
	}
	if includeRefresh && hasScope(scope, "offline_access") {
		refreshToken := randomToken(48)
		expires := time.Now().Add(30 * 24 * time.Hour)
		p.mu.Lock()
		p.refreshTokens[refreshToken] = &RefreshRecord{
			Token: refreshToken, ClientID: clientID, Subject: subject,
			Scope: scope, ExpiresAt: expires,
		}
		p.mu.Unlock()
		resp["refresh_token"] = refreshToken
	}
	return resp, nil
}

func (p *Provider) issueAccessToken(clientID, subject string, scope []string) (*TokenRecord, error) {
	now := time.Now()
	expires := now.Add(time.Hour)
	jti := randomToken(24)
	claims := map[string]any{
		"iss": p.issuer, "sub": subject, "aud": clientID, "client_id": clientID,
		"scope": strings.Join(scope, " "), "exp": expires.Unix(), "iat": now.Unix(),
		"jti": jti, "token_use": "access",
	}
	token, err := p.signJWT(claims)
	if err != nil {
		return nil, err
	}
	record := &TokenRecord{Token: token, JTI: jti, ClientID: clientID, Subject: subject, Scope: scope, ExpiresAt: expires}
	p.mu.Lock()
	p.accessTokens[token] = record
	p.mu.Unlock()
	return record, nil
}

func (p *Provider) issueIDToken(clientID, subject string, scope []string, nonce string, authTime time.Time, accessToken string) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss": p.issuer, "sub": subject, "aud": clientID,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"auth_time": authTime.Unix(), "at_hash": accessTokenHash(accessToken),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if hasScope(scope, "profile") || hasScope(scope, "email") {
		if user := p.userBySubject(subject); user != nil {
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
	return p.signJWT(claims)
}

func (p *Provider) authenticateClient(r *http.Request) (*Client, string) {
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	if clientID == "" {
		return nil, "Missing client credentials"
	}
	p.mu.Lock()
	client := p.clients[clientID]
	p.mu.Unlock()
	if client == nil {
		return nil, "Unknown client_id"
	}
	if client.Public {
		if secret != "" {
			return nil, "Public clients must not send client_secret"
		}
		return client, ""
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(client.Secret)) != 1 {
		return nil, "Invalid client_secret"
	}
	return client, ""
}

func (p *Provider) authenticateUser(username, password string) (string, bool) {
	p.mu.Lock()
	user := p.users[username]
	p.mu.Unlock()
	if user == nil {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(user.Password)) != 1 {
		return "", false
	}
	return user.Subject, true
}

func (p *Provider) subjectFromSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("oidc_sid")
	if err != nil {
		return "", false
	}
	p.mu.Lock()
	session := p.sessions[cookie.Value]
	if session != nil && time.Now().After(session.ExpiresAt) {
		delete(p.sessions, cookie.Value)
		session = nil
	}
	p.mu.Unlock()
	if session == nil {
		return "", false
	}
	return session.Subject, true
}

func (p *Provider) userBySubject(subject string) *User {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, u := range p.users {
		if u.Subject == subject {
			return u
		}
	}
	return nil
}

func (p *Provider) signJWT(claims map[string]any) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": p.keyID}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(signature), nil
}

func (p *Provider) redirectWithOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, code, description, state string) {
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

func (p *Provider) renderLogin(w http.ResponseWriter, req authRequest, clientName, message string) {
	fields := map[string]string{
		"response_type": req.ResponseType, "client_id": req.ClientID,
		"redirect_uri": req.RedirectURI, "scope": req.Scope, "state": req.State,
		"nonce": req.Nonce, "code_challenge": req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod, "prompt": req.Prompt,
	}
	data := struct {
		Error      string
		ClientName string
		Fields     map[string]string
	}{Error: message, ClientName: clientName, Fields: fields}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginTemplate.Execute(w, data); err != nil {
		log.Printf("render login: %v", err)
	}
}

func (p *Provider) endpoint(path string) string { return p.issuer + path }

// ── Pure helpers ───────────────────────────────────────────────────────────────

func verifyPKCE(challenge, method, verifier string) bool {
	if verifier == "" {
		return false
	}
	if method == "" || method == "plain" {
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1
	}
	if method == "S256" {
		sum := sha256.Sum256([]byte(verifier))
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(b64(sum[:]))) == 1
	}
	return false
}

func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return b64(sum[:len(sum)/2])
}

func redirectAllowed(client *Client, redirectURI string) bool {
	for _, allowed := range client.RedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func parseScope(raw string) []string {
	seen := map[string]bool{}
	var scopes []string
	for _, s := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
		if s != "" && !seen[s] {
			scopes = append(scopes, s)
			seen[s] = true
		}
	}
	return scopes
}

func hasScope(scopes []string, needle string) bool {
	for _, s := range scopes {
		if s == needle {
			return true
		}
	}
	return false
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func randomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return b64(buf)
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func html2string(s string) string { return template.HTMLEscapeString(s) }

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func maskSecret(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:4] + "****"
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Encryption helpers (XOR + base64 — for local dev secrets) ─────────────────

func getEncryptionKey() []byte {
	h := sha256.Sum256([]byte(configPath))
	return h[:]
}

func encryptSecret(plaintext string) (string, error) {
	key := getEncryptionKey()
	data := []byte(plaintext)
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

func decryptSecret(encrypted string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	key := getEncryptionKey()
	out := make([]byte, len(decoded))
	for i := range decoded {
		out[i] = decoded[i] ^ key[i%len(key)]
	}
	return string(out), nil
}

// ── Persistence ────────────────────────────────────────────────────────────────

func loadUsers() (map[string]*User, error) {
	return loadJSON[map[string]*User](filepath.Join(configPath, usersFile))
}

func saveUsers(v map[string]*User) error {
	return saveJSON(filepath.Join(configPath, usersFile), v)
}

func loadApps() (map[string]*App, error) {
	apps, err := loadJSON[map[string]*App](filepath.Join(configPath, appsFile))
	if err == nil {
		return apps, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	// Migration: read old clients.json if apps.json doesn't exist yet.
	return migrateClientsToApps()
}

func migrateClientsToApps() (map[string]*App, error) {
	type oldClient struct {
		ID           string   `json:"client_id"`
		Secret       string   `json:"client_secret,omitempty"`
		Name         string   `json:"client_name,omitempty"`
		RedirectURIs []string `json:"redirect_uris"`
		Public       bool     `json:"public,omitempty"`
	}
	clients, err := loadJSON[map[string]*oldClient](filepath.Join(configPath, "clients.json"))
	if err != nil {
		return nil, os.ErrNotExist
	}
	apps := make(map[string]*App, len(clients))
	now := time.Now().Format(time.RFC3339)
	for id, c := range clients {
		apps[id] = &App{
			ID: c.ID, Name: c.Name, RedirectURIs: c.RedirectURIs,
			Public: c.Public, Secret: c.Secret,
			Scopes:  []string{"openid", "profile", "email"},
			Enabled: true, CreatedAt: now, UpdatedAt: now,
		}
	}
	return apps, nil
}

func saveApps(v map[string]*App) error {
	return saveJSON(filepath.Join(configPath, appsFile), v)
}

func loadProvider() (map[string]interface{}, error) {
	return loadJSON[map[string]interface{}](filepath.Join(configPath, providerFile))
}

func saveProvider(v map[string]interface{}) error {
	return saveJSON(filepath.Join(configPath, providerFile), v)
}

func loadExternalProviders() (map[string]*ExternalProvider, error) {
	providers, err := loadJSON[map[string]*ExternalProvider](filepath.Join(configPath, providersFile))
	if err == nil {
		return providers, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	// Migration: read old integrations.json.
	return migrateIntegrationsToProviders()
}

func migrateIntegrationsToProviders() (map[string]*ExternalProvider, error) {
	type oldIntegration struct {
		ID               string   `json:"id"`
		Name             string   `json:"name"`
		Type             string   `json:"type"`
		Provider         string   `json:"provider"`
		ClientID         string   `json:"client_id"`
		ClientSecret     string   `json:"client_secret_encrypted"`
		AuthorizationURL string   `json:"authorization_url"`
		AccessTokenURL   string   `json:"access_token_url"`
		ResourceURL      string   `json:"resource_url"`
		RedirectURL      string   `json:"redirect_url"`
		LogoutURL        string   `json:"logout_url"`
		UserIdentifier   string   `json:"user_identifier"`
		Scopes           []string `json:"scopes"`
		Enabled          bool     `json:"enabled"`
		CreatedAt        string   `json:"created_at"`
		UpdatedAt        string   `json:"updated_at"`
	}
	old, err := loadJSON[map[string]*oldIntegration](filepath.Join(configPath, "integrations.json"))
	if err != nil {
		return nil, os.ErrNotExist
	}
	providers := make(map[string]*ExternalProvider, len(old))
	for id, o := range old {
		providers[id] = &ExternalProvider{
			ID: o.ID, Name: o.Name, Template: o.Provider, Type: o.Type,
			ClientID: o.ClientID, ClientSecret: o.ClientSecret,
			AuthorizationURL: o.AuthorizationURL, AccessTokenURL: o.AccessTokenURL,
			ResourceURL: o.ResourceURL, RedirectURL: o.RedirectURL,
			LogoutURL: o.LogoutURL, UserIdentifier: o.UserIdentifier,
			Scopes: o.Scopes, Enabled: o.Enabled,
			CreatedAt: o.CreatedAt, UpdatedAt: o.UpdatedAt,
		}
	}
	return providers, nil
}

func saveExternalProviders(v map[string]*ExternalProvider) error {
	return saveJSON(filepath.Join(configPath, providersFile), v)
}

func loadJSON[T any](path string) (T, error) {
	var zero T
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return zero, err
	}
	return v, nil
}

func saveJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func shutdownServer() error {
	fmt.Println("\nTo stop the server:")
	fmt.Println("  Press Ctrl+C in the terminal running 'server'")
	fmt.Println("  Windows: tasklist | findstr access-nex  →  taskkill /PID <pid> /F")
	fmt.Println("  Linux/Mac: ps aux | grep access-nex  →  kill <pid>")
	fmt.Println()
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

// ── Login page template ────────────────────────────────────────────────────────

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Access-Nex Sign In</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center}
    .container{width:100%;max-width:420px;padding:20px}
    .card{background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.3);padding:40px}
    .logo{font-size:28px;font-weight:700;color:#667eea;text-align:center;margin-bottom:4px}
    .logo-sub{font-size:11px;color:#999;text-align:center;text-transform:uppercase;letter-spacing:1px;margin-bottom:24px}
    h1{font-size:22px;color:#333;margin:16px 0 8px;font-weight:600}
    .subtitle{color:#666;font-size:14px;margin-bottom:24px}
    .app-info{background:#f8f9ff;border-left:4px solid #667eea;padding:12px 15px;border-radius:4px;margin-bottom:24px;font-size:14px}
    .app-name{color:#667eea;font-weight:600}
    .fg{margin-bottom:16px}
    label{display:block;font-size:13px;font-weight:600;color:#333;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
    input{width:100%;padding:12px 14px;border:1px solid #ddd;border-radius:6px;font-size:15px;transition:all .3s}
    input:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.1)}
    button{width:100%;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:0;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;margin-top:20px}
    button:hover{opacity:.9}
    .error{background:#fee;border:1px solid #fcc;border-radius:6px;color:#c33;padding:12px 14px;margin-bottom:20px;font-size:14px}
    .footer{text-align:center;margin-top:20px;font-size:12px;color:#999}
    .footer a{color:#667eea;text-decoration:none}
  </style>
</head><body>
  <div class="container"><div class="card">
    <div class="logo">🔐 Access-Nex</div>
    <div class="logo-sub">OAuth2 &amp; OIDC Provider</div>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <h1>Welcome</h1>
    {{if .ClientName}}
    <div class="app-info"><strong>Signing in to:</strong><br><span class="app-name">{{.ClientName}}</span></div>
    <p class="subtitle">Sign in with your Access-Nex account to continue</p>
    {{else}}<p class="subtitle">Sign in to continue</p>{{end}}
    <form method="post" action="/authorize">
      {{range $k,$v := .Fields}}{{if $v}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}{{end}}
      <div class="fg"><label for="username">Username</label>
        <input type="text" id="username" name="username" placeholder="Enter username" autocomplete="username" required autofocus></div>
      <div class="fg"><label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="Enter password" autocomplete="current-password" required></div>
      <button type="submit">Sign In</button>
    </form>
    <div class="footer">Access-Nex | <a href="/">Home</a></div>
  </div></div>
</body></html>`))

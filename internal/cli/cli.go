// Package cli defines the access-nex command tree. Every command talks to
// the SQLite database through the store package.
package cli

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/database"
	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
	"github.com/omegadc/access-nex/internal/server"
	"github.com/omegadc/access-nex/internal/store"
)

const (
	defaultAddr      = ":8080"
	defaultIssuer    = "http://localhost:8080"
	defaultConfigDir = ".access-nex"
)

var (
	configDir string
	dbDSN     string
	db        *database.DB
	st        *store.Store
)

// Execute runs the root command; it is the only entry point used by main.
func Execute() error {
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	return rootCmd.Execute()
}

var rootCmd = &cobra.Command{
	Use:           "access-nex",
	Short:         "OIDC/OAuth2 provider and management CLI",
	SilenceUsage:  true,
	SilenceErrors: false,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// configDir always holds the AES box key and (legacy) signing key
		// files, regardless of which database backend is in use.
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
		var err error
		dsn := dbDSN
		if dsn == "" {
			dsn = configDir // default: SQLite file inside the config dir
		}
		db, err = database.Open(dsn)
		if err != nil {
			return err
		}
		st = store.New(db)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configDir, "config", defaultConfigDir,
		"config directory (holds the SQLite database, AES key, and legacy signing key files)")
	rootCmd.PersistentFlags().StringVar(&dbDSN, "db", "",
		"database DSN; postgres://user:pass@host/db to use PostgreSQL, otherwise SQLite in --config is used")

	rootCmd.AddCommand(userCmd, appCmd, providerCmd, serverCmd, shutdownCmd, migrateCmd, auditCmd)

	// user
	userCmd.AddCommand(userAddCmd, userListCmd, userDeleteCmd, userPromoteCmd, userDemoteCmd)
	userAddCmd.Flags().StringP("username", "u", "", "Username")
	userAddCmd.Flags().StringP("password", "p", "", "Password")
	userAddCmd.Flags().StringP("email", "e", "", "Email")
	userAddCmd.Flags().StringP("name", "n", "", "Full name")
	userAddCmd.Flags().Bool("admin", false, "Grant admin rights (access to /admin)")
	userDeleteCmd.Flags().StringP("username", "u", "", "Username to delete")
	userPromoteCmd.Flags().StringP("username", "u", "", "Username to promote")
	userDemoteCmd.Flags().StringP("username", "u", "", "Username to demote")

	// audit
	auditCmd.Flags().IntP("limit", "n", 50, "Number of entries to show")

	// app
	appCmd.AddCommand(appCreateCmd, appListCmd, appShowCmd, appUpdateCmd, appDeleteCmd)
	appCreateCmd.Flags().StringP("name", "n", "", "Application name")
	appCreateCmd.Flags().StringSliceP("redirect-uri", "r", nil, "Redirect URI (repeatable)")
	appCreateCmd.Flags().Bool("public", false, "Public client (PKCE, no secret)")
	appCreateCmd.Flags().StringP("provider", "p", "", "External provider ID (omit to use access-nex itself)")
	appCreateCmd.Flags().StringP("scopes", "s", "", "Comma-separated scopes")
	appShowCmd.Flags().StringP("id", "i", "", "Application ID")
	appUpdateCmd.Flags().StringP("id", "i", "", "Application ID")
	appUpdateCmd.Flags().StringP("name", "n", "", "Name")
	appUpdateCmd.Flags().StringSliceP("redirect-uri", "r", nil, "Redirect URIs")
	appUpdateCmd.Flags().StringP("provider", "p", "", "External provider ID")
	appUpdateCmd.Flags().StringP("scopes", "s", "", "Scopes")
	appUpdateCmd.Flags().String("id-token-enc-key", "", "Path to RSA public key PEM for ID-token encryption (JWE); 'none' to disable")
	appUpdateCmd.Flags().String("backchannel-logout-uri", "", "URI notified server-to-server when a user's session ends; 'none' to disable")
	appUpdateCmd.Flags().String("frontchannel-logout-uri", "", "URI loaded in a browser iframe when a user's session ends; 'none' to disable")
	appDeleteCmd.Flags().StringP("id", "i", "", "Application ID")

	// provider self
	providerSelfCmd.AddCommand(providerSelfInitCmd, providerSelfInfoCmd,
		providerSelfRotateKeyCmd, providerSelfListKeysCmd, providerSelfRetireKeyCmd)
	providerSelfInitCmd.Flags().StringP("issuer", "i", defaultIssuer, "Issuer URL")
	providerSelfRetireKeyCmd.Flags().StringP("kid", "k", "", "Key ID to retire")

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

	providerCmd.AddCommand(providerSelfCmd, providerAddCmd, providerListCmd,
		providerShowCmd, providerUpdateCmd, providerDeleteCmd)

	serverCmd.Flags().StringP("addr", "a", defaultAddr, "Listen address")
	serverCmd.Flags().String("tls-cert", "", "Path to a TLS certificate (PEM); requires --tls-key")
	serverCmd.Flags().String("tls-key", "", "Path to the TLS certificate's private key (PEM); requires --tls-cert")
	serverCmd.Flags().Bool("tls-self-signed", false, "Serve HTTPS with an in-memory self-signed certificate (dev/local use)")

	// group
	groupCmd.AddCommand(groupCreateCmd, groupListCmd, groupDeleteCmd, groupAddMemberCmd, groupRemoveMemberCmd)
	groupCreateCmd.Flags().StringP("name", "n", "", "Group name")
	groupCreateCmd.Flags().StringP("description", "d", "", "Description")
	groupDeleteCmd.Flags().StringP("name", "n", "", "Group name")
	groupAddMemberCmd.Flags().StringP("group", "g", "", "Group name")
	groupAddMemberCmd.Flags().StringP("username", "u", "", "Username to add")
	groupRemoveMemberCmd.Flags().StringP("group", "g", "", "Group name")
	groupRemoveMemberCmd.Flags().StringP("username", "u", "", "Username to remove")
	rootCmd.AddCommand(groupCmd)
}

// ── user commands ─────────────────────────────────────────────────────────────

var userCmd = &cobra.Command{Use: "user", Short: "Manage users"}

var userAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new user",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		email, _ := cmd.Flags().GetString("email")
		name, _ := cmd.Flags().GetString("name")
		if username == "" {
			return fmt.Errorf("username is required")
		}
		if password == "" {
			return fmt.Errorf("password is required")
		}
		admin, _ := cmd.Flags().GetBool("admin")
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u := &models.User{
			Subject:      fmt.Sprintf("user-%s-%d", username, time.Now().UnixNano()),
			Username:     username,
			PasswordHash: string(hash),
			Email:        email,
			Name:         name,
			IsAdmin:      admin,
		}
		if err := st.CreateUser(u); err != nil {
			return err
		}
		role := ""
		if admin {
			role = " [admin]"
		}
		fmt.Printf("✓ User '%s' created (subject: %s)%s\n", username, u.Subject, role)
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	RunE: func(cmd *cobra.Command, args []string) error {
		users, err := st.ListUsers()
		if err != nil {
			return err
		}
		if len(users) == 0 {
			fmt.Println("No users found")
			return nil
		}
		fmt.Printf("\n%-20s %-40s %-25s %-20s %s\n", "Username", "Subject", "Email", "Name", "Source")
		fmt.Println(strings.Repeat("-", 120))
		for _, u := range users {
			source := "local"
			if u.ProviderID != "" {
				source = u.ProviderID
			}
			fmt.Printf("%-20s %-40s %-25s %-20s %s\n", u.Username, u.Subject, u.Email, u.Name, source)
		}
		fmt.Println()
		return nil
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a user",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		if username == "" {
			return fmt.Errorf("username is required")
		}
		if err := st.DeleteUserByUsername(username); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("user %s not found", username)
			}
			return err
		}
		fmt.Printf("✓ User '%s' deleted\n", username)
		return nil
	},
}

// ── app commands ──────────────────────────────────────────────────────────────

var appCmd = &cobra.Command{Use: "app", Short: "Manage applications (OAuth2/OIDC clients)"}

var appCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an application",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		uris, _ := cmd.Flags().GetStringSlice("redirect-uri")
		public, _ := cmd.Flags().GetBool("public")
		providerID, _ := cmd.Flags().GetString("provider")
		scopesStr, _ := cmd.Flags().GetString("scopes")
		if name == "" {
			return fmt.Errorf("name is required")
		}
		if len(uris) == 0 {
			return fmt.Errorf("at least one --redirect-uri is required")
		}
		if providerID != "" {
			if _, err := st.GetProvider(providerID); err != nil {
				return fmt.Errorf("provider %s not found", providerID)
			}
		}

		scopes := parseScopes(scopesStr)
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		app := &models.App{
			ID: fmt.Sprintf("client-%s-%d",
				strings.ToLower(strings.ReplaceAll(name, " ", "-")), time.Now().UnixNano()),
			Name:         name,
			Public:       public,
			ProviderID:   providerID,
			RedirectURIs: uris,
			Scopes:       scopes,
			Enabled:      true,
		}
		if !public {
			app.Secret = secrets.RandomToken(32)
		}
		if err := st.CreateApp(app); err != nil {
			return err
		}

		providerLabel := providerID
		if providerLabel == "" {
			providerLabel = "self (access-nex)"
		}
		fmt.Printf("\n✓ Application '%s' created\n", name)
		fmt.Printf("  Client ID:     %s\n", app.ID)
		if public {
			fmt.Printf("  Type:          Public (PKCE)\n")
		} else {
			fmt.Printf("  Client Secret: %s\n", app.Secret)
		}
		fmt.Printf("  Provider:      %s\n", providerLabel)
		fmt.Printf("  Scopes:        %s\n", strings.Join(scopes, ", "))
		fmt.Printf("  Redirect URIs:\n")
		for _, u := range uris {
			fmt.Printf("    - %s\n", u)
		}
		fmt.Println()
		return nil
	},
}

var appListCmd = &cobra.Command{
	Use:   "list",
	Short: "List applications",
	RunE: func(cmd *cobra.Command, args []string) error {
		apps, err := st.ListApps()
		if err != nil {
			return err
		}
		if len(apps) == 0 {
			fmt.Println("No applications found")
			return nil
		}
		fmt.Printf("\n%-42s %-22s %-14s %-20s\n", "Client ID", "Name", "Type", "Provider")
		fmt.Println(strings.Repeat("-", 100))
		for _, a := range apps {
			t := "Confidential"
			if a.Public {
				t = "Public"
			}
			provider := a.ProviderID
			if provider == "" {
				provider = "self"
			}
			fmt.Printf("%-42s %-22s %-14s %-20s\n", a.ID, a.Name, t, provider)
		}
		fmt.Println()
		return nil
	},
}

var appShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show application details",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("id is required")
		}
		a, err := st.GetApp(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("app %s not found", id)
			}
			return err
		}
		t := "Confidential"
		if a.Public {
			t = "Public (PKCE)"
		}
		provider := a.ProviderID
		if provider == "" {
			provider = "self (access-nex)"
		}
		fmt.Printf("\nApplication: %s\n", a.Name)
		fmt.Println(strings.Repeat("-", 60))
		fmt.Printf("  ID:            %s\n", a.ID)
		fmt.Printf("  Type:          %s\n", t)
		fmt.Printf("  Provider:      %s\n", provider)
		fmt.Printf("  Scopes:        %s\n", strings.Join(a.Scopes, ", "))
		fmt.Printf("  Enabled:       %v\n", a.Enabled)
		if !a.Public {
			fmt.Printf("  Secret:        %s\n", maskSecret(a.Secret))
		}
		fmt.Printf("  Redirect URIs:\n")
		for _, u := range a.RedirectURIs {
			fmt.Printf("    - %s\n", u)
		}
		fmt.Printf("  Created:       %s\n", a.CreatedAt.Format(time.RFC3339))
		fmt.Printf("  Updated:       %s\n\n", a.UpdatedAt.Format(time.RFC3339))
		return nil
	},
}

var appUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an application",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("id is required")
		}
		a, err := st.GetApp(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("app %s not found", id)
			}
			return err
		}
		if name, _ := cmd.Flags().GetString("name"); name != "" {
			a.Name = name
		}
		if uris, _ := cmd.Flags().GetStringSlice("redirect-uri"); len(uris) > 0 {
			a.RedirectURIs = uris
		}
		if providerID, _ := cmd.Flags().GetString("provider"); providerID != "" {
			if _, err := st.GetProvider(providerID); err != nil {
				return fmt.Errorf("provider %s not found", providerID)
			}
			a.ProviderID = providerID
		}
		if scopesStr, _ := cmd.Flags().GetString("scopes"); scopesStr != "" {
			a.Scopes = parseScopes(scopesStr)
		}
		if keyPath, _ := cmd.Flags().GetString("id-token-enc-key"); keyPath != "" {
			if keyPath == "none" {
				a.IDTokenEncKey = ""
			} else {
				pemBytes, err := os.ReadFile(keyPath)
				if err != nil {
					return fmt.Errorf("read encryption key: %w", err)
				}
				if _, err := secrets.ParsePublicKeyPEM(string(pemBytes)); err != nil {
					return fmt.Errorf("invalid RSA public key PEM: %w", err)
				}
				a.IDTokenEncKey = string(pemBytes)
			}
		}
		if v, _ := cmd.Flags().GetString("backchannel-logout-uri"); v != "" {
			if v == "none" {
				v = ""
			}
			a.BackchannelLogoutURI = v
		}
		if v, _ := cmd.Flags().GetString("frontchannel-logout-uri"); v != "" {
			if v == "none" {
				v = ""
			}
			a.FrontchannelLogoutURI = v
		}
		if err := st.UpdateApp(a); err != nil {
			return err
		}
		fmt.Printf("✓ Application '%s' updated\n", a.Name)
		return nil
	},
}

var appDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete an application",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("id is required")
		}
		if err := st.DeleteApp(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("app %s not found", id)
			}
			return err
		}
		fmt.Printf("✓ Application '%s' deleted\n", id)
		return nil
	},
}

// ── provider commands ─────────────────────────────────────────────────────────
// provider self init/info               → the local OIDC provider row
// provider add/list/show/update/delete  → external OAuth/OIDC providers

var providerCmd = &cobra.Command{Use: "provider", Short: "Manage OIDC/OAuth2 providers (self + external)"}
var providerSelfCmd = &cobra.Command{Use: "self", Short: "Manage the local (self-hosted) OIDC provider"}

var providerSelfInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the local OIDC provider",
	RunE: func(cmd *cobra.Command, args []string) error {
		issuer, _ := cmd.Flags().GetString("issuer")
		issuer = strings.TrimRight(issuer, "/")
		if issuer == "" {
			issuer = defaultIssuer
		}
		if err := st.UpsertInternalProvider(issuer); err != nil {
			return err
		}
		fmt.Printf("\n✓ Local OIDC Provider initialized\n")
		fmt.Printf("  Issuer:      %s\n", issuer)
		fmt.Printf("  Discovery:   %s/.well-known/openid-configuration\n", issuer)
		fmt.Printf("  OAuth proxy: %s/oauth/start\n\n", issuer)
		return nil
	},
}

var providerSelfInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show local provider info",
	RunE: func(cmd *cobra.Command, args []string) error {
		internal, err := st.GetInternalProvider()
		if errors.Is(err, store.ErrNotFound) {
			fmt.Println("Provider not initialized. Run 'provider self init' first.")
			return nil
		}
		if err != nil {
			return err
		}
		users, apps, ext, err := st.Counts()
		if err != nil {
			return err
		}
		fmt.Printf("\nLocal Provider:\n")
		fmt.Printf("  Issuer:           %s\n", internal.Issuer)
		fmt.Printf("  Users:            %d\n", users)
		fmt.Printf("  Applications:     %d\n", apps)
		fmt.Printf("  Ext. Providers:   %d\n", ext)
		fmt.Println()
		return nil
	},
}

var providerAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add an external OAuth/OIDC provider",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		templateName, _ := cmd.Flags().GetString("type")
		clientID, _ := cmd.Flags().GetString("client-id")
		clientSecret, _ := cmd.Flags().GetString("client-secret")
		if name == "" {
			return fmt.Errorf("name is required")
		}
		if clientID == "" {
			return fmt.Errorf("client-id is required")
		}
		if clientSecret == "" {
			return fmt.Errorf("client-secret is required")
		}

		p := &models.Provider{
			ID: fmt.Sprintf("provider-%s-%d",
				strings.ToLower(strings.ReplaceAll(name, " ", "-")), time.Now().UnixNano()),
			Name:           name,
			Kind:           models.ProviderKindOAuth2,
			Template:       templateName,
			ClientID:       clientID,
			UserIdentifier: "id",
			Scopes:         []string{"openid", "profile", "email"},
			Enabled:        true,
		}
		if tmpl := models.ProviderTemplates[templateName]; tmpl != nil {
			p.Kind = tmpl.Kind
			p.AuthorizationURL = tmpl.AuthorizationURL
			p.AccessTokenURL = tmpl.AccessTokenURL
			p.ResourceURL = tmpl.ResourceURL
			p.LogoutURL = tmpl.LogoutURL
			p.UserIdentifier = tmpl.UserIdentifier
			p.Scopes = tmpl.Scopes
		}
		applyProviderFlags(cmd, p)

		box, err := secrets.NewBox(configDir)
		if err != nil {
			return err
		}
		if p.ClientSecretEnc, err = box.Encrypt(clientSecret); err != nil {
			return fmt.Errorf("failed to encrypt secret: %w", err)
		}
		if err := st.CreateProvider(p); err != nil {
			return err
		}

		fmt.Printf("\n✓ Provider '%s' added\n", name)
		fmt.Printf("  ID:         %s\n", p.ID)
		fmt.Printf("  Template:   %s\n", templateName)
		fmt.Printf("  Type:       %s\n", p.Kind)
		fmt.Printf("  Client ID:  %s\n", clientID)
		if p.AuthorizationURL != "" {
			fmt.Printf("  Auth URL:   %s\n", p.AuthorizationURL)
		}
		fmt.Printf("  Scopes:     %s\n\n", strings.Join(p.Scopes, ", "))
		return nil
	},
}

var providerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List providers (self + external)",
	RunE: func(cmd *cobra.Command, args []string) error {
		selfIssuer := "(not initialized — run: provider self init)"
		if internal, err := st.GetInternalProvider(); err == nil {
			selfIssuer = internal.Issuer
		}
		fmt.Printf("\n%-42s %-22s %-8s %s\n", "ID", "Name", "Type", "Auth URL / Issuer")
		fmt.Println(strings.Repeat("-", 120))
		fmt.Printf("%-42s %-22s %-8s %s\n", "self", "Local (access-nex)", "oidc", selfIssuer)

		providers, err := st.ListExternalProviders(false)
		if err != nil {
			return err
		}
		for _, p := range providers {
			status := ""
			if !p.Enabled {
				status = " [disabled]"
			}
			fmt.Printf("%-42s %-22s %-8s %s%s\n", p.ID, p.Name, p.Kind, trunc(p.AuthorizationURL, 55), status)
		}
		fmt.Println()
		return nil
	},
}

var providerShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show external provider details",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("id is required")
		}
		p, err := st.GetProvider(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("provider %s not found", id)
			}
			return err
		}
		secret := "[unable to decrypt]"
		if box, err := secrets.NewBox(configDir); err == nil {
			if plain, err := box.Decrypt(p.ClientSecretEnc); err == nil {
				secret = plain
			}
		}
		fmt.Printf("\nProvider: %s\n", p.Name)
		fmt.Println(strings.Repeat("-", 60))
		fmt.Printf("  ID:                %s\n", p.ID)
		fmt.Printf("  Template:          %s\n", p.Template)
		fmt.Printf("  Type:              %s\n", p.Kind)
		fmt.Printf("  Client ID:         %s\n", p.ClientID)
		fmt.Printf("  Client Secret:     %s\n", maskSecret(secret))
		fmt.Printf("  Redirect URL:      %s\n", p.RedirectURL)
		fmt.Printf("  Authorization URL: %s\n", p.AuthorizationURL)
		fmt.Printf("  Access Token URL:  %s\n", p.AccessTokenURL)
		fmt.Printf("  Resource URL:      %s\n", p.ResourceURL)
		fmt.Printf("  Logout URL:        %s\n", p.LogoutURL)
		fmt.Printf("  User Identifier:   %s\n", p.UserIdentifier)
		fmt.Printf("  Scopes:            %s\n", strings.Join(p.Scopes, ", "))
		fmt.Printf("  Enabled:           %v\n", p.Enabled)
		fmt.Printf("  Created:           %s\n", p.CreatedAt.Format(time.RFC3339))
		fmt.Printf("  Updated:           %s\n\n", p.UpdatedAt.Format(time.RFC3339))
		return nil
	},
}

var providerUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an external provider",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("id is required")
		}
		p, err := st.GetProvider(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("provider %s not found", id)
			}
			return err
		}
		if name, _ := cmd.Flags().GetString("name"); name != "" {
			p.Name = name
		}
		if clientID, _ := cmd.Flags().GetString("client-id"); clientID != "" {
			p.ClientID = clientID
		}
		if clientSecret, _ := cmd.Flags().GetString("client-secret"); clientSecret != "" {
			box, err := secrets.NewBox(configDir)
			if err != nil {
				return err
			}
			if p.ClientSecretEnc, err = box.Encrypt(clientSecret); err != nil {
				return err
			}
		}
		applyProviderFlags(cmd, p)
		if err := st.UpdateProvider(p); err != nil {
			return err
		}
		fmt.Printf("✓ Provider '%s' updated\n", p.Name)
		return nil
	},
}

var providerDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete an external provider",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("id is required")
		}
		if err := st.DeleteProvider(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("provider %s not found", id)
			}
			return err
		}
		fmt.Printf("✓ Provider '%s' deleted\n", id)
		return nil
	},
}

// applyProviderFlags copies any endpoint/scope flags the user set onto p.
func applyProviderFlags(cmd *cobra.Command, p *models.Provider) {
	if v, _ := cmd.Flags().GetString("redirect-url"); v != "" {
		p.RedirectURL = v
	}
	if v, _ := cmd.Flags().GetString("authorization-url"); v != "" {
		p.AuthorizationURL = v
	}
	if v, _ := cmd.Flags().GetString("access-token-url"); v != "" {
		p.AccessTokenURL = v
	}
	if v, _ := cmd.Flags().GetString("resource-url"); v != "" {
		p.ResourceURL = v
	}
	if v, _ := cmd.Flags().GetString("logout-url"); v != "" {
		p.LogoutURL = v
	}
	if v, _ := cmd.Flags().GetString("user-identifier"); v != "" {
		p.UserIdentifier = v
	}
	if v, _ := cmd.Flags().GetString("scopes"); v != "" {
		p.Scopes = parseScopes(v)
	}
}

// ── server command ────────────────────────────────────────────────────────────

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the OIDC/OAuth2 server",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		tlsCert, _ := cmd.Flags().GetString("tls-cert")
		tlsKey, _ := cmd.Flags().GetString("tls-key")
		tlsSelfSigned, _ := cmd.Flags().GetBool("tls-self-signed")
		if (tlsCert == "") != (tlsKey == "") {
			return fmt.Errorf("--tls-cert and --tls-key must be given together")
		}
		useTLS := tlsCert != "" || tlsSelfSigned

		internal, err := st.GetInternalProvider()
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("provider not initialized — run 'provider self init' first")
		}
		if err != nil {
			return err
		}
		issuer := internal.Issuer
		if issuer == "" {
			issuer = defaultIssuer
		}
		if useTLS && !strings.HasPrefix(issuer, "https://") {
			fmt.Printf("! Warning: serving HTTPS but issuer is %q — run 'provider self init --issuer https://...' so cookies and issued URLs match.\n", issuer)
		}

		box, err := secrets.NewBox(configDir)
		if err != nil {
			return err
		}
		keys, err := loadSigningKeys(box)
		if err != nil {
			return err
		}

		users, apps, ext, err := st.Counts()
		if err != nil {
			return err
		}

		srv := server.New(issuer, keys, st, box)

		// Purge expired codes, tokens, and sessions in the background.
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				if err := st.CleanupExpired(); err != nil {
					fmt.Printf("cleanup: %v\n", err)
				}
			}
		}()

		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		fmt.Printf("\n✓ OIDC/OAuth2 provider starting on %s://%s\n", scheme, addr)
		fmt.Printf("  Issuer:          %s\n", issuer)
		fmt.Printf("  Users:           %d\n", users)
		fmt.Printf("  Applications:    %d\n", apps)
		fmt.Printf("  Ext. Providers:  %d\n", ext)
		fmt.Printf("  OAuth Proxy:     %s/oauth/start\n", issuer)
		fmt.Printf("  Discovery:       %s/.well-known/openid-configuration\n\n", issuer)

		if !useTLS {
			return http.ListenAndServe(addr, srv.Handler())
		}
		httpSrv := &http.Server{Addr: addr, Handler: srv.Handler()}
		if tlsSelfSigned {
			cert, err := secrets.GenerateSelfSignedCert([]string{"localhost", "127.0.0.1", "::1"})
			if err != nil {
				return fmt.Errorf("generate self-signed cert: %w", err)
			}
			fmt.Println("  TLS:             self-signed (browsers will warn; fine for local/dev use)")
			httpSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			return httpSrv.ListenAndServeTLS("", "")
		}
		fmt.Printf("  TLS:             %s\n", tlsCert)
		return httpSrv.ListenAndServeTLS(tlsCert, tlsKey)
	},
}

var shutdownCmd = &cobra.Command{
	Use:   "shutdown",
	Short: "Print instructions to stop the running server",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("\nTo stop the server:")
		fmt.Println("  Press Ctrl+C in the terminal running 'server'")
		fmt.Println("  Windows: tasklist | findstr access-nex  →  taskkill /PID <pid> /F")
		fmt.Println("  Linux/Mac: ps aux | grep access-nex  →  kill <pid>")
		fmt.Println()
		return nil
	},
}

// ── small helpers ─────────────────────────────────────────────────────────────

func parseScopes(raw string) []string {
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

func maskSecret(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:4] + "****"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

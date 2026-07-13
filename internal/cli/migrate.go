package cli

// The migrate command imports data from the legacy JSON files
// (users.json, apps.json, providers.json, provider.json) into the SQLite
// database. It is idempotent: rows that already exist are skipped.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
	"github.com/omegadc/access-nex/internal/store"
)

// Legacy JSON shapes (as written by the pre-SQL version of access-nex).

type legacyUser struct {
	Subject  string `json:"sub"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

type legacyApp struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Public       bool     `json:"public"`
	Secret       string   `json:"secret"`
	ProviderID   string   `json:"provider_id"`
	Scopes       []string `json:"scopes"`
	Enabled      bool     `json:"enabled"`
}

type legacyProvider struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Template         string   `json:"template"`
	Type             string   `json:"type"`
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret_encrypted"`
	AuthorizationURL string   `json:"authorization_url"`
	AccessTokenURL   string   `json:"access_token_url"`
	ResourceURL      string   `json:"resource_url"`
	LogoutURL        string   `json:"logout_url"`
	UserIdentifier   string   `json:"user_identifier"`
	Scopes           []string `json:"scopes"`
	RedirectURL      string   `json:"redirect_url"`
	Enabled          bool     `json:"enabled"`
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Import legacy JSON data (users/apps/providers) into the SQL database",
	RunE: func(cmd *cobra.Command, args []string) error {
		migrated := 0

		// provider.json → internal provider row (only if not initialized yet)
		var providerMeta map[string]any
		if loadLegacyJSON(filepath.Join(configDir, "provider.json"), &providerMeta) == nil {
			if _, err := st.GetInternalProvider(); errors.Is(err, store.ErrNotFound) {
				if issuer, _ := providerMeta["issuer"].(string); issuer != "" {
					if err := st.UpsertInternalProvider(issuer); err != nil {
						return err
					}
					fmt.Printf("✓ Internal provider initialized (issuer: %s)\n", issuer)
					migrated++
				}
			}
		}

		// providers.json → providers table (re-encrypt XOR secrets with AES)
		var legacyProviders map[string]*legacyProvider
		if loadLegacyJSON(filepath.Join(configDir, "providers.json"), &legacyProviders) == nil {
			box, err := secrets.NewBox(configDir)
			if err != nil {
				return err
			}
			for id, lp := range legacyProviders {
				if _, err := st.GetProvider(id); err == nil {
					fmt.Printf("- Provider %s already exists, skipped\n", id)
					continue
				}
				kind := lp.Type
				if kind != models.ProviderKindOIDC && kind != models.ProviderKindOAuth2 {
					kind = models.ProviderKindOAuth2
				}
				secretEnc := ""
				if plain, err := decryptLegacySecret(lp.ClientSecret); err == nil {
					if secretEnc, err = box.Encrypt(plain); err != nil {
						return err
					}
				} else {
					fmt.Printf("! Provider %s: could not decrypt legacy secret, imported without one\n", id)
				}
				p := &models.Provider{
					ID: id, Name: lp.Name, Kind: kind, Template: lp.Template,
					ClientID: lp.ClientID, ClientSecretEnc: secretEnc,
					AuthorizationURL: lp.AuthorizationURL, AccessTokenURL: lp.AccessTokenURL,
					ResourceURL: lp.ResourceURL, LogoutURL: lp.LogoutURL,
					UserIdentifier: lp.UserIdentifier, Scopes: lp.Scopes,
					RedirectURL: lp.RedirectURL, Enabled: lp.Enabled,
				}
				if err := st.CreateProvider(p); err != nil {
					return fmt.Errorf("provider %s: %w", id, err)
				}
				fmt.Printf("✓ Provider '%s' imported\n", lp.Name)
				migrated++
			}
		}

		// users.json → users table (plaintext passwords become bcrypt hashes)
		var legacyUsers map[string]*legacyUser
		if loadLegacyJSON(filepath.Join(configDir, "users.json"), &legacyUsers) == nil {
			for username, lu := range legacyUsers {
				if _, err := st.GetUserByUsername(username); err == nil {
					fmt.Printf("- User %s already exists, skipped\n", username)
					continue
				}
				hash := ""
				if lu.Password != "" {
					h, err := bcrypt.GenerateFromPassword([]byte(lu.Password), bcrypt.DefaultCost)
					if err != nil {
						return err
					}
					hash = string(h)
				}
				u := &models.User{
					Subject: lu.Subject, Username: username,
					PasswordHash: hash, Email: lu.Email, Name: lu.Name,
				}
				if err := st.CreateUser(u); err != nil {
					return fmt.Errorf("user %s: %w", username, err)
				}
				fmt.Printf("✓ User '%s' imported\n", username)
				migrated++
			}
		}

		// apps.json → applications table
		var legacyApps map[string]*legacyApp
		if loadLegacyJSON(filepath.Join(configDir, "apps.json"), &legacyApps) == nil {
			for id, la := range legacyApps {
				if _, err := st.GetApp(id); err == nil {
					fmt.Printf("- App %s already exists, skipped\n", id)
					continue
				}
				providerID := la.ProviderID
				if providerID != "" {
					if _, err := st.GetProvider(providerID); err != nil {
						fmt.Printf("! App %s: provider %s not found, imported without provider link\n", id, providerID)
						providerID = ""
					}
				}
				a := &models.App{
					ID: id, Name: la.Name, Secret: la.Secret, Public: la.Public,
					ProviderID: providerID, RedirectURIs: la.RedirectURIs,
					Scopes: la.Scopes, Enabled: la.Enabled,
				}
				if err := st.CreateApp(a); err != nil {
					return fmt.Errorf("app %s: %w", id, err)
				}
				fmt.Printf("✓ Application '%s' imported\n", la.Name)
				migrated++
			}
		}

		if migrated == 0 {
			fmt.Println("Nothing to migrate — no legacy JSON files found or all rows already exist.")
		} else {
			fmt.Printf("\n✓ Migration complete: %d record(s) imported.\n", migrated)
			fmt.Println("  The JSON files were left in place; delete them once you have verified the data.")
		}
		return nil
	},
}

func loadLegacyJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// decryptLegacySecret reverses the old XOR-with-sha256(configDir) scheme used
// by the JSON-file version to obfuscate provider client secrets.
func decryptLegacySecret(encrypted string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(configDir))
	out := make([]byte, len(decoded))
	for i := range decoded {
		out[i] = decoded[i] ^ key[i%len(key)]
	}
	return string(out), nil
}

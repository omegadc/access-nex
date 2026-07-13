package cli

// Signing key management: keys live in the signing_keys table (PEM encrypted
// with the AES box). Exactly one is active; the others stay in JWKS so older
// tokens keep verifying. `rotate-key` switches signing to a fresh key.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/omegadc/access-nex/internal/secrets"
	"github.com/omegadc/access-nex/internal/server"
	"github.com/omegadc/access-nex/internal/store"
)

// loadSigningKeys returns all non-retired keys, active first. On first run it
// imports the legacy signing.pem (keeping its original kid so outstanding
// tokens still match JWKS) or generates a fresh key.
func loadSigningKeys(box *secrets.Box) ([]server.SigningKey, error) {
	rows, err := st.ListSigningKeys(false)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		key, err := secrets.LoadOrCreateSigningKey(configDir) // legacy signing.pem or new
		if err != nil {
			return nil, err
		}
		pemEnc, err := box.Encrypt(secrets.EncodePrivateKeyPEM(key))
		if err != nil {
			return nil, err
		}
		if err := st.InsertSigningKey("access-nex-key-1", pemEnc, true); err != nil {
			return nil, err
		}
		return []server.SigningKey{{Kid: "access-nex-key-1", Key: key}}, nil
	}

	keys := make([]server.SigningKey, 0, len(rows))
	for _, row := range rows {
		pemStr, err := box.Decrypt(row.PEMEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt key %s: %w", row.Kid, err)
		}
		key, err := secrets.ParsePrivateKeyPEM(pemStr)
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", row.Kid, err)
		}
		keys = append(keys, server.SigningKey{Kid: row.Kid, Key: key})
	}
	if len(keys) == 0 || !rows[0].Active {
		return nil, errors.New("no active signing key — run 'provider self rotate-key'")
	}
	return keys, nil
}

var providerSelfRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Generate a new signing key and make it active (old keys stay in JWKS)",
	RunE: func(cmd *cobra.Command, args []string) error {
		box, err := secrets.NewBox(configDir)
		if err != nil {
			return err
		}
		// Ensure the current key is imported before rotating past it.
		if _, err := loadSigningKeys(box); err != nil {
			return err
		}
		key, err := secrets.GenerateRSAKey()
		if err != nil {
			return err
		}
		pemEnc, err := box.Encrypt(secrets.EncodePrivateKeyPEM(key))
		if err != nil {
			return err
		}
		kid := fmt.Sprintf("key-%d", time.Now().Unix())
		if err := st.InsertSigningKey(kid, pemEnc, true); err != nil {
			return err
		}
		st.Audit("key_rotated", "", "", "", "new active kid "+kid)
		fmt.Printf("✓ New signing key '%s' is now active.\n", kid)
		fmt.Println("  Previous keys remain published in JWKS so outstanding tokens keep verifying.")
		fmt.Println("  Restart the server to pick up the new key.")
		return nil
	},
}

var providerSelfListKeysCmd = &cobra.Command{
	Use:   "list-keys",
	Short: "List signing keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		rows, err := st.ListSigningKeys(true)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No signing keys yet — one is created on first server start.")
			return nil
		}
		fmt.Printf("\n%-22s %-8s %-22s %s\n", "Kid", "Active", "Created", "Retired")
		fmt.Println(strings.Repeat("-", 75))
		for _, k := range rows {
			retired := ""
			if !k.RetiredAt.IsZero() {
				retired = k.RetiredAt.Format(time.RFC3339)
			}
			active := ""
			if k.Active {
				active = "✓"
			}
			fmt.Printf("%-22s %-8s %-22s %s\n", k.Kid, active, k.CreatedAt.Format(time.RFC3339), retired)
		}
		fmt.Println()
		return nil
	},
}

var providerSelfRetireKeyCmd = &cobra.Command{
	Use:   "retire-key",
	Short: "Remove an old (non-active) key from JWKS once its tokens have expired",
	RunE: func(cmd *cobra.Command, args []string) error {
		kid, _ := cmd.Flags().GetString("kid")
		if kid == "" {
			return fmt.Errorf("kid is required")
		}
		if err := st.RetireSigningKey(kid); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("key %s not found, already retired, or still active", kid)
			}
			return err
		}
		st.Audit("key_retired", "", "", "", kid)
		fmt.Printf("✓ Key '%s' retired — it is no longer published in JWKS.\n", kid)
		return nil
	},
}

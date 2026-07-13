package store

import (
	"database/sql"
	"errors"

	"github.com/omegadc/access-nex/internal/models"
)

const providerCols = `id, name, kind, template, issuer, client_id, client_secret_enc,
	authorization_url, access_token_url, resource_url, logout_url,
	user_identifier, scopes, redirect_url, enabled, created_at, updated_at`

func scanProvider(row interface{ Scan(...any) error }) (*models.Provider, error) {
	var p models.Provider
	var scopes, created, updated string
	err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.Template, &p.Issuer,
		&p.ClientID, &p.ClientSecretEnc, &p.AuthorizationURL, &p.AccessTokenURL,
		&p.ResourceURL, &p.LogoutURL, &p.UserIdentifier, &scopes,
		&p.RedirectURL, &p.Enabled, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.Scopes = splitScopes(scopes)
	p.CreatedAt = parseTime(created)
	p.UpdatedAt = parseTime(updated)
	return &p, nil
}

func (s *Store) CreateProvider(p *models.Provider) error {
	ts := now()
	p.CreatedAt = parseTime(ts)
	p.UpdatedAt = p.CreatedAt
	_, err := s.db.Exec(`
		INSERT INTO providers (id, name, kind, template, issuer, client_id, client_secret_enc,
			authorization_url, access_token_url, resource_url, logout_url,
			user_identifier, scopes, redirect_url, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.Kind, p.Template, p.Issuer, p.ClientID, p.ClientSecretEnc,
		p.AuthorizationURL, p.AccessTokenURL, p.ResourceURL, p.LogoutURL,
		p.UserIdentifier, joinScopes(p.Scopes), p.RedirectURL, p.Enabled, ts, ts)
	return err
}

func (s *Store) GetProvider(id string) (*models.Provider, error) {
	return scanProvider(s.db.QueryRow(`SELECT `+providerCols+` FROM providers WHERE id = ?`, id))
}

// ListExternalProviders returns all non-internal providers. If enabledOnly is
// true, disabled providers are filtered out (used by the running server).
func (s *Store) ListExternalProviders(enabledOnly bool) ([]*models.Provider, error) {
	q := `SELECT ` + providerCols + ` FROM providers WHERE kind != 'internal'`
	if enabledOnly {
		q += ` AND enabled = 1`
	}
	rows, err := s.db.Query(q + ` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var providers []*models.Provider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

func (s *Store) UpdateProvider(p *models.Provider) error {
	res, err := s.db.Exec(`
		UPDATE providers
		SET name = ?, kind = ?, template = ?, issuer = ?, client_id = ?, client_secret_enc = ?,
			authorization_url = ?, access_token_url = ?, resource_url = ?, logout_url = ?,
			user_identifier = ?, scopes = ?, redirect_url = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		p.Name, p.Kind, p.Template, p.Issuer, p.ClientID, p.ClientSecretEnc,
		p.AuthorizationURL, p.AccessTokenURL, p.ResourceURL, p.LogoutURL,
		p.UserIdentifier, joinScopes(p.Scopes), p.RedirectURL, p.Enabled, now(), p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteProvider(id string) error {
	res, err := s.db.Exec(`DELETE FROM providers WHERE id = ? AND kind != 'internal'`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetInternalProvider returns the single kind='internal' row, if initialized.
func (s *Store) GetInternalProvider() (*models.Provider, error) {
	return scanProvider(s.db.QueryRow(`SELECT ` + providerCols + ` FROM providers WHERE kind = 'internal' LIMIT 1`))
}

// UpsertInternalProvider initializes or updates the local provider's issuer.
func (s *Store) UpsertInternalProvider(issuer string) error {
	existing, err := s.GetInternalProvider()
	if errors.Is(err, ErrNotFound) {
		return s.CreateProvider(&models.Provider{
			ID:      "self",
			Name:    "Local (access-nex)",
			Kind:    models.ProviderKindInternal,
			Issuer:  issuer,
			Enabled: true,
		})
	}
	if err != nil {
		return err
	}
	existing.Issuer = issuer
	return s.UpdateProvider(existing)
}

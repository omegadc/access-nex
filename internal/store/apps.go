package store

import (
	"database/sql"
	"errors"

	"github.com/omegadc/access-nex/internal/models"
)

const appCols = `id, name, secret, public, provider_id, redirect_uris, scopes, enabled, id_token_enc_key, created_at, updated_at`

func scanApp(row interface{ Scan(...any) error }) (*models.App, error) {
	var a models.App
	var providerID sql.NullString
	var uris, scopes, created, updated string
	err := row.Scan(&a.ID, &a.Name, &a.Secret, &a.Public, &providerID,
		&uris, &scopes, &a.Enabled, &a.IDTokenEncKey, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.ProviderID = fromNull(providerID)
	a.RedirectURIs = urisFromJSON(uris)
	a.Scopes = splitScopes(scopes)
	a.CreatedAt = parseTime(created)
	a.UpdatedAt = parseTime(updated)
	return &a, nil
}

func (s *Store) CreateApp(a *models.App) error {
	ts := now()
	a.CreatedAt = parseTime(ts)
	a.UpdatedAt = a.CreatedAt
	_, err := s.db.Exec(`
		INSERT INTO applications (id, name, secret, public, provider_id, redirect_uris, scopes, enabled, id_token_enc_key, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.Secret, a.Public, nullable(a.ProviderID),
		urisToJSON(a.RedirectURIs), joinScopes(a.Scopes), a.Enabled, a.IDTokenEncKey, ts, ts)
	return err
}

func (s *Store) GetApp(id string) (*models.App, error) {
	return scanApp(s.db.QueryRow(`SELECT `+appCols+` FROM applications WHERE id = ?`, id))
}

func (s *Store) ListApps() ([]*models.App, error) {
	rows, err := s.db.Query(`SELECT ` + appCols + ` FROM applications ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []*models.App
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

func (s *Store) UpdateApp(a *models.App) error {
	res, err := s.db.Exec(`
		UPDATE applications
		SET name = ?, secret = ?, public = ?, provider_id = ?, redirect_uris = ?, scopes = ?, enabled = ?, id_token_enc_key = ?, updated_at = ?
		WHERE id = ?`,
		a.Name, a.Secret, a.Public, nullable(a.ProviderID),
		urisToJSON(a.RedirectURIs), joinScopes(a.Scopes), a.Enabled, a.IDTokenEncKey, now(), a.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteApp(id string) error {
	res, err := s.db.Exec(`DELETE FROM applications WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

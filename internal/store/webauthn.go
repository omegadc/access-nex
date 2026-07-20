package store

import (
	"database/sql"
	"errors"

	"github.com/omegadc/access-nex/internal/models"
)

const credCols = `id, user_id, name, credential_json, created_at`

func scanCredential(row interface{ Scan(...any) error }) (*models.WebAuthnCredential, error) {
	var c models.WebAuthnCredential
	var credJSON, created string
	err := row.Scan(&c.ID, &c.UserID, &c.Name, &credJSON, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.CredentialJSON = []byte(credJSON)
	c.CreatedAt = parseTime(created)
	return &c, nil
}

func (s *Store) SaveWebAuthnCredential(c *models.WebAuthnCredential) error {
	_, err := s.db.Exec(`
		INSERT INTO webauthn_credentials (id, user_id, name, credential_json, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.Name, string(c.CredentialJSON), now())
	return err
}

func (s *Store) ListWebAuthnCredentials(userID int64) ([]*models.WebAuthnCredential, error) {
	rows, err := s.db.Query(`SELECT `+credCols+` FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.WebAuthnCredential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetWebAuthnCredential(id string) (*models.WebAuthnCredential, error) {
	return scanCredential(s.db.QueryRow(`SELECT `+credCols+` FROM webauthn_credentials WHERE id = ?`, id))
}

// UpdateWebAuthnCredential persists the credential after a successful login
// (the library bumps the authenticator's signature counter and clone-warning
// flag inside the serialized struct — required so a cloned authenticator
// whose counter doesn't increase, or goes backward, can be detected).
func (s *Store) UpdateWebAuthnCredential(c *models.WebAuthnCredential) error {
	res, err := s.db.Exec(`UPDATE webauthn_credentials SET credential_json = ? WHERE id = ?`,
		string(c.CredentialJSON), c.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteWebAuthnCredential(userID int64, id string) error {
	res, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CountWebAuthnCredentials(userID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

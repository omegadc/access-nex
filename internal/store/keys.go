package store

import (
	"github.com/omegadc/access-nex/internal/models"
)

// ListSigningKeys returns all keys, active first, newest next. Retired keys
// are excluded unless includeRetired is set.
func (s *Store) ListSigningKeys(includeRetired bool) ([]*models.SigningKey, error) {
	q := `SELECT kid, pem_enc, active, created_at, retired_at FROM signing_keys`
	if !includeRetired {
		q += ` WHERE retired_at = ''`
	}
	q += ` ORDER BY active DESC, created_at DESC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*models.SigningKey
	for rows.Next() {
		var k models.SigningKey
		var created, retired string
		if err := rows.Scan(&k.Kid, &k.PEMEnc, &k.Active, &created, &retired); err != nil {
			return nil, err
		}
		k.CreatedAt = parseTime(created)
		if retired != "" {
			k.RetiredAt = parseTime(retired)
		}
		keys = append(keys, &k)
	}
	return keys, rows.Err()
}

// InsertSigningKey adds a key. If active is true, all other keys are
// deactivated first (exactly one key signs at a time).
func (s *Store) InsertSigningKey(kid, pemEnc string, active bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if active {
		if _, err := tx.Exec(`UPDATE signing_keys SET active = 0`); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`
		INSERT INTO signing_keys (kid, pem_enc, active, created_at) VALUES (?, ?, ?, ?)`,
		kid, pemEnc, active, now()); err != nil {
		return err
	}
	return tx.Commit()
}

// RetireSigningKey removes a non-active key from JWKS publication. Tokens
// signed with it will no longer verify, so retire only after they expired.
func (s *Store) RetireSigningKey(kid string) error {
	res, err := s.db.Exec(`UPDATE signing_keys SET retired_at = ? WHERE kid = ? AND active = 0 AND retired_at = ''`,
		now(), kid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

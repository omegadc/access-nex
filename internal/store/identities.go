package store

import (
	"github.com/omegadc/access-nex/internal/models"
)

// ListIdentities returns the external identities linked to a user (account
// linking), for the portal's "linked accounts" self-service section.
func (s *Store) ListIdentities(userID int64) ([]*models.Identity, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, provider_id, external_id, created_at
		FROM identities WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Identity
	for rows.Next() {
		var id models.Identity
		var created string
		if err := rows.Scan(&id.ID, &id.UserID, &id.ProviderID, &id.ExternalID, &created); err != nil {
			return nil, err
		}
		id.CreatedAt = parseTime(created)
		out = append(out, &id)
	}
	return out, rows.Err()
}

func (s *Store) CountIdentities(userID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM identities WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

// UnlinkIdentity removes one linked identity, scoped to userID so a user can
// only unlink their own.
func (s *Store) UnlinkIdentity(userID, identityID int64) error {
	res, err := s.db.Exec(`DELETE FROM identities WHERE id = ? AND user_id = ?`, identityID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

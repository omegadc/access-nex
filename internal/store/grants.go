package store

import (
	"database/sql"
	"errors"

	"github.com/omegadc/access-nex/internal/models"
)

// HasGrant reports whether the user previously approved this client for at
// least the requested scopes.
func (s *Store) HasGrant(subject, clientID string, scopes []string) (bool, error) {
	var granted string
	err := s.db.QueryRow(`SELECT scopes FROM grants WHERE subject = ? AND client_id = ?`,
		subject, clientID).Scan(&granted)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	have := map[string]bool{}
	for _, sc := range splitScopes(granted) {
		have[sc] = true
	}
	for _, sc := range scopes {
		if !have[sc] {
			return false, nil
		}
	}
	return true, nil
}

// SaveGrant records approval, merging with any previously granted scopes.
func (s *Store) SaveGrant(subject, clientID string, scopes []string) error {
	var existing string
	err := s.db.QueryRow(`SELECT scopes FROM grants WHERE subject = ? AND client_id = ?`,
		subject, clientID).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.db.Exec(`
			INSERT INTO grants (subject, client_id, scopes, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)`,
			subject, clientID, joinScopes(scopes), now(), now())
		return err
	case err != nil:
		return err
	}
	merged := splitScopes(existing)
	have := map[string]bool{}
	for _, sc := range merged {
		have[sc] = true
	}
	for _, sc := range scopes {
		if !have[sc] {
			merged = append(merged, sc)
		}
	}
	_, err = s.db.Exec(`UPDATE grants SET scopes = ?, updated_at = ? WHERE subject = ? AND client_id = ?`,
		joinScopes(merged), now(), subject, clientID)
	return err
}

func (s *Store) ListGrants(subject string) ([]*models.Grant, error) {
	rows, err := s.db.Query(`
		SELECT subject, client_id, scopes, created_at, updated_at
		FROM grants WHERE subject = ? ORDER BY client_id`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []*models.Grant
	for rows.Next() {
		var g models.Grant
		var scopes, created, updated string
		if err := rows.Scan(&g.Subject, &g.ClientID, &scopes, &created, &updated); err != nil {
			return nil, err
		}
		g.Scopes = splitScopes(scopes)
		g.CreatedAt = parseTime(created)
		g.UpdatedAt = parseTime(updated)
		grants = append(grants, &g)
	}
	return grants, rows.Err()
}

func (s *Store) DeleteGrant(subject, clientID string) error {
	_, err := s.db.Exec(`DELETE FROM grants WHERE subject = ? AND client_id = ?`, subject, clientID)
	return err
}

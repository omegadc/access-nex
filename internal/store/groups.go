package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/omegadc/access-nex/internal/models"
)

func (s *Store) CreateGroup(name, description string) (*models.Group, error) {
	res, err := s.db.Exec(`INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)`,
		name, description, now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &models.Group{ID: id, Name: name, Description: description}, nil
}

func (s *Store) GetGroupByName(name string) (*models.Group, error) {
	var g models.Group
	var created string
	err := s.db.QueryRow(`SELECT id, name, description, created_at FROM groups WHERE name = ?`, name).
		Scan(&g.ID, &g.Name, &g.Description, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.CreatedAt = parseTime(created)
	return &g, nil
}

func (s *Store) ListGroups() ([]*models.Group, error) {
	rows, err := s.db.Query(`SELECT id, name, description, created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Group
	for rows.Next() {
		var g models.Group
		var created string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &created); err != nil {
			return nil, err
		}
		g.CreatedAt = parseTime(created)
		out = append(out, &g)
	}
	return out, rows.Err()
}

func (s *Store) DeleteGroup(name string) error {
	res, err := s.db.Exec(`DELETE FROM groups WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AddGroupMember(groupName, username string) error {
	g, err := s.GetGroupByName(groupName)
	if err != nil {
		return err
	}
	u, err := s.GetUserByUsername(username)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO group_members (group_id, user_id) VALUES (?, ?)`, g.ID, u.ID)
	if err != nil && !isUniqueViolation(err) {
		return err
	}
	return nil
}

func (s *Store) RemoveGroupMember(groupName, username string) error {
	g, err := s.GetGroupByName(groupName)
	if err != nil {
		return err
	}
	u, err := s.GetUserByUsername(username)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, g.ID, u.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GroupNamesForSubject returns the names of every group the subject's user
// belongs to, sorted — used to populate the "groups" claim.
func (s *Store) GroupNamesForSubject(subject string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT g.name FROM groups g
		JOIN group_members gm ON gm.group_id = g.id
		JOIN users u ON u.id = gm.user_id
		WHERE u.subject = ? ORDER BY g.name`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

func (s *Store) ListGroupMembers(groupName string) ([]string, error) {
	g, err := s.GetGroupByName(groupName)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`
		SELECT u.username FROM users u
		JOIN group_members gm ON gm.user_id = u.id
		WHERE gm.group_id = ? ORDER BY u.username`, g.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

func isUniqueViolation(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "duplicate key") || strings.Contains(msg, "23505")
}

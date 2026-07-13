package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/omegadc/access-nex/internal/models"
)

var ErrNotFound = errors.New("not found")

const userCols = `id, subject, username, password_hash, email, name, provider_id, external_id, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*models.User, error) {
	var u models.User
	var providerID sql.NullString
	var created, updated string
	err := row.Scan(&u.ID, &u.Subject, &u.Username, &u.PasswordHash, &u.Email,
		&u.Name, &providerID, &u.ExternalID, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.ProviderID = fromNull(providerID)
	u.CreatedAt = parseTime(created)
	u.UpdatedAt = parseTime(updated)
	return &u, nil
}

func (s *Store) CreateUser(u *models.User) error {
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO users (subject, username, password_hash, email, name, provider_id, external_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Subject, u.Username, u.PasswordHash, u.Email, u.Name,
		nullable(u.ProviderID), u.ExternalID, ts, ts)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("user %q already exists", u.Username)
		}
		return err
	}
	u.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) GetUserByUsername(username string) (*models.User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, username))
}

func (s *Store) GetUserBySubject(subject string) (*models.User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE subject = ?`, subject))
}

func (s *Store) ListUsers() ([]*models.User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) DeleteUserByUsername(username string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnsureExternalUser finds or creates the local user for an identity coming
// from an external provider. Returns the subject and whether it was created.
func (s *Store) EnsureExternalUser(providerID, externalID, login, email, name string) (string, bool, error) {
	subject := fmt.Sprintf("ext:%s:%s", providerID, externalID)
	if _, err := s.GetUserBySubject(subject); err == nil {
		return subject, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return "", false, err
	}

	suffix := externalID
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	if login == "" && email != "" {
		login = strings.SplitN(email, "@", 2)[0]
	}
	if login == "" {
		login = "ext-" + suffix
	}

	username := login
	if _, err := s.GetUserByUsername(username); err == nil {
		username = login + "-" + suffix
	}

	u := &models.User{
		Subject:    subject,
		Username:   username,
		Email:      email,
		Name:       name,
		ProviderID: providerID,
		ExternalID: externalID,
	}
	if err := s.CreateUser(u); err != nil {
		return "", false, err
	}
	return subject, true, nil
}

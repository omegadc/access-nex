package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/models"
)

var ErrNotFound = errors.New("not found")

const userCols = `id, subject, username, password_hash, email, name, provider_id, external_id,
	is_admin, failed_logins, locked_until, totp_secret, totp_enabled, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*models.User, error) {
	var u models.User
	var providerID sql.NullString
	var locked, created, updated string
	err := row.Scan(&u.ID, &u.Subject, &u.Username, &u.PasswordHash, &u.Email,
		&u.Name, &providerID, &u.ExternalID,
		&u.IsAdmin, &u.FailedLogins, &locked, &u.TOTPSecret, &u.TOTPEnabled, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.ProviderID = fromNull(providerID)
	if locked != "" {
		u.LockedUntil = parseTime(locked)
	}
	u.CreatedAt = parseTime(created)
	u.UpdatedAt = parseTime(updated)
	return &u, nil
}

func (s *Store) CreateUser(u *models.User) error {
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO users (subject, username, password_hash, email, name, provider_id, external_id,
			is_admin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Subject, u.Username, u.PasswordHash, u.Email, u.Name,
		nullable(u.ProviderID), u.ExternalID, u.IsAdmin, ts, ts)
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

func (s *Store) GetUserByID(id int64) (*models.User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// GetSoleUserByEmail returns the user with the given email only when exactly
// one exists — used for account linking, where ambiguity must not link.
func (s *Store) GetSoleUserByEmail(email string) (*models.User, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = ?`, email).Scan(&count); err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrNotFound
	}
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE email = ?`, email))
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

func (s *Store) SetUserAdmin(username string, admin bool) error {
	res, err := s.db.Exec(`UPDATE users SET is_admin = ?, updated_at = ? WHERE username = ?`,
		admin, now(), username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Login lockout ─────────────────────────────────────────────────────────────

// RegisterLoginFailure bumps the failed-login counter; after maxFailures the
// account is locked for lockFor. Returns whether the account is now locked.
func (s *Store) RegisterLoginFailure(username string, maxFailures int, lockFor time.Duration) (bool, error) {
	u, err := s.GetUserByUsername(username)
	if err != nil {
		return false, err
	}
	failures := u.FailedLogins + 1
	lockedUntil := ""
	if failures >= maxFailures {
		lockedUntil = time.Now().Add(lockFor).UTC().Format(time.RFC3339)
		failures = 0
	}
	_, err = s.db.Exec(`UPDATE users SET failed_logins = ?, locked_until = ? WHERE username = ?`,
		failures, lockedUntil, username)
	return lockedUntil != "", err
}

func (s *Store) ClearLoginFailures(username string) error {
	_, err := s.db.Exec(`UPDATE users SET failed_logins = 0, locked_until = '' WHERE username = ?`, username)
	return err
}

// ── External identities & account linking ────────────────────────────────────

// LinkIdentity records that an external identity belongs to a local user.
func (s *Store) LinkIdentity(userID int64, providerID, externalID string) error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO identities (user_id, provider_id, external_id, created_at)
		VALUES (?, ?, ?, ?)`, userID, providerID, externalID, now())
	return err
}

// GetUserByIdentity resolves an external identity to its linked local user.
func (s *Store) GetUserByIdentity(providerID, externalID string) (*models.User, error) {
	return scanUser(s.db.QueryRow(`
		SELECT `+prefixCols(userCols, "u.")+` FROM users u
		JOIN identities i ON i.user_id = u.id
		WHERE i.provider_id = ? AND i.external_id = ?`, providerID, externalID))
}

func prefixCols(cols, prefix string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = prefix + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// EnsureExternalUser resolves an external identity to a local subject:
//
//  1. Identity already linked → that user.
//  2. Verified email matches exactly one local user → link to it.
//  3. Otherwise → create a new user and link the identity.
//
// Returns (subject, createdNewUser, linkedToExisting).
func (s *Store) EnsureExternalUser(providerID, externalID, login, email, name string, emailVerified bool) (string, bool, bool, error) {
	if u, err := s.GetUserByIdentity(providerID, externalID); err == nil {
		return u.Subject, false, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return "", false, false, err
	}

	// Account linking: attach this identity to an existing local user with
	// the same verified email address.
	if email != "" && emailVerified {
		if u, err := s.GetSoleUserByEmail(email); err == nil {
			if err := s.LinkIdentity(u.ID, providerID, externalID); err != nil {
				return "", false, false, err
			}
			return u.Subject, false, true, nil
		} else if !errors.Is(err, ErrNotFound) {
			return "", false, false, err
		}
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
		Subject:    fmt.Sprintf("ext:%s:%s", providerID, externalID),
		Username:   username,
		Email:      email,
		Name:       name,
		ProviderID: providerID,
		ExternalID: externalID,
	}
	if err := s.CreateUser(u); err != nil {
		return "", false, false, err
	}
	if err := s.LinkIdentity(u.ID, providerID, externalID); err != nil {
		return "", false, false, err
	}
	return u.Subject, true, false, nil
}

// ── Password & TOTP self-service ──────────────────────────────────────────────

func (s *Store) UpdatePasswordHash(username, hash string) error {
	res, err := s.db.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?`,
		hash, now(), username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPendingTOTPSecret stores a secret awaiting confirmation (totp_enabled
// stays false until ConfirmTOTP is called with a valid code).
func (s *Store) SetPendingTOTPSecret(username, secret string) error {
	_, err := s.db.Exec(`UPDATE users SET totp_secret = ?, totp_enabled = 0, updated_at = ? WHERE username = ?`,
		secret, now(), username)
	return err
}

func (s *Store) ConfirmTOTP(username string) error {
	res, err := s.db.Exec(`UPDATE users SET totp_enabled = 1, updated_at = ? WHERE username = ? AND totp_secret != ''`,
		now(), username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DisableTOTP(username string) error {
	_, err := s.db.Exec(`UPDATE users SET totp_secret = '', totp_enabled = 0, updated_at = ? WHERE username = ?`,
		now(), username)
	return err
}

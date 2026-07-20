package store

// Password reset and email verification: single-use, expiring tokens. Both
// tables share the same shape, so one pair of helpers backs both.

import (
	"database/sql"
	"errors"
	"time"
)

const resetTokenTTL = 1 * time.Hour
const verifyTokenTTL = 24 * time.Hour

func (s *Store) SavePasswordReset(token, subject string) error {
	_, err := s.db.Exec(`INSERT INTO password_resets (token, subject, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		token, subject, time.Now().Add(resetTokenTTL).UTC().Format(time.RFC3339), now())
	return err
}

// ConsumePasswordReset validates and deletes a reset token in one step —
// single-use, like an auth code.
func (s *Store) ConsumePasswordReset(token string) (subject string, err error) {
	var expires string
	err = s.db.QueryRow(`SELECT subject, expires_at FROM password_resets WHERE token = ?`, token).
		Scan(&subject, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`DELETE FROM password_resets WHERE token = ?`, token); err != nil {
		return "", err
	}
	if time.Now().After(parseTime(expires)) {
		return "", ErrNotFound
	}
	return subject, nil
}

func (s *Store) SaveEmailVerification(token, subject string) error {
	_, err := s.db.Exec(`INSERT INTO email_verifications (token, subject, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		token, subject, time.Now().Add(verifyTokenTTL).UTC().Format(time.RFC3339), now())
	return err
}

func (s *Store) ConsumeEmailVerification(token string) (subject string, err error) {
	var expires string
	err = s.db.QueryRow(`SELECT subject, expires_at FROM email_verifications WHERE token = ?`, token).
		Scan(&subject, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`DELETE FROM email_verifications WHERE token = ?`, token); err != nil {
		return "", err
	}
	if time.Now().After(parseTime(expires)) {
		return "", ErrNotFound
	}
	return subject, nil
}

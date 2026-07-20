package store

// Runtime state persistence: authorization codes, access/refresh tokens, and
// sessions. Keeping these in SQL (instead of in-memory maps) means logins and
// issued tokens survive server restarts.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/omegadc/access-nex/internal/models"
)

// ── Authorization codes ───────────────────────────────────────────────────────

func (s *Store) SaveAuthCode(c *models.AuthCode) error {
	_, err := s.db.Exec(`
		INSERT INTO auth_codes (code, client_id, redirect_uri, subject, scopes, nonce,
			code_challenge, code_challenge_method, auth_time, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Code, c.ClientID, c.RedirectURI, c.Subject, joinScopes(c.Scope), c.Nonce,
		c.CodeChallenge, c.CodeChallengeMethod,
		c.AuthTime.UTC().Format(time.RFC3339), c.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

// ConsumeAuthCode fetches and deletes a code in one step — auth codes are
// strictly single-use.
func (s *Store) ConsumeAuthCode(code string) (*models.AuthCode, error) {
	var c models.AuthCode
	var scopes, authTime, expires string
	err := s.db.QueryRow(`
		SELECT code, client_id, redirect_uri, subject, scopes, nonce,
			code_challenge, code_challenge_method, auth_time, expires_at
		FROM auth_codes WHERE code = ?`, code).
		Scan(&c.Code, &c.ClientID, &c.RedirectURI, &c.Subject, &scopes, &c.Nonce,
			&c.CodeChallenge, &c.CodeChallengeMethod, &authTime, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if _, err := s.db.Exec(`DELETE FROM auth_codes WHERE code = ?`, code); err != nil {
		return nil, err
	}
	c.Scope = splitScopes(scopes)
	c.AuthTime = parseTime(authTime)
	c.ExpiresAt = parseTime(expires)
	return &c, nil
}

// ── Access tokens ─────────────────────────────────────────────────────────────

func (s *Store) SaveAccessToken(t *models.TokenRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO access_tokens (token, jti, client_id, subject, scopes, audiences, jkt, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		t.Token, t.JTI, t.ClientID, t.Subject, joinScopes(t.Scope), joinScopes(t.Audiences), t.JKT,
		t.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

func (s *Store) GetAccessToken(token string) (*models.TokenRecord, error) {
	var t models.TokenRecord
	var scopes, audiences, expires string
	err := s.db.QueryRow(`
		SELECT token, jti, client_id, subject, scopes, audiences, jkt, expires_at, revoked
		FROM access_tokens WHERE token = ?`, token).
		Scan(&t.Token, &t.JTI, &t.ClientID, &t.Subject, &scopes, &audiences, &t.JKT, &expires, &t.Revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.Scope = splitScopes(scopes)
	t.Audiences = splitScopes(audiences)
	t.ExpiresAt = parseTime(expires)
	return &t, nil
}

// ── Refresh tokens ────────────────────────────────────────────────────────────

// ErrRefreshReuse signals that an already-revoked refresh token was replayed;
// the whole rotation family has been revoked in response.
var ErrRefreshReuse = errors.New("refresh token reuse detected")

func (s *Store) SaveRefreshToken(t *models.RefreshRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO refresh_tokens (token, client_id, subject, scopes, family, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, 0)`,
		t.Token, t.ClientID, t.Subject, joinScopes(t.Scope), t.Family,
		t.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

func (s *Store) GetRefreshToken(token string) (*models.RefreshRecord, error) {
	var t models.RefreshRecord
	var scopes, expires string
	err := s.db.QueryRow(`
		SELECT token, client_id, subject, scopes, family, expires_at, revoked
		FROM refresh_tokens WHERE token = ?`, token).
		Scan(&t.Token, &t.ClientID, &t.Subject, &scopes, &t.Family, &expires, &t.Revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.Scope = splitScopes(scopes)
	t.ExpiresAt = parseTime(expires)
	return &t, nil
}

// ConsumeRefreshToken validates a refresh token for a client and marks it
// revoked (single-use rotation). Presenting a token that was already used
// is treated as theft: the entire family is revoked and ErrRefreshReuse is
// returned so the caller can audit it.
func (s *Store) ConsumeRefreshToken(token, clientID string) (*models.RefreshRecord, error) {
	t, err := s.GetRefreshToken(token)
	if err != nil {
		return nil, err
	}
	if t.Revoked {
		if t.Family != "" {
			if _, err := s.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE family = ?`, t.Family); err != nil {
				return nil, err
			}
		}
		return t, ErrRefreshReuse
	}
	if t.ClientID != clientID || time.Now().After(t.ExpiresAt) {
		return nil, ErrNotFound
	}
	if _, err := s.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE token = ?`, token); err != nil {
		return nil, err
	}
	return t, nil
}

// RevokeToken marks a token revoked in whichever table it lives, but only if
// it belongs to the requesting client (per RFC 7009).
func (s *Store) RevokeToken(token, clientID string) error {
	if _, err := s.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE token = ? AND client_id = ?`, token, clientID); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE token = ? AND client_id = ?`, token, clientID)
	return err
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func (s *Store) SaveSession(sess *models.Session) error {
	created := sess.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.db.Exec(`
		INSERT INTO sessions (id, subject, expires_at, created_at, user_agent) VALUES (?, ?, ?, ?, ?)`,
		sess.ID, sess.Subject, sess.ExpiresAt.UTC().Format(time.RFC3339),
		created.UTC().Format(time.RFC3339), sess.UserAgent)
	return err
}

func scanSession(row interface{ Scan(...any) error }) (*models.Session, error) {
	var sess models.Session
	var expires, created string
	err := row.Scan(&sess.ID, &sess.Subject, &expires, &created, &sess.UserAgent)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	sess.ExpiresAt = parseTime(expires)
	if created != "" {
		sess.CreatedAt = parseTime(created)
	}
	return &sess, nil
}

func (s *Store) GetSession(id string) (*models.Session, error) {
	return scanSession(s.db.QueryRow(`SELECT id, subject, expires_at, created_at, user_agent FROM sessions WHERE id = ?`, id))
}

// ListSessions returns a subject's non-expired sessions, newest first, for
// the portal's "active sessions" self-service view.
func (s *Store) ListSessions(subject string) ([]*models.Session, error) {
	rows, err := s.db.Query(`
		SELECT id, subject, expires_at, created_at, user_agent FROM sessions
		WHERE subject = ? AND expires_at > ? ORDER BY created_at DESC`,
		subject, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteSessionForSubject revokes one session, but only if it belongs to
// subject — used by the self-service portal so a user can only end their own
// sessions.
func (s *Store) DeleteSessionForSubject(subject, id string) error {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE id = ? AND subject = ?`, id, subject)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Stats and housekeeping ────────────────────────────────────────────────────

// CountActive returns non-expired session and access-token counts for the portal.
func (s *Store) CountActive() (sessions, tokens int, err error) {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE expires_at > ?`, nowStr).Scan(&sessions); err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM access_tokens WHERE revoked = 0 AND expires_at > ?`, nowStr).Scan(&tokens)
	return
}

// CleanupExpired deletes expired runtime rows. Timestamps are RFC3339 UTC
// strings, which compare correctly as text.
func (s *Store) CleanupExpired() error {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	for _, q := range []string{
		`DELETE FROM auth_codes WHERE expires_at <= ?`,
		`DELETE FROM access_tokens WHERE expires_at <= ?`,
		`DELETE FROM refresh_tokens WHERE expires_at <= ?`,
		`DELETE FROM sessions WHERE expires_at <= ?`,
		`DELETE FROM device_codes WHERE expires_at <= ?`,
	} {
		if _, err := s.db.Exec(q, nowStr); err != nil {
			return err
		}
	}
	return nil
}

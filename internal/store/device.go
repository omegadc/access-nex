package store

// RFC 8628 device authorization grant storage.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/omegadc/access-nex/internal/models"
)

func (s *Store) SaveDeviceCode(d *models.DeviceCode) error {
	_, err := s.db.Exec(`
		INSERT INTO device_codes (device_code, user_code, client_id, scopes, status,
			subject, interval_secs, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceCode, d.UserCode, d.ClientID, joinScopes(d.Scope), models.DeviceStatusPending,
		"", d.IntervalSecs, d.ExpiresAt.UTC().Format(time.RFC3339), now())
	return err
}

func scanDeviceCode(row interface{ Scan(...any) error }) (*models.DeviceCode, error) {
	var d models.DeviceCode
	var scopes, lastPolled, expires, created string
	err := row.Scan(&d.DeviceCode, &d.UserCode, &d.ClientID, &scopes, &d.Status,
		&d.Subject, &d.IntervalSecs, &lastPolled, &expires, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	d.Scope = splitScopes(scopes)
	if lastPolled != "" {
		d.LastPolledAt = parseTime(lastPolled)
	}
	d.ExpiresAt = parseTime(expires)
	d.CreatedAt = parseTime(created)
	return &d, nil
}

const deviceCols = `device_code, user_code, client_id, scopes, status, subject, interval_secs, last_polled_at, expires_at, created_at`

func (s *Store) GetDeviceCode(deviceCode string) (*models.DeviceCode, error) {
	return scanDeviceCode(s.db.QueryRow(`SELECT `+deviceCols+` FROM device_codes WHERE device_code = ?`, deviceCode))
}

// GetDeviceCodeByUserCode looks up a pending code by the short code a human
// types in at the verification page. Comparison is case-insensitive.
func (s *Store) GetDeviceCodeByUserCode(userCode string) (*models.DeviceCode, error) {
	return scanDeviceCode(s.db.QueryRow(`SELECT `+deviceCols+` FROM device_codes WHERE upper(user_code) = upper(?)`, userCode))
}

// MarkDevicePolled enforces the RFC 8628 polling interval: it records the
// poll time and reports whether the caller is polling too fast.
func (s *Store) MarkDevicePolled(deviceCode string) (tooFast bool, err error) {
	d, err := s.GetDeviceCode(deviceCode)
	if err != nil {
		return false, err
	}
	if !d.LastPolledAt.IsZero() && time.Since(d.LastPolledAt) < time.Duration(d.IntervalSecs)*time.Second {
		tooFast = true
	}
	_, err = s.db.Exec(`UPDATE device_codes SET last_polled_at = ? WHERE device_code = ?`, now(), deviceCode)
	return tooFast, err
}

// ResolveDeviceCode records the user's approve/deny decision against the
// user_code they typed in, scoped to pending codes that haven't expired.
func (s *Store) ResolveDeviceCode(userCode, subject, status string) error {
	res, err := s.db.Exec(`
		UPDATE device_codes SET status = ?, subject = ?
		WHERE upper(user_code) = upper(?) AND status = ? AND expires_at > ?`,
		status, subject, userCode, models.DeviceStatusPending, now())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteDeviceCode(deviceCode string) error {
	_, err := s.db.Exec(`DELETE FROM device_codes WHERE device_code = ?`, deviceCode)
	return err
}

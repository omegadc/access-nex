package store

import (
	"log"

	"github.com/omegadc/access-nex/internal/models"
)

// Audit appends an entry to the audit log. Failures are logged, not
// propagated — auditing must never break the main flow.
func (s *Store) Audit(event, subject, clientID, ip, detail string) {
	_, err := s.db.Exec(`
		INSERT INTO audit_log (at, event, subject, client_id, ip, detail)
		VALUES (?, ?, ?, ?, ?, ?)`, now(), event, subject, clientID, ip, detail)
	if err != nil {
		log.Printf("audit: %v", err)
	}
}

// ListAudit returns the newest entries, most recent first.
func (s *Store) ListAudit(limit int) ([]*models.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT id, at, event, subject, client_id, ip, detail
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []*models.AuditEntry
	for rows.Next() {
		var e models.AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Event, &e.Subject, &e.ClientID, &e.IP, &e.Detail); err != nil {
			return nil, err
		}
		e.At = parseTime(at)
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

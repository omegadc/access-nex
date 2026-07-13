// Package store provides SQL-backed CRUD for users, providers, and
// applications. It is the only package that writes SQL against the database.
package store

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Store wraps the database handle. Create one with New and share it between
// the CLI and the HTTP server.
type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Counts returns totals for the dashboard / provider info commands.
func (s *Store) Counts() (users, apps, externalProviders int, err error) {
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return
	}
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM applications`).Scan(&apps); err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM providers WHERE kind != 'internal'`).Scan(&externalProviders)
	return
}

// ── column conversion helpers ─────────────────────────────────────────────────

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// joinScopes stores scope lists as a single space-separated column.
func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }

func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// urisToJSON stores redirect URI lists as a JSON array column.
func urisToJSON(uris []string) string {
	if uris == nil {
		uris = []string{}
	}
	data, _ := json.Marshal(uris)
	return string(data)
}

func urisFromJSON(s string) []string {
	var uris []string
	_ = json.Unmarshal([]byte(s), &uris)
	return uris
}

// nullable maps "" to NULL for foreign key columns.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func fromNull(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

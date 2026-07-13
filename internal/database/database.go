// Package database opens the access-nex SQLite database and creates the
// schema. This replaces the previous JSON file storage (users.json,
// apps.json, providers.json).
//
// The driver is modernc.org/sqlite — a pure-Go SQLite build, so no CGO or C
// compiler is needed on any platform.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DefaultFileName is the database file created inside the config directory.
const DefaultFileName = "access-nex.db"

// Schema creates the three core tables. Everything is idempotent
// (IF NOT EXISTS) so it runs safely on every startup.
const Schema = `
CREATE TABLE IF NOT EXISTS providers (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('internal','oidc','oauth2')),
    template          TEXT NOT NULL DEFAULT '',
    issuer            TEXT NOT NULL DEFAULT '',
    client_id         TEXT NOT NULL DEFAULT '',
    client_secret_enc TEXT NOT NULL DEFAULT '',
    authorization_url TEXT NOT NULL DEFAULT '',
    access_token_url  TEXT NOT NULL DEFAULT '',
    resource_url      TEXT NOT NULL DEFAULT '',
    logout_url        TEXT NOT NULL DEFAULT '',
    user_identifier   TEXT NOT NULL DEFAULT 'sub',
    scopes            TEXT NOT NULL DEFAULT '',
    redirect_url      TEXT NOT NULL DEFAULT '',
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    subject       TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',
    provider_id   TEXT REFERENCES providers(id) ON DELETE SET NULL,
    external_id   TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applications (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    secret        TEXT NOT NULL DEFAULT '',
    public        INTEGER NOT NULL DEFAULT 0,
    provider_id   TEXT REFERENCES providers(id) ON DELETE SET NULL,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    scopes        TEXT NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider_id);
CREATE INDEX IF NOT EXISTS idx_apps_provider  ON applications(provider_id);

-- Runtime state: persisted so logins, codes, and tokens survive restarts.
CREATE TABLE IF NOT EXISTS auth_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL DEFAULT '',
    subject               TEXT NOT NULL,
    scopes                TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    auth_time             TEXT NOT NULL,
    expires_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_tokens (
    token      TEXT PRIMARY KEY,
    jti        TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token      TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    subject    TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
`

// Open creates the config directory if needed, opens (or creates) the SQLite
// database file inside it, and ensures the schema exists.
func Open(configDir string) (*sql.DB, error) {
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	path := filepath.Join(configDir, DefaultFileName)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// SQLite allows a single writer; serializing through one connection
	// avoids SQLITE_BUSY errors under concurrent HTTP handlers.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure database: %w", err)
	}
	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return db, nil
}

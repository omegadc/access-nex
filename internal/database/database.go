// Package database opens the access-nex database and creates the schema.
// Two backends are supported: the zero-config default (pure-Go SQLite, no
// CGO) and PostgreSQL for multi-instance deployments — selected by the DSN
// passed to Open. The rest of the codebase (internal/store) writes plain
// `?`-style parameterized SQL; DB rebinds placeholders to `$N` transparently
// when talking to Postgres, so no query text has to change per backend.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

// DefaultFileName is the SQLite database file created inside the config directory.
const DefaultFileName = "access-nex.db"

// DB wraps *sql.DB, rebinding `?` placeholders to `$N` for Postgres.
type DB struct {
	*sql.DB
	Dialect Dialect
}

func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	return d.DB.Exec(rebind(d.Dialect, query), convertArgs(d.Dialect, args)...)
}

func (d *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return d.DB.Query(rebind(d.Dialect, query), convertArgs(d.Dialect, args)...)
}

func (d *DB) QueryRow(query string, args ...any) *sql.Row {
	return d.DB.QueryRow(rebind(d.Dialect, query), convertArgs(d.Dialect, args)...)
}

func (d *DB) Begin() (*Tx, error) {
	tx, err := d.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx, dialect: d.Dialect}, nil
}

// Tx mirrors DB's rebinding behavior for transactions.
type Tx struct {
	*sql.Tx
	dialect Dialect
}

func (t *Tx) Exec(query string, args ...any) (sql.Result, error) {
	return t.Tx.Exec(rebind(t.dialect, query), convertArgs(t.dialect, args)...)
}

func (t *Tx) Query(query string, args ...any) (*sql.Rows, error) {
	return t.Tx.Query(rebind(t.dialect, query), convertArgs(t.dialect, args)...)
}

func (t *Tx) QueryRow(query string, args ...any) *sql.Row {
	return t.Tx.QueryRow(rebind(t.dialect, query), convertArgs(t.dialect, args)...)
}

// convertArgs adapts Go values the two drivers disagree on. Booleans are the
// one case here: SQLite's driver freely accepts a Go bool for an INTEGER
// column, but pgx encodes strictly by column type and rejects it — so for
// Postgres, bools are sent as 0/1 instead. Schema and query text (which use
// INTEGER for every boolean-ish column) stay identical across both backends.
func convertArgs(d Dialect, args []any) []any {
	if d != DialectPostgres {
		return args
	}
	out := make([]any, len(args))
	for i, a := range args {
		if b, ok := a.(bool); ok {
			if b {
				out[i] = 1
			} else {
				out[i] = 0
			}
			continue
		}
		out[i] = a
	}
	return out
}

// rebind converts `?` placeholders to Postgres `$1, $2, ...` form. `?`
// characters inside single-quoted string literals are left untouched; none
// of this codebase's fixed SQL text embeds `?` inside a literal, so a simple
// quote-tracking scan is sufficient.
func rebind(d Dialect, query string) string {
	if d != DialectPostgres || !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	inString := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'':
			inString = !inString
			b.WriteByte(c)
		case c == '?' && !inString:
			n++
			fmt.Fprintf(&b, "$%d", n)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Open opens the database described by dsn.
//
//   - "postgres://..." or "postgresql://..." → connects to PostgreSQL.
//   - anything else is treated as a directory path (the pre-existing
//     zero-config behavior) and a SQLite file is opened/created inside it.
func Open(dsn string) (*DB, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return openPostgres(dsn)
	}
	return openSQLite(dsn)
}

func openSQLite(configDir string) (*DB, error) {
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	path := filepath.Join(configDir, DefaultFileName)

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// SQLite allows a single writer; serializing through one connection
	// avoids SQLITE_BUSY errors under concurrent HTTP handlers.
	sqlDB.SetMaxOpenConns(1)

	db := &DB{DB: sqlDB, Dialect: DialectSQLite}
	if _, err := db.Exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("configure database: %w", err)
	}
	if err := migrate(db); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func openPostgres(dsn string) (*DB, error) {
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	sqlDB.SetMaxOpenConns(10)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	db := &DB{DB: sqlDB, Dialect: DialectPostgres}
	if err := migrate(db); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *DB) error {
	if _, err := db.Exec(schema(db.Dialect)); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	for _, m := range columnMigrations {
		if err := ensureColumn(db, m.table, m.column, m.ddl); err != nil {
			return fmt.Errorf("migrate %s.%s: %w", m.table, m.column, err)
		}
	}
	// Backfill: users provisioned before account-linking existed carry their
	// external identity on the users row; mirror it into identities.
	backfill := `
		INSERT INTO identities (user_id, provider_id, external_id, created_at)
		SELECT id, provider_id, external_id, created_at FROM users
		WHERE provider_id IS NOT NULL AND external_id != ''
		ON CONFLICT (provider_id, external_id) DO NOTHING`
	if db.Dialect == DialectSQLite {
		backfill = strings.Replace(backfill,
			"INSERT INTO identities", "INSERT OR IGNORE INTO identities", 1)
		backfill = strings.Replace(backfill,
			"ON CONFLICT (provider_id, external_id) DO NOTHING", "", 1)
	}
	if _, err := db.Exec(backfill); err != nil {
		return fmt.Errorf("backfill identities: %w", err)
	}
	return nil
}

func ensureColumn(db *DB, table, column, ddl string) error {
	var checkQuery string
	if db.Dialect == DialectPostgres {
		checkQuery = `SELECT column_name FROM information_schema.columns WHERE table_name = ? AND column_name = ?`
	} else {
		checkQuery = `SELECT name FROM pragma_table_info(?) WHERE name = ?`
	}
	var name string
	err := db.QueryRow(checkQuery, table, column).Scan(&name)
	if err == nil {
		return nil // already present
	}
	if err != sql.ErrNoRows {
		return err
	}
	_, err = db.Exec(ddl)
	return err
}

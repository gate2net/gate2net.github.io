// Package store persists users, sessions, subdomains and SSH keys in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
	// ErrFull is returned when a range has no free port left.
	ErrFull = errors.New("no free port")
)

// Store wraps the SQLite database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database at path and migrates it.
func Open(path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

var migrations = []string{
	`CREATE TABLE users (
		id            INTEGER PRIMARY KEY,
		email         TEXT NOT NULL UNIQUE,
		name          TEXT NOT NULL DEFAULT '',
		avatar_url    TEXT NOT NULL DEFAULT '',
		webauthn_id   BLOB NOT NULL UNIQUE,
		disabled      INTEGER NOT NULL DEFAULT 0,
		created_at    INTEGER NOT NULL,
		last_login_at INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE identities (
		provider   TEXT NOT NULL,
		subject    TEXT NOT NULL,
		user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		username   TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		PRIMARY KEY (provider, subject)
	);
	CREATE INDEX identities_user ON identities(user_id);
	CREATE TABLE passkeys (
		id            INTEGER PRIMARY KEY,
		user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		credential_id BLOB NOT NULL UNIQUE,
		name          TEXT NOT NULL,
		credential    BLOB NOT NULL,
		created_at    INTEGER NOT NULL,
		last_used_at  INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX passkeys_user ON passkeys(user_id);
	CREATE TABLE sessions (
		id         TEXT PRIMARY KEY,
		token_hash BLOB NOT NULL UNIQUE,
		user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		csrf_token TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX sessions_user ON sessions(user_id);
	CREATE TABLE subdomains (
		id          INTEGER PRIMARY KEY,
		name        TEXT NOT NULL UNIQUE,
		user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		access      TEXT NOT NULL,
		created_at  INTEGER NOT NULL
	);
	CREATE INDEX subdomains_user ON subdomains(user_id);
	CREATE TABLE ssh_keys (
		id           INTEGER PRIMARY KEY,
		subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
		name         TEXT NOT NULL,
		fingerprint  TEXT NOT NULL,
		public_key   TEXT NOT NULL,
		created_at   INTEGER NOT NULL,
		last_used_at INTEGER NOT NULL DEFAULT 0,
		UNIQUE (subdomain_id, fingerprint)
	);
	CREATE INDEX ssh_keys_fingerprint ON ssh_keys(fingerprint);`,
	// Access and roles granted from the dashboard or the admin socket, on
	// top of what the configuration allows.
	`ALTER TABLE users ADD COLUMN added INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';`,
	// Raw TCP (and later UDP) ports of subdomains, each with a public port
	// allocated from tcp.ports for good.
	`CREATE TABLE tcp_ports (
		id           INTEGER PRIMARY KEY,
		subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
		name         TEXT NOT NULL,
		protocol     TEXT NOT NULL DEFAULT 'tcp',
		port         INTEGER NOT NULL UNIQUE,
		allow        TEXT NOT NULL DEFAULT '',
		preset       TEXT NOT NULL DEFAULT '',
		local_port   INTEGER NOT NULL DEFAULT 0,
		created_at   INTEGER NOT NULL,
		UNIQUE (subdomain_id, name)
	);
	CREATE INDEX tcp_ports_subdomain ON tcp_ports(subdomain_id);`,
	// Settings made from the dashboard's setup or the admin socket, such as
	// email delivery: JSON by key.
	`CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`,
	// SSH keys of an account, which its owner adds to subdomains: each
	// subdomain's copy refers to it, and goes with it.
	`CREATE TABLE user_keys (
		id          INTEGER PRIMARY KEY,
		user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name        TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		public_key  TEXT NOT NULL,
		created_at  INTEGER NOT NULL,
		UNIQUE (user_id, fingerprint)
	);
	ALTER TABLE ssh_keys ADD COLUMN user_key_id INTEGER REFERENCES user_keys(id) ON DELETE CASCADE;
	CREATE INDEX ssh_keys_user_key ON ssh_keys(user_key_id);`,
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var e *sqlite.Error
	return errors.As(err, &e) && e.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

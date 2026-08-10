package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store interface {
	Close(context.Context) error
}

type SQLiteStore struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("storage path is required")
	}
	if err := ensureParentDir(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &SQLiteStore{db: db}
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func (s *SQLiteStore) Close(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- s.db.Close()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SQLiteStore) configure(ctx context.Context) error {
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
	}
	for _, pragma := range pragmas {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("apply %s: %w", pragma, err)
		}
	}
	return nil
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TEXT NOT NULL
)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	migrations := []migration{
		{
			version: 1,
			name:    "create audit_events",
			statements: []string{
				`CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	client_ip TEXT NOT NULL,
	query_name TEXT NOT NULL,
	query_type INTEGER NOT NULL,
	action TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	rule_id INTEGER NOT NULL DEFAULT 0,
	blocklist_id INTEGER NOT NULL DEFAULT 0,
	response TEXT NOT NULL DEFAULT '',
	duration_ns INTEGER NOT NULL DEFAULT 0
)`,
				`CREATE INDEX IF NOT EXISTS audit_events_timestamp_idx
ON audit_events (timestamp DESC, id DESC)`,
			},
		},
		{
			version: 2,
			name:    "create admin_users",
			statements: []string{
				`CREATE TABLE IF NOT EXISTS admin_users (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	password_hash TEXT NOT NULL,
	created_at TEXT NOT NULL
)`,
			},
		},
		{
			version: 3,
			name:    "create app_config",
			statements: []string{
				`CREATE TABLE IF NOT EXISTS app_config (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	payload TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`,
			},
		},
		{
			version: 4,
			name:    "create local_dns_records",
			statements: []string{
				`CREATE TABLE IF NOT EXISTS local_dns_records (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	type TEXT NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME', 'PTR')),
	value TEXT NOT NULL,
	ttl INTEGER NOT NULL DEFAULT 300 CHECK (ttl >= 0 AND ttl <= 604800),
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
	comment TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`,
				`CREATE INDEX IF NOT EXISTS local_dns_records_lookup_idx
ON local_dns_records (enabled, name, type)`,
				`CREATE INDEX IF NOT EXISTS local_dns_records_updated_at_idx
ON local_dns_records (updated_at DESC, id DESC)`,
			},
		},
		{
			version: 5,
			name:    "create filter tables",
			statements: []string{
				`CREATE TABLE IF NOT EXISTS filter_lists (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	url TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '',
	kind TEXT NOT NULL CHECK (kind IN ('allow', 'deny')),
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
	last_updated_at TEXT NOT NULL DEFAULT '',
	last_error TEXT NOT NULL DEFAULT '',
	CHECK (url <> '' OR path <> '')
)`,
				`CREATE INDEX IF NOT EXISTS filter_lists_kind_enabled_idx
ON filter_lists (kind, enabled)`,
				`CREATE TABLE IF NOT EXISTS filter_list_entries (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	list_id INTEGER NOT NULL REFERENCES filter_lists(id) ON DELETE CASCADE,
	pattern TEXT NOT NULL,
	match_type TEXT NOT NULL CHECK (match_type IN ('exact', 'suffix', 'regex')),
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
	UNIQUE (list_id, pattern, match_type)
)`,
				`CREATE INDEX IF NOT EXISTS filter_list_entries_list_idx
ON filter_list_entries (list_id, enabled)`,
				`CREATE TABLE IF NOT EXISTS filter_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	pattern TEXT NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('allow', 'deny')),
	match_type TEXT NOT NULL CHECK (match_type IN ('exact', 'suffix', 'regex')),
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
	comment TEXT NOT NULL DEFAULT ''
)`,
				`CREATE INDEX IF NOT EXISTS filter_rules_kind_match_enabled_idx
ON filter_rules (kind, match_type, enabled)`,
				`CREATE TABLE IF NOT EXISTS filter_clients (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	address TEXT NOT NULL UNIQUE,
	comment TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
)`,
				`CREATE TABLE IF NOT EXISTS filter_groups (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	comment TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
)`,
				`CREATE TABLE IF NOT EXISTS filter_client_groups (
	client_id INTEGER NOT NULL REFERENCES filter_clients(id) ON DELETE CASCADE,
	group_id INTEGER NOT NULL REFERENCES filter_groups(id) ON DELETE CASCADE,
	PRIMARY KEY (client_id, group_id)
)`,
				`CREATE TABLE IF NOT EXISTS filter_list_groups (
	list_id INTEGER NOT NULL REFERENCES filter_lists(id) ON DELETE CASCADE,
	group_id INTEGER NOT NULL REFERENCES filter_groups(id) ON DELETE CASCADE,
	PRIMARY KEY (list_id, group_id)
)`,
				`CREATE TABLE IF NOT EXISTS filter_rule_groups (
	rule_id INTEGER NOT NULL REFERENCES filter_rules(id) ON DELETE CASCADE,
	group_id INTEGER NOT NULL REFERENCES filter_groups(id) ON DELETE CASCADE,
	PRIMARY KEY (rule_id, group_id)
)`,
			},
		},
		{
			version: 6,
			name:    "create audit settings",
			statements: []string{
				`CREATE TABLE IF NOT EXISTS audit_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	retention_duration_ns INTEGER NOT NULL DEFAULT 0 CHECK (retention_duration_ns >= 0),
	privacy_level INTEGER NOT NULL DEFAULT 0 CHECK (privacy_level >= 0 AND privacy_level <= 2),
	updated_at TEXT NOT NULL
)`,
				`INSERT OR IGNORE INTO audit_settings (
	id,
	retention_duration_ns,
	privacy_level,
	updated_at
) VALUES (1, 0, 0, '')`,
			},
		},
		{
			version: 7,
			name:    "create api_keys",
			statements: []string{
				`CREATE TABLE IF NOT EXISTS api_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	key_hash TEXT NOT NULL UNIQUE,
	prefix TEXT NOT NULL,
	last4 TEXT NOT NULL,
	created_at TEXT NOT NULL,
	last_used_at TEXT NOT NULL DEFAULT '',
	revoked_at TEXT NOT NULL DEFAULT '',
	disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
)`,
				`CREATE INDEX IF NOT EXISTS api_keys_hash_active_idx
ON api_keys (key_hash, disabled, revoked_at)`,
				`CREATE INDEX IF NOT EXISTS api_keys_created_at_idx
ON api_keys (created_at DESC, id DESC)`,
			},
		},
		{
			version: 8,
			name:    "index audit event query fields",
			statements: []string{
				`CREATE INDEX IF NOT EXISTS audit_events_client_ip_idx
ON audit_events (client_ip)`,
				`CREATE INDEX IF NOT EXISTS audit_events_query_name_idx
ON audit_events (query_name)`,
				`CREATE INDEX IF NOT EXISTS audit_events_query_type_idx
ON audit_events (query_type)`,
				`CREATE INDEX IF NOT EXISTS audit_events_action_idx
ON audit_events (action)`,
				`CREATE INDEX IF NOT EXISTS audit_events_response_idx
ON audit_events (response)`,
				`CREATE INDEX IF NOT EXISTS audit_events_rule_id_idx
ON audit_events (rule_id)`,
				`CREATE INDEX IF NOT EXISTS audit_events_blocklist_id_idx
ON audit_events (blocklist_id)`,
				`CREATE INDEX IF NOT EXISTS audit_events_duration_ns_idx
ON audit_events (duration_ns)`,
				`CREATE INDEX IF NOT EXISTS audit_events_client_ip_timestamp_idx
ON audit_events (client_ip, timestamp DESC, id DESC)`,
				`CREATE INDEX IF NOT EXISTS audit_events_query_name_timestamp_idx
ON audit_events (query_name, timestamp DESC, id DESC)`,
				`CREATE INDEX IF NOT EXISTS audit_events_action_timestamp_idx
ON audit_events (action, timestamp DESC, id DESC)`,
			},
		},
		{
			version: 9,
			name:    "create audit action totals",
			statements: []string{
				`CREATE TABLE IF NOT EXISTS audit_action_totals (
	action TEXT PRIMARY KEY,
	count INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
	updated_at TEXT NOT NULL
)`,
				`DELETE FROM audit_action_totals`,
				`INSERT INTO audit_action_totals (action, count, updated_at)
SELECT action, COUNT(*), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM audit_events
GROUP BY action`,
			},
		},
		{
			version: 10,
			name:    "add audit upstream diagnostics",
			statements: []string{
				`ALTER TABLE audit_events ADD COLUMN upstream_resolver TEXT NOT NULL DEFAULT ''`,
				`ALTER TABLE audit_events ADD COLUMN cache_status TEXT NOT NULL DEFAULT ''`,
				`ALTER TABLE audit_events ADD COLUMN forward_duration_ns INTEGER NOT NULL DEFAULT 0`,
				`ALTER TABLE audit_events ADD COLUMN retry_count INTEGER NOT NULL DEFAULT -1`,
				`ALTER TABLE audit_events ADD COLUMN forward_error TEXT NOT NULL DEFAULT ''`,
				`CREATE INDEX IF NOT EXISTS audit_events_upstream_resolver_idx
ON audit_events (upstream_resolver)`,
				`CREATE INDEX IF NOT EXISTS audit_events_cache_status_idx
ON audit_events (cache_status)`,
				`CREATE INDEX IF NOT EXISTS audit_events_forward_duration_ns_idx
ON audit_events (forward_duration_ns)`,
				`CREATE INDEX IF NOT EXISTS audit_events_retry_count_idx
ON audit_events (retry_count)`,
			},
		},
	}

	for _, migration := range migrations {
		if err := s.applyMigration(ctx, migration); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) applyMigration(ctx context.Context, migration migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", migration.version, err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var exists int
	err = tx.QueryRowContext(
		ctx,
		"SELECT COUNT(1) FROM schema_migrations WHERE version = ?",
		migration.version,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check migration %d: %w", migration.version, err)
	}
	if exists > 0 {
		return tx.Commit()
	}

	for _, statement := range migration.statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply migration %d: %w", migration.version, err)
		}
	}

	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
		migration.version,
		migration.name,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("record migration %d: %w", migration.version, err)
	}

	return tx.Commit()
}

type migration struct {
	version    int
	name       string
	statements []string
}

func ensureParentDir(path string) error {
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}

	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create storage directory: %w", err)
	}
	return nil
}

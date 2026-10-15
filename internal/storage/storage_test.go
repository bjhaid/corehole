package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestEveryPoolConnectionGetsSQLiteSettings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		open    func(context.Context, string) (*SQLiteStore, error)
		writers int
	}{
		{"main", OpenMain, 4}, {"audit", OpenAudit, 1},
		{"sessions", OpenSessions, 1}, {"jobs", OpenJobs, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			store, err := tc.open(ctx, filepath.Join(t.TempDir(), "db with ? and #.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close(ctx) }()
			if store.ReadDB() != store.DB() && store.ReadDB().Stats().MaxOpenConnections != 10 {
				t.Fatal("dedicated reader pools must allow ten concurrent connections")
			}
			for _, pool := range []struct {
				db             *sql.DB
				size, readOnly int
			}{
				{store.DB(), tc.writers, 0},
				{store.ReadDB(), store.ReadDB().Stats().MaxOpenConnections, boolInt(store.ReadDB() != store.DB())},
			} {
				var conns []*sql.Conn
				for i := 0; i < pool.size; i++ {
					conn, err := pool.db.Conn(ctx)
					if err != nil {
						t.Fatal(err)
					}
					conns = append(conns, conn)
					defer func() { _ = conn.Close() }()
					for pragma, want := range map[string]int{"busy_timeout": 5000, "foreign_keys": 1, "query_only": pool.readOnly} {
						var got int
						if err := conn.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
							t.Fatal(err)
						}
						if got != want {
							t.Fatalf("connection %d %s = %d, want %d", i, pragma, got, want)
						}
					}
				}
				for _, conn := range conns {
					_ = conn.Close()
				}
			}
		})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestAuditReadersAndWriterMakeIndependentProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, err := OpenAudit(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close(ctx) }()
	if store.DB().Stats().MaxOpenConnections != 1 || store.ReadDB().Stats().MaxOpenConnections != 10 {
		t.Fatal("want one writer and ten readers")
	}
	if _, err := store.DB().ExecContext(ctx, "CREATE TABLE pool_probe (v INTEGER)"); err != nil {
		t.Fatal(err)
	}
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "INSERT INTO pool_probe VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < store.ReadDB().Stats().MaxOpenConnections; i++ {
		conn, err := store.ReadDB().Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		var count int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pool_probe").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal("reader observed uncommitted write")
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO pool_probe VALUES (2)"); err == nil {
			t.Fatal("reader must reject writes")
		}
	}
	// All reader slots remain checked out; the writer must still commit.
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditMemoryStoreSharesSchemaWithReaders(t *testing.T) {
	ctx := context.Background()
	store, err := OpenAudit(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close(ctx) }()
	var count int
	if err := store.ReadDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events").Scan(&count); err != nil {
		t.Fatal(err)
	}
}

func TestReaderPoolLimitsAreConfigurable(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(context.Context, string) (*SQLiteStore, error)
	}{
		{"main", OpenMain}, {"audit", OpenAudit}, {"sessions", OpenSessions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			store, err := tc.open(ctx, filepath.Join(t.TempDir(), "db.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close(ctx) }()
			writers := store.DB().Stats().MaxOpenConnections
			for _, limit := range []int{15, 3} {
				if err := store.SetReaderConnections(limit); err != nil {
					t.Fatal(err)
				}
				if store.ReadDB().Stats().MaxOpenConnections != limit {
					t.Fatal("reader limit not applied")
				}
				if store.DB().Stats().MaxOpenConnections != writers {
					t.Fatal("reader setting changed writer pool")
				}
			}
			for _, invalid := range []int{0, -1} {
				if err := store.SetReaderConnections(invalid); err == nil {
					t.Fatal("nonpositive limit accepted")
				}
				if store.ReadDB().Stats().MaxOpenConnections != 3 {
					t.Fatal("invalid limit changed pool")
				}
			}
		})
	}
}

func TestOpenConfiguresSQLiteAndAppliesMigrations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	var journalMode string
	if err := store.DB().QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}

	var busyTimeout int
	if err := store.DB().QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", busyTimeout)
	}

	assertTableExists(t, ctx, store, "schema_migrations")
	assertTableExists(t, ctx, store, "audit_events")
	assertTableExists(t, ctx, store, "audit_action_totals")
	assertTableExists(t, ctx, store, "admin_users")
	assertTableExists(t, ctx, store, "app_config")
	assertTableExists(t, ctx, store, "local_dns_records")
	assertTableExists(t, ctx, store, "filter_lists")
	assertTableExists(t, ctx, store, "filter_list_entries")
	assertTableExists(t, ctx, store, "filter_rules")
	assertTableExists(t, ctx, store, "filter_clients")
	assertTableExists(t, ctx, store, "filter_groups")
	assertTableExists(t, ctx, store, "filter_client_groups")
	assertTableExists(t, ctx, store, "filter_list_groups")
	assertTableExists(t, ctx, store, "filter_rule_groups")
	assertTableExists(t, ctx, store, "audit_settings")
	assertTableExists(t, ctx, store, "api_keys")
	assertTableExists(t, ctx, store, "admin_sessions")

	for _, version := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13} {
		var migrations int
		if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&migrations); err != nil {
			t.Fatalf("query schema_migrations version %d: %v", version, err)
		}
		if migrations != 1 {
			t.Fatalf("migration version %d rows = %d, want 1", version, migrations)
		}
	}

	for _, index := range []string{
		"audit_events_timestamp_idx",
		"audit_events_client_ip_idx",
		"audit_events_query_name_idx",
		"audit_events_query_type_idx",
		"audit_events_action_idx",
		"audit_events_response_idx",
		"audit_events_rule_id_idx",
		"audit_events_blocklist_id_idx",
		"audit_events_duration_ns_idx",
		"audit_events_client_ip_timestamp_idx",
		"audit_events_query_name_timestamp_idx",
		"audit_events_action_timestamp_idx",
		"audit_events_upstream_resolver_idx",
		"audit_events_cache_status_idx",
		"audit_events_forward_duration_ns_idx",
		"audit_events_retry_count_idx",
		"audit_events_timestamp_action_idx",
		"audit_events_timestamp_cache_status_idx",
		"audit_events_timestamp_query_name_idx",
		"audit_events_timestamp_action_query_name_idx",
		"audit_events_timestamp_client_ip_idx",
		"audit_events_timestamp_action_client_ip_idx",
		"admin_sessions_expires_at_idx",
	} {
		assertIndexExists(t, ctx, store, index)
	}
	for _, column := range []string{
		"upstream_resolver",
		"cache_status",
		"forward_duration_ns",
		"retry_count",
		"forward_error",
	} {
		assertColumnExists(t, ctx, store, "audit_events", column)
	}
}

func TestOpenMainAppliesOnlyMainMigrations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")

	store, err := OpenMain(ctx, path)
	if err != nil {
		t.Fatalf("OpenMain() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	for _, table := range []string{
		"schema_migrations",
		"admin_users",
		"app_config",
		"local_dns_records",
		"filter_lists",
		"filter_list_entries",
		"filter_rules",
		"filter_clients",
		"filter_groups",
		"filter_client_groups",
		"filter_list_groups",
		"filter_rule_groups",
		"api_keys",
		"admin_sessions",
	} {
		assertTableExists(t, ctx, store, table)
	}
	for _, table := range []string{"audit_events", "audit_action_totals", "audit_settings"} {
		assertTableMissing(t, ctx, store, table)
	}
	for _, version := range []int{2, 3, 4, 5, 7, 11} {
		assertMigrationExists(t, ctx, store, version)
	}
	for _, version := range []int{1, 6, 8, 9, 10, 12, 13} {
		assertMigrationMissing(t, ctx, store, version)
	}
}

func TestOpenAuditAppliesOnlyAuditMigrations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole-audit.db")

	store, err := OpenAudit(ctx, path)
	if err != nil {
		t.Fatalf("OpenAudit() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	for _, table := range []string{
		"schema_migrations",
		"audit_events",
		"audit_action_totals",
		"audit_settings",
	} {
		assertTableExists(t, ctx, store, table)
	}
	for _, table := range []string{
		"admin_users",
		"app_config",
		"local_dns_records",
		"filter_lists",
		"api_keys",
		"admin_sessions",
	} {
		assertTableMissing(t, ctx, store, table)
	}
	for _, version := range []int{1, 6, 8, 9, 10, 12, 13} {
		assertMigrationExists(t, ctx, store, version)
	}
	for _, version := range []int{2, 3, 4, 5, 7, 11} {
		assertMigrationMissing(t, ctx, store, version)
	}
}

func TestAdminUsersTableAllowsExactlyOneAdmin(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	if _, err := store.DB().ExecContext(ctx, "INSERT INTO admin_users (id, password_hash, created_at) VALUES (1, 'hash', 'now')"); err != nil {
		t.Fatalf("insert admin user: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, "INSERT INTO admin_users (id, password_hash, created_at) VALUES (2, 'hash', 'now')"); err == nil {
		t.Fatal("insert second admin user succeeded, want constraint error")
	}

	var count int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_users").Scan(&count); err != nil {
		t.Fatalf("query admin_users: %v", err)
	}
	if count != 1 {
		t.Fatalf("admin_users rows = %d, want 1", count)
	}
}

func TestOpenMigrationsAreIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if err := store.Close(ctx); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	store, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("second Close() error = %v", err)
		}
	}()

	var migrations int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&migrations); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if migrations != 13 {
		t.Fatalf("migration rows = %d, want 13", migrations)
	}
}

func TestAuditActionTotalsMigrationBackfillsExistingEvents(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")
	prepareVersion8AuditDB(t, ctx, path)

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	assertTableExists(t, ctx, store, "audit_action_totals")
	assertActionTotal(t, ctx, store, "allow", 1)
	assertActionTotal(t, ctx, store, "block", 2)

	var migrations int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = 9").Scan(&migrations); err != nil {
		t.Fatalf("query schema_migrations version 9: %v", err)
	}
	if migrations != 1 {
		t.Fatalf("migration version 9 rows = %d, want 1", migrations)
	}
}

func TestAuditSettingsDefaults(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	var retentionNS int64
	var privacyLevel int
	if err := store.DB().QueryRowContext(ctx, `
SELECT retention_duration_ns, privacy_level
FROM audit_settings
WHERE id = 1`).Scan(&retentionNS, &privacyLevel); err != nil {
		t.Fatalf("query audit_settings: %v", err)
	}
	if retentionNS != int64(48*time.Hour) || privacyLevel != 0 {
		t.Fatalf("audit settings = retention %d privacy %d, want 48h/0", retentionNS, privacyLevel)
	}
}

func TestAuditRetentionMigrationBoundsExistingDisabledRetention(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")
	prepareVersion12AuditSettingsDB(t, ctx, path)

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	var retentionNS int64
	if err := store.DB().QueryRowContext(ctx, `
SELECT retention_duration_ns
FROM audit_settings
WHERE id = 1`).Scan(&retentionNS); err != nil {
		t.Fatalf("query audit_settings: %v", err)
	}
	if retentionNS != int64(48*time.Hour) {
		t.Fatalf("audit retention = %d, want 48h", retentionNS)
	}
}

func TestAPIKeysTableStoresOnlyMetadataAndHash(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	_, err = store.DB().ExecContext(ctx, `
INSERT INTO api_keys (name, key_hash, prefix, last4, created_at)
VALUES ('automation', 'digest', 'ch_abcdefghi', 'wxyz', 'now')`)
	if err != nil {
		t.Fatalf("insert api key metadata: %v", err)
	}

	var count int
	if err := store.DB().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM api_keys
WHERE name = 'automation'
	AND key_hash = 'digest'
	AND prefix = 'ch_abcdefghi'
	AND last4 = 'wxyz'
	AND disabled = 0
	AND revoked_at = ''
	AND last_used_at = ''`).Scan(&count); err != nil {
		t.Fatalf("query api_keys: %v", err)
	}
	if count != 1 {
		t.Fatalf("api_keys matching metadata rows = %d, want 1", count)
	}
}

func prepareVersion12AuditSettingsDB(t *testing.T, ctx context.Context, path string) {
	t.Helper()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close sqlite: %v", err)
		}
	}()

	statements := []string{
		`CREATE TABLE schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TEXT NOT NULL
)`,
		`CREATE TABLE audit_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	retention_duration_ns INTEGER NOT NULL DEFAULT 0 CHECK (retention_duration_ns >= 0),
	privacy_level INTEGER NOT NULL DEFAULT 0 CHECK (privacy_level >= 0 AND privacy_level <= 2),
	updated_at TEXT NOT NULL
)`,
		`INSERT INTO audit_settings (id, retention_duration_ns, privacy_level, updated_at)
VALUES (1, 0, 0, '2026-08-10T12:00:00Z')`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("prepare version 12 db: %v", err)
		}
	}
	for version := 1; version <= 12; version++ {
		if _, err := db.ExecContext(ctx, `
INSERT INTO schema_migrations (version, name, applied_at)
VALUES (?, ?, '2026-08-10T12:00:00Z')`, version, "applied"); err != nil {
			t.Fatalf("insert migration version %d: %v", version, err)
		}
	}
}

func prepareVersion8AuditDB(t *testing.T, ctx context.Context, path string) {
	t.Helper()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close sqlite: %v", err)
		}
	}()

	statements := []string{
		`CREATE TABLE schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TEXT NOT NULL
)`,
		`CREATE TABLE audit_events (
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
		`CREATE TABLE audit_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	retention_duration_ns INTEGER NOT NULL DEFAULT 0 CHECK (retention_duration_ns >= 0),
	privacy_level INTEGER NOT NULL DEFAULT 0 CHECK (privacy_level >= 0 AND privacy_level <= 2),
	updated_at TEXT NOT NULL
)`,
		`INSERT INTO audit_settings (id, retention_duration_ns, privacy_level, updated_at)
VALUES (1, 0, 0, '2026-08-10T12:00:00Z')`,
		`INSERT INTO audit_events (
	timestamp,
	client_ip,
	query_name,
	query_type,
	action,
	reason,
	rule_id,
	blocklist_id,
	response,
	duration_ns
) VALUES
	('2026-08-10T12:00:00Z', '192.0.2.10', 'one.example.', 1, 'allow', '', 0, 0, 'NOERROR', 1000),
	('2026-08-10T12:00:01Z', '192.0.2.10', 'two.example.', 1, 'block', '', 0, 0, 'NXDOMAIN', 1000),
	('2026-08-10T12:00:02Z', '192.0.2.10', 'three.example.', 1, 'block', '', 0, 0, 'NXDOMAIN', 1000)`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("prepare version 8 db: %v", err)
		}
	}
	for version := 1; version <= 8; version++ {
		if _, err := db.ExecContext(ctx, `
INSERT INTO schema_migrations (version, name, applied_at)
VALUES (?, ?, '2026-08-10T12:00:00Z')`, version, "applied"); err != nil {
			t.Fatalf("insert migration version %d: %v", version, err)
		}
	}
}

func assertTableExists(t *testing.T, ctx context.Context, store *SQLiteStore, table string) {
	t.Helper()

	var count int
	if err := store.DB().QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
		table,
	).Scan(&count); err != nil {
		t.Fatalf("query sqlite_master for %s: %v", table, err)
	}
	if count != 1 {
		t.Fatalf("table %s exists count = %d, want 1", table, count)
	}
}

func assertTableMissing(t *testing.T, ctx context.Context, store *SQLiteStore, table string) {
	t.Helper()

	var count int
	if err := store.DB().QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
		table,
	).Scan(&count); err != nil {
		t.Fatalf("query sqlite_master for %s: %v", table, err)
	}
	if count != 0 {
		t.Fatalf("table %s exists count = %d, want 0", table, count)
	}
}

func assertMigrationExists(t *testing.T, ctx context.Context, store *SQLiteStore, version int) {
	t.Helper()

	var migrations int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&migrations); err != nil {
		t.Fatalf("query schema_migrations version %d: %v", version, err)
	}
	if migrations != 1 {
		t.Fatalf("migration version %d rows = %d, want 1", version, migrations)
	}
}

func assertMigrationMissing(t *testing.T, ctx context.Context, store *SQLiteStore, version int) {
	t.Helper()

	var migrations int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&migrations); err != nil {
		t.Fatalf("query schema_migrations version %d: %v", version, err)
	}
	if migrations != 0 {
		t.Fatalf("migration version %d rows = %d, want 0", version, migrations)
	}
}

func assertActionTotal(t *testing.T, ctx context.Context, store *SQLiteStore, action string, want int64) {
	t.Helper()

	var got int64
	if err := store.DB().QueryRowContext(
		ctx,
		"SELECT count FROM audit_action_totals WHERE action = ?",
		action,
	).Scan(&got); err != nil {
		t.Fatalf("query audit action total %q: %v", action, err)
	}
	if got != want {
		t.Fatalf("audit action total %q = %d, want %d", action, got, want)
	}
}

func assertIndexExists(t *testing.T, ctx context.Context, store *SQLiteStore, index string) {
	t.Helper()

	var count int
	if err := store.DB().QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?",
		index,
	).Scan(&count); err != nil {
		t.Fatalf("query sqlite_master for %s: %v", index, err)
	}
	if count != 1 {
		t.Fatalf("index %s exists count = %d, want 1", index, count)
	}
}

func assertColumnExists(t *testing.T, ctx context.Context, store *SQLiteStore, table string, column string) {
	t.Helper()

	rows, err := store.DB().QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		t.Fatalf("query table info for %s: %v", table, err)
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			t.Fatalf("scan table info for %s: %v", table, err)
		}
		if name == column {
			return
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read table info for %s: %v", table, err)
	}
	t.Fatalf("table %s missing column %s", table, column)
}

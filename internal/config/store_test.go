package config_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/bjhaid/corehole/internal/config"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/bjhaid/corehole/internal/storage"
)

func TestPersistedReaderConnectionConfiguration(t *testing.T) {
	ctx := context.Background()
	db, err := storage.OpenMain(ctx, filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	store := config.NewSQLiteStore(db.DB())
	cfg := config.Default()
	cfg.Storage.MainReadConnections, cfg.Storage.AuditReadConnections, cfg.Storage.SessionReadConnections = 12, 20, 15
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	bootstrap := config.Default()
	bootstrap.Storage.MainReadConnections = 99
	result, err := config.InitializeStoreWithSource(ctx, store, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if result.Source != config.SourcePersisted || result.Config.Storage != cfg.Storage {
		t.Fatalf("persisted config not authoritative: %#v", result)
	}
	// Old persisted JSON has no pool settings: decode over the new defaults.
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	fields := payload["storage"].(map[string]any)
	for _, field := range []string{"main_read_connections", "audit_read_connections", "session_read_connections"} {
		delete(fields, field)
	}
	encoded, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, "UPDATE app_config SET payload=? WHERE id=1", string(encoded)); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Storage.MainReadConnections != 10 || loaded.Storage.AuditReadConnections != 10 || loaded.Storage.SessionReadConnections != 10 {
		t.Fatalf("legacy defaults = %#v", loaded.Storage)
	}
	fields["audit_read_connections"] = 0
	encoded, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, "UPDATE app_config SET payload=? WHERE id=1", string(encoded)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx); err == nil {
		t.Fatal("invalid persisted reader limit accepted")
	}
}

func TestSQLiteStoreInitializeSaveLoad(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	store := config.NewSQLiteStore(db.DB())
	bootstrap := config.Default()
	bootstrap.DNS.Listen = ":5353"
	bootstrap.Storage.Path = filepath.Join(t.TempDir(), "corehole.db")
	bootstrap.Blocking.Blocklists = []string{"ads.txt"}

	initialized, err := config.InitializeStore(ctx, store, bootstrap)
	if err != nil {
		t.Fatalf("InitializeStore() error = %v", err)
	}
	if initialized.DNS.Listen != ":5353" {
		t.Fatalf("initialized dns.listen = %q, want :5353", initialized.DNS.Listen)
	}

	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load() after initialize error = %v", err)
	}
	if loaded.DNS.Listen != ":5353" || loaded.Blocking.Blocklists[0] != "ads.txt" {
		t.Fatalf("loaded config = %#v, want bootstrap values", loaded)
	}

	updated := loaded
	updated.DNS.Resolvers = []config.Resolver{{
		Name:     "quad9",
		Address:  "9.9.9.9:53",
		Protocol: "udp",
		Enabled:  true,
	}}
	updated.Blocking.Response = coreholedns.BlockingResponseRefused
	if err := store.Save(ctx, updated); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	reloaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load() after save error = %v", err)
	}
	if reloaded.DNS.Resolvers[0].Name != "quad9" || reloaded.Blocking.Response != coreholedns.BlockingResponseRefused {
		t.Fatalf("reloaded config = %#v, want saved values", reloaded)
	}
}

func TestSQLiteStoreLoadMapsLegacyCacheTTLToSplitTTLs(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	_, err = db.DB().ExecContext(ctx, `
INSERT INTO app_config (id, payload, updated_at)
VALUES (1, ?, datetime('now'))`,
		`{
			"dns": {
				"listen": ":5353",
				"cache_ttl": 0,
				"cache_success_capacity": 0,
				"cache_denial_capacity": 0,
				"resolvers": [{"name": "cloudflare", "address": "1.1.1.1:53", "protocol": "udp", "enabled": true}]
			},
			"admin": {"listen": "127.0.0.1:8080"},
			"storage": {"path": "corehole.db"},
			"blocking": {"response": "nxdomain", "bundled": true, "blocklists": []},
			"logging": {"level": "info", "format": "text"}
		}`)
	if err != nil {
		t.Fatalf("insert legacy config: %v", err)
	}

	loaded, err := config.NewSQLiteStore(db.DB()).Load(ctx)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.DNS.CacheEnabled() {
		t.Fatalf("cache enabled = true, want legacy cache_ttl: 0 to disable cache: %#v", loaded.DNS)
	}
	if loaded.Storage.AuditPath != "corehole-audit.db" {
		t.Fatalf("storage.audit_path = %q, want derived legacy audit path", loaded.Storage.AuditPath)
	}
}

func TestInitializeStoreKeepsExistingConfig(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	store := config.NewSQLiteStore(db.DB())
	existing := config.Default()
	existing.DNS.Listen = ":5353"
	if err := store.Save(ctx, existing); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	bootstrap := config.Default()
	bootstrap.DNS.Listen = ":9999"
	initialized, err := config.InitializeStore(ctx, store, bootstrap)
	if err != nil {
		t.Fatalf("InitializeStore() error = %v", err)
	}
	if initialized.DNS.Listen != ":5353" {
		t.Fatalf("initialized dns.listen = %q, want existing :5353", initialized.DNS.Listen)
	}
}

func TestInitializeStoreWithSourceReportsActiveSource(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	store := config.NewSQLiteStore(db.DB())
	bootstrap := config.Default()
	bootstrap.Storage.Path = filepath.Join(t.TempDir(), "corehole.db")
	first, err := config.InitializeStoreWithSource(ctx, store, bootstrap)
	if err != nil {
		t.Fatalf("first InitializeStoreWithSource() error = %v", err)
	}
	if first.Source != config.SourceBootstrap {
		t.Fatalf("first source = %q, want %q", first.Source, config.SourceBootstrap)
	}

	changedBootstrap := bootstrap
	changedBootstrap.Blocking.Blocklists = []string{"changed.txt"}
	second, err := config.InitializeStoreWithSource(ctx, store, changedBootstrap)
	if err != nil {
		t.Fatalf("second InitializeStoreWithSource() error = %v", err)
	}
	if second.Source != config.SourcePersisted {
		t.Fatalf("second source = %q, want %q", second.Source, config.SourcePersisted)
	}
	if len(second.Config.Blocking.Blocklists) != 0 {
		t.Fatalf("blocklists = %#v, want persisted empty list", second.Config.Blocking.Blocklists)
	}
}

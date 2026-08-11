package config_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bjhaid/corehole/internal/config"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/bjhaid/corehole/internal/storage"
)

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

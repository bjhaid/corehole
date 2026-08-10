package app

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/blocklist"
	"github.com/bjhaid/corehole/internal/config"
	"github.com/bjhaid/corehole/internal/coreplugin"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/bjhaid/corehole/internal/filter"
	"github.com/bjhaid/corehole/internal/localdns"
	"github.com/bjhaid/corehole/internal/storage"
	"github.com/miekg/dns"
)

func TestStartupConfigLocalBlocklistBlocksAdzerk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	blocklistPath := filepath.Join(dir, "ads.txt")
	if err := os.WriteFile(blocklistPath, []byte("adzerk.com\n0.0.0.0 hosts-format.example\n"), 0o600); err != nil {
		t.Fatalf("write blocklist: %v", err)
	}

	bootstrap := testConfig(filepath.Join(dir, "corehole.db"))
	bootstrap.Blocking.Blocklists = []string{blocklistPath}

	store, err := storage.Open(ctx, bootstrap.Storage.Path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer closeStore(t, ctx, store)

	result, err := config.InitializeStoreWithSource(ctx, config.NewSQLiteStore(store.DB()), bootstrap)
	if err != nil {
		t.Fatalf("InitializeStoreWithSource() error = %v", err)
	}
	if result.Source != config.SourceBootstrap {
		t.Fatalf("source = %q, want %q", result.Source, config.SourceBootstrap)
	}

	manager := blocklist.NewManagerWithBundled(result.Config.Blocking.Blocklists, result.Config.Blocking.Bundled)
	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	assertBlockDecision(t, manager, "adzerk.com")
	assertBlockDecision(t, manager, "hosts-format.example")
}

func TestStartupConfigPersistedConfigHidesChangedYAMLBlocklists(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "corehole.db")
	blocklistPath := filepath.Join(dir, "ads.txt")
	if err := os.WriteFile(blocklistPath, []byte("adzerk.com\n"), 0o600); err != nil {
		t.Fatalf("write blocklist: %v", err)
	}

	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer closeStore(t, ctx, store)

	cfgStore := config.NewSQLiteStore(store.DB())
	persisted := testConfig(dbPath)
	if err := cfgStore.Save(ctx, persisted); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	bootstrap := testConfig(dbPath)
	bootstrap.Blocking.Blocklists = []string{blocklistPath}
	result, err := config.InitializeStoreWithSource(ctx, cfgStore, bootstrap)
	if err != nil {
		t.Fatalf("InitializeStoreWithSource() error = %v", err)
	}
	if result.Source != config.SourcePersisted {
		t.Fatalf("source = %q, want %q", result.Source, config.SourcePersisted)
	}
	if len(result.Config.Blocking.Blocklists) != 0 {
		t.Fatalf("active blocklists = %#v, want persisted empty list", result.Config.Blocking.Blocklists)
	}

	manager := blocklist.NewManagerWithBundled(result.Config.Blocking.Blocklists, result.Config.Blocking.Bundled)
	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	decision := manager.Decide(ctx, coreholedns.Query{Name: "adzerk.com"})
	if decision.Action != coreholedns.ActionAllow {
		t.Fatalf("decision for adzerk.com = %q (%s), want allow from persisted config without YAML blocklist", decision.Action, decision.Reason)
	}
}

func TestStartupLogsReportRuntimeBlocklistSources(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOutput)

	cfg := testConfig("corehole.db")
	stats := filter.BlocklistRuntimeStats{
		EnabledLists:         1,
		ImportedEnabledLists: 1,
		EnabledEntries:       1,
	}
	snapshot := blocklist.Snapshot{
		Paths:      nil,
		Bundled:    false,
		EntryCount: 1,
		Status:     blocklist.ReloadStatusOK,
	}

	logConfigSource("corehole.yaml", config.SourcePersisted, cfg, cfg, stats)
	logStartup("corehole.yaml", config.SourcePersisted, cfg, snapshot, stats)

	got := buf.String()
	for _, want := range []string{
		"active_yaml_blocklist_paths=0",
		"yaml_blocklist_paths=0",
		"bundled_enabled=false",
		"db_filter_lists_enabled=1",
		"db_filter_lists_imported=1",
		"db_filter_entries_enabled=1",
		"runtime_entries=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("startup logs missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "blocklists=0") || strings.Contains(got, "active_blocklists=0") {
		t.Fatalf("startup logs still contain misleading blocklist zero count:\n%s", got)
	}
}

func TestFilterListRefreshReloadsInstalledRuntimeDecider(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "adlist.txt")
	if err := os.WriteFile(path, []byte("adzerk.com\n"), 0o600); err != nil {
		t.Fatalf("write adlist: %v", err)
	}

	store, err := storage.Open(ctx, filepath.Join(dir, "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer closeStore(t, ctx, store)

	repo := filter.NewRepository(store.DB())
	service := filter.NewService(repo)
	manager := blocklist.NewManagerWithBundledAndSources(nil, false, filter.NewBlocklistSource(repo))
	runtime := coreplugin.Current()
	runtime.SetDecider(coreplugin.AllowAll{})
	t.Cleanup(func() {
		runtime.SetDecider(coreplugin.AllowAll{})
	})

	list, err := service.CreateList(ctx, filter.List{
		Path:    path,
		Kind:    filter.KindDeny,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateList() error = %v", err)
	}
	if _, err := service.RefreshList(ctx, list.ID); err != nil {
		t.Fatalf("RefreshList() error = %v", err)
	}
	reloader := runtimeBlocklistReloader{manager: manager, runtime: runtime}
	if err := reloader.Reload(ctx); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	decision := runtime.Decide(ctx, coreholedns.Query{Name: "adzerk.com."})
	if decision.Action != coreholedns.ActionBlock {
		t.Fatalf("runtime decision for adzerk.com. = %q (%s), want block", decision.Action, decision.Reason)
	}

	list.Enabled = false
	if _, err := service.UpdateList(ctx, list); err != nil {
		t.Fatalf("UpdateList() error = %v", err)
	}
	if err := reloader.Reload(ctx); err != nil {
		t.Fatalf("Reload() after disable error = %v", err)
	}
	decision = runtime.Decide(ctx, coreholedns.Query{Name: "adzerk.com."})
	if decision.Action != coreholedns.ActionAllow {
		t.Fatalf("runtime decision for disabled adzerk.com. = %q (%s), want allow", decision.Action, decision.Reason)
	}
}

func TestDNSRuntimeReloaderInvokesCoreDNSServerReload(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig("corehole.db")
	server := &fakeCoreDNSServer{}
	reloader := dnsRuntimeReloader{server: server}

	if err := reloader.ReloadDNS(ctx, cfg); err != nil {
		t.Fatalf("ReloadDNS() error = %v", err)
	}
	if server.reloadCount != 1 {
		t.Fatalf("reloadCount = %d, want 1", server.reloadCount)
	}
	if server.last.DNS.Listen != cfg.DNS.Listen {
		t.Fatalf("reloaded config DNS listen = %q, want %q", server.last.DNS.Listen, cfg.DNS.Listen)
	}
}

func TestBlockingRuntimeControllerPausePersistsAndUpdatesRuntime(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "corehole.db")
	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer closeStore(t, ctx, store)

	cfg := testConfig(dbPath)
	cfgStore := config.NewSQLiteStore(store.DB())
	if err := cfgStore.Save(ctx, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	runtime := coreplugin.NewRuntime()
	controller := blockingRuntimeController{store: cfgStore, runtime: runtime}
	until := time.Now().Add(10 * time.Minute).UTC()
	status, err := controller.Pause(ctx, until)
	if err != nil {
		t.Fatalf("Pause() error = %v", err)
	}
	if !status.Paused || status.Indefinite || status.PauseUntil == "" {
		t.Fatalf("pause status = %#v, want timed pause", status)
	}
	if !runtime.BlockingPause().Active(time.Now()) {
		t.Fatal("runtime blocking pause is not active")
	}

	reloaded, err := cfgStore.Load(ctx)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reloaded.Blocking.Paused || reloaded.Blocking.PauseUntil == "" {
		t.Fatalf("persisted blocking config = %#v, want timed pause", reloaded.Blocking)
	}
}

func TestBlockingRuntimeControllerResumePersistsAndUpdatesRuntime(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "corehole.db")
	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer closeStore(t, ctx, store)

	cfg := testConfig(dbPath)
	cfg.Blocking.Paused = true
	cfg.Blocking.PauseUntil = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	cfgStore := config.NewSQLiteStore(store.DB())
	if err := cfgStore.Save(ctx, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	runtime := coreplugin.NewRuntime()
	runtime.PauseBlocking(time.Time{})
	controller := blockingRuntimeController{store: cfgStore, runtime: runtime}
	status, err := controller.Resume(ctx)
	if err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if status.Paused {
		t.Fatalf("resume status = %#v, want unpaused", status)
	}
	if runtime.BlockingPause().Enabled {
		t.Fatal("runtime blocking pause still enabled")
	}

	reloaded, err := cfgStore.Load(ctx)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if reloaded.Blocking.Paused || reloaded.Blocking.PauseUntil != "" {
		t.Fatalf("persisted blocking config = %#v, want unpaused", reloaded.Blocking)
	}
}

func TestApplyBlockingPauseIgnoresExpiredTimedPause(t *testing.T) {
	runtime := coreplugin.NewRuntime()
	cfg := config.BlockingConfig{
		Paused:     true,
		PauseUntil: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
	}

	applyBlockingPause(runtime, cfg)

	if runtime.BlockingPause().Enabled {
		t.Fatal("expired blocking pause still enabled")
	}
}

func TestLocalDNSRuntimeReloaderInstallsStaticRuntimeSnapshot(t *testing.T) {
	ctx := context.Background()
	runtime := coreplugin.NewRuntime()
	store := staticEnabledLocalDNSStore{records: []localdns.Record{
		{
			Name:    "router.lan",
			Type:    localdns.TypeA,
			Value:   "192.0.2.1",
			TTL:     60,
			Enabled: true,
		},
	}}
	reloader := localDNSRuntimeReloader{store: store, runtime: runtime}

	if err := reloader.ReloadLocalDNS(ctx); err != nil {
		t.Fatalf("ReloadLocalDNS() error = %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("router.lan.", dns.TypeA)
	res, ok, err := runtime.ResolveLocal(ctx, req)
	if err != nil {
		t.Fatalf("ResolveLocal() error = %v", err)
	}
	if !ok || len(res.Answer) != 1 {
		t.Fatalf("ResolveLocal() ok=%t answers=%d, want one local answer", ok, len(res.Answer))
	}
}

func TestLocalDNSRuntimeSnapshotDoesNotReadStoreDuringResolution(t *testing.T) {
	ctx := context.Background()
	runtime := coreplugin.NewRuntime()
	store := &countingEnabledLocalDNSStore{records: []localdns.Record{
		{
			Name:    "router.lan",
			Type:    localdns.TypeA,
			Value:   "192.0.2.1",
			TTL:     60,
			Enabled: true,
		},
	}}
	reloader := localDNSRuntimeReloader{store: store, runtime: runtime}

	if err := reloader.ReloadLocalDNS(ctx); err != nil {
		t.Fatalf("ReloadLocalDNS() error = %v", err)
	}
	store.records = nil

	req := new(dns.Msg)
	req.SetQuestion("router.lan.", dns.TypeA)
	for i := 0; i < 100; i++ {
		res, ok, err := runtime.ResolveLocal(ctx, req)
		if err != nil {
			t.Fatalf("ResolveLocal() error = %v", err)
		}
		if !ok || len(res.Answer) != 1 {
			t.Fatalf("ResolveLocal() ok=%t answers=%d, want one local answer", ok, len(res.Answer))
		}
	}
	if store.calls != 1 {
		t.Fatalf("ListEnabled calls = %d, want only the initial reload call", store.calls)
	}
}

type staticEnabledLocalDNSStore struct {
	records []localdns.Record
}

func (s staticEnabledLocalDNSStore) ListEnabled(context.Context) ([]localdns.Record, error) {
	return append([]localdns.Record(nil), s.records...), nil
}

type countingEnabledLocalDNSStore struct {
	records []localdns.Record
	calls   int
}

func (s *countingEnabledLocalDNSStore) ListEnabled(context.Context) ([]localdns.Record, error) {
	s.calls++
	return append([]localdns.Record(nil), s.records...), nil
}

func testConfig(dbPath string) config.Config {
	cfg := config.Default()
	cfg.DNS.Listen = ":1053"
	cfg.Admin.Listen = "127.0.0.1:0"
	cfg.Storage.Path = dbPath
	cfg.Blocking.Bundled = false
	cfg.Blocking.Blocklists = nil
	return cfg
}

func assertBlockDecision(t *testing.T, decider coreholedns.Decider, query string) {
	t.Helper()

	decision := decider.Decide(context.Background(), coreholedns.Query{Name: query})
	if decision.Action != coreholedns.ActionBlock {
		t.Fatalf("decision for %q = %q (%s), want block", query, decision.Action, decision.Reason)
	}
}

func closeStore(t *testing.T, ctx context.Context, store *storage.SQLiteStore) {
	t.Helper()

	if err := store.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type fakeCoreDNSServer struct {
	reloadCount int
	last        config.Config
}

func (s *fakeCoreDNSServer) Reload(_ context.Context, cfg config.Config) error {
	s.reloadCount++
	s.last = cfg
	return nil
}

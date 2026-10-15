package app

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/audit"
	"github.com/bjhaid/corehole/internal/blocklist"
	"github.com/bjhaid/corehole/internal/config"
	"github.com/bjhaid/corehole/internal/coreplugin"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/bjhaid/corehole/internal/filter"
	"github.com/bjhaid/corehole/internal/localdns"
	"github.com/bjhaid/corehole/internal/storage"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func TestServeForwardsWhenFilterPluginCannotLoad(t *testing.T) {
	upstreamSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &dns.Server{PacketConn: upstreamSocket, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		res := new(dns.Msg)
		res.SetReply(req)
		res.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.123")}}
		_ = w.WriteMsg(res)
	})}
	go func() { _ = upstream.ActivateAndServe() }()
	defer func() { _ = upstream.Shutdown() }()
	reserveDNS, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsPort := reserveDNS.LocalAddr().(*net.UDPAddr).Port
	_ = reserveDNS.Close()
	reserveAdmin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminAddr := reserveAdmin.Addr().String()
	_ = reserveAdmin.Close()
	cfg := testConfig(filepath.Join(t.TempDir(), "corehole.db"))
	cfg.DNS.Listen = fmt.Sprintf(":%d", dnsPort)
	cfg.DNS.Resolvers[0].Address = upstreamSocket.LocalAddr().String()
	cfg.Admin.Listen = adminAddr
	cfg.Blocking.Blocklists = []string{filepath.Join(t.TempDir(), "unavailable-list.txt")}
	// An unavailable audit plugin must not prevent DNS forwarding either.
	cfg.Storage.AuditPath = t.TempDir()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "corehole.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- Serve(ctx, []string{"--config", path}) }()
	defer func() {
		cancel()
		select {
		case err := <-stopped:
			if err != nil {
				t.Errorf("Serve shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop")
		}
		coreplugin.Current().SetDecider(coreplugin.AllowAll{})
		coreplugin.Current().SetLocalResolver(nil)
		coreplugin.Current().SetAudit(audit.NoopSink{})
	}()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := client.Get("http://" + adminAddr + "/api/status")
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("admin listener did not become ready despite optional plugin failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
	query := new(dns.Msg)
	query.SetQuestion("forward.example.", dns.TypeA)
	res, _, err := (&dns.Client{Timeout: time.Second}).Exchange(query, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 1 {
		t.Fatalf("fail-open DNS response: %s", res)
	}
	if answer, ok := res.Answer[0].(*dns.A); !ok || !answer.A.Equal(net.ParseIP("192.0.2.123")) {
		t.Fatalf("wrong upstream answer: %s", res)
	}
}

func TestFilterLoaderServesWhileBlockedAndActivatesWhenReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &delayedBlocklistSource{entered: make(chan struct{}), release: make(chan struct{})}
	manager := blocklist.NewManagerWithBundledAndSources(nil, false, source)
	runtime := coreplugin.NewRuntime()
	reloader := &runtimeBlocklistReloader{manager: manager, runtime: runtime}
	done := startPlugin(ctx, "filtering", reloader.Reload)
	<-source.entered
	select {
	case <-done:
		t.Fatal("loader completed before source was ready")
	default:
	}
	query := coreholedns.Query{Name: "ads.example."}
	if got := runtime.Decide(ctx, query); got.Action != coreholedns.ActionAllow {
		t.Fatalf("unready plugin must fail open: %+v", got)
	}
	close(source.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loader did not activate")
	}
	if got := runtime.Decide(ctx, query); got.Action != coreholedns.ActionBlock {
		t.Fatalf("ready plugin did not block: %+v", got)
	}
}

type delayedBlocklistSource struct{ entered, release chan struct{} }

func (s *delayedBlocklistSource) Entries(ctx context.Context) ([]blocklist.Entry, error) {
	close(s.entered)
	select {
	case <-s.release:
		return []blocklist.Entry{{Domain: "ads.example", Kind: blocklist.EntryExact}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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
	rules := filter.NewRuleDecider(repo, manager)
	if _, err := service.CreateRule(ctx, filter.Rule{Pattern: "blocked.example.org", Kind: filter.KindDeny, MatchType: filter.MatchSuffix, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	reloader := runtimeBlocklistReloader{manager: manager, rules: rules, runtime: runtime}
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
	decision = runtime.Decide(ctx, coreholedns.Query{Name: "blocked.example.org."})
	if decision.Action != coreholedns.ActionBlock || decision.RuleID == 0 {
		t.Fatalf("list reload lost custom rule decider: %+v", decision)
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

func TestRuntimeConfigApplierUpdatesBlockingResponse(t *testing.T) {
	cfg := testConfig("corehole.db")
	cfg.Blocking.Response = coreholedns.BlockingResponseRefused
	runtime := coreplugin.NewRuntime()

	if runtime.BlockingResponse() != coreholedns.BlockingResponseNullIP {
		t.Fatalf("initial blocking response = %q, want null-ip", runtime.BlockingResponse())
	}
	if err := (runtimeConfigApplier{runtime: runtime}).ApplyRuntimeConfig(context.Background(), cfg); err != nil {
		t.Fatalf("ApplyRuntimeConfig() error = %v", err)
	}
	if runtime.BlockingResponse() != coreholedns.BlockingResponseRefused {
		t.Fatalf("blocking response = %q, want refused", runtime.BlockingResponse())
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
	cfg.Storage.AuditPath = config.DefaultAuditPath(dbPath)
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

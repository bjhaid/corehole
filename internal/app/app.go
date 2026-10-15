package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/bjhaid/corehole/internal/admin"
	"github.com/bjhaid/corehole/internal/audit"
	"github.com/bjhaid/corehole/internal/blocklist"
	"github.com/bjhaid/corehole/internal/config"
	"github.com/bjhaid/corehole/internal/coredns"
	"github.com/bjhaid/corehole/internal/coreplugin"
	"github.com/bjhaid/corehole/internal/filter"
	"github.com/bjhaid/corehole/internal/localdns"
	coreholelog "github.com/bjhaid/corehole/internal/logging"
	"github.com/bjhaid/corehole/internal/storage"
)

var version = "dev"

func Version() string {
	return version
}

func PrintUsage(w io.Writer) error {
	_, err := fmt.Fprintln(w, "usage: corehole <serve|version> [options]")
	return err
}

func Serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "corehole.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	bootstrapCfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	store, err := storage.OpenMain(ctx, bootstrapCfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = store.Close(closeCtx)
	}()

	cfgStore := config.NewSQLiteStore(store.DB())
	initResult, err := config.InitializeStoreWithSource(ctx, cfgStore, bootstrapCfg)
	if err != nil {
		return fmt.Errorf("config store: %w", err)
	}
	cfg := initResult.Config
	if err := store.SetReaderConnections(cfg.Storage.MainReadConnections); err != nil {
		return fmt.Errorf("main reader pool: %w", err)
	}
	coreholelog.Configure(string(cfg.Logging.EffectiveLevel()), string(cfg.Logging.EffectiveFormat()))

	auditStore, err := storage.OpenAudit(ctx, cfg.Storage.AuditPath)
	if err == nil {
		if poolErr := auditStore.SetReaderConnections(cfg.Storage.AuditReadConnections); poolErr != nil {
			_ = auditStore.Close(ctx)
			err = poolErr
		}
	}
	var auditSink audit.Sink = audit.NoopSink{}
	var auditReader admin.AuditReader
	if err != nil {
		coreholelog.Warn("audit_unavailable", "fail_open", true, "error", err)
	} else {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = auditStore.Close(closeCtx)
		}()
		if err := audit.CopyLegacyMetadata(ctx, store.DB(), auditStore.DB()); err != nil {
			coreholelog.Warn("audit_legacy_metadata_unavailable", "error", err)
		}
		sink, err := audit.NewSQLiteSink(auditStore.DB(), audit.WithReaderDB(auditStore.ReadDB()))
		if err != nil {
			coreholelog.Warn("audit_unavailable", "fail_open", true, "error", err)
		} else {
			auditSink, auditReader = sink, sink
		}
	}

	blocklist.SetBundledDefault(cfg.Blocking.Bundled)
	runtime := coreplugin.Current()
	runtime.SetBlockingResponse(cfg.Blocking.Response)
	applyBlockingPause(runtime, cfg.Blocking)
	runtime.SetCacheEnabled(cfg.DNS.CacheEnabled())
	// Forward immediately until the background loaders install ready plugins.
	runtime.SetDecider(coreplugin.AllowAll{})
	runtime.SetLocalResolver(nil)
	filterRepo := filter.NewRepository(store.DB())
	filterService := filter.NewService(filterRepo)
	blocklistManager := blocklist.NewManagerWithBundledAndSources(cfg.Blocking.Blocklists, cfg.Blocking.Bundled, filter.NewBlocklistSource(filterRepo))
	ruleDecider := filter.NewRuleDecider(filterRepo, blocklistManager)
	filterReloader := &runtimeBlocklistReloader{manager: blocklistManager, rules: ruleDecider, runtime: runtime}

	runtime.SetAudit(auditSink)
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = auditSink.Close(closeCtx)
	}()

	localDNSRepo := localdns.NewSQLiteRepository(store.DB())
	localDNSReloader := localDNSRuntimeReloader{
		store:   localDNSRepo,
		runtime: runtime,
	}
	var refreshJobs *admin.RefreshJobs
	jobsStore, jobsErr := storage.OpenJobs(ctx, storage.JobsPath(cfg.Storage.Path))
	if jobsErr == nil {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = jobsStore.Close(closeCtx)
		}()
		refreshJobs, jobsErr = admin.NewRefreshJobs(ctx, filterService, filterReloader, jobsStore.DB())
	}
	if jobsErr != nil {
		coreholelog.Warn("refresh_jobs_unavailable", "error", jobsErr)
	}
	if refreshJobs != nil {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = refreshJobs.Close(closeCtx)
		}()
	}
	// Session writes must not wait for a large filter import's write lock.
	var sessions admin.SessionStore
	sessionStore, sessionErr := storage.OpenSessions(ctx, storage.SessionsPath(cfg.Storage.Path))
	if sessionErr == nil {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = sessionStore.Close(closeCtx)
		}()
		sessionErr = sessionStore.SetReaderConnections(cfg.Storage.SessionReadConnections)
		if sessionErr == nil {
			sessionErr = admin.CopyLegacySessions(ctx, store.ReadDB(), sessionStore.DB())
		}
		if sessionErr == nil {
			sessions = admin.NewSQLiteSessionStoreWithReader(sessionStore.DB(), sessionStore.ReadDB())
		}
	}
	if sessionErr != nil {
		coreholelog.Warn("sessions_unavailable", "error", sessionErr)
		// Keep DNS available, but fail closed for login/session creation.
		sessions = admin.NewUnavailableSessionStore()
	}
	adminListener, err := net.Listen("tcp", cfg.Admin.Listen)
	if err != nil {
		return fmt.Errorf("admin server listen %s: %w", cfg.Admin.Listen, err)
	}

	dnsServer, err := coredns.Start(ctx, cfg)
	if err != nil {
		_ = adminListener.Close()
		return fmt.Errorf("dns server: %w", err)
	}

	adminServer := &http.Server{
		Addr: cfg.Admin.Listen,
		Handler: admin.NewServer(
			admin.NewSQLiteUserStoreWithReader(store.DB(), store.ReadDB()),
			admin.WithSessionStore(sessions),
			admin.WithSecureCookie(false),
			admin.WithConfigSnapshot(adminConfigSnapshot(cfg)),
			admin.WithConfigStoreAndRuntime(cfgStore, dnsRuntimeReloader{server: dnsServer}, runtimeConfigApplier{runtime: runtime}),
			admin.WithBlockingController(blockingRuntimeController{
				store:   cfgStore,
				runtime: runtime,
			}),
			admin.WithAuditReader(auditReader),
			admin.WithLocalDNSStore(localDNSRepo),
			admin.WithLocalDNSReloader(localDNSReloader),
			admin.WithFilterService(filterService),
			admin.WithFilterReloader(filterReloader),
			admin.WithRefreshJobs(refreshJobs),
		),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		if err := adminServer.Serve(adminListener); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()

	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	pluginCtx, cancelPlugins := context.WithCancel(signalCtx)
	defer cancelPlugins()
	logListeners(*configPath, initResult.Source, cfg)
	filterReady := startPlugin(pluginCtx, "filtering", func(ctx context.Context) error {
		if err := filterReloader.Reload(ctx); err != nil {
			return err
		}
		stats, err := filterRepo.BlocklistRuntimeStats(ctx)
		if err != nil {
			coreholelog.Warn("filter_stats_unavailable", "error", err)
		}
		logConfigSource(*configPath, initResult.Source, bootstrapCfg, cfg, stats)
		logBlockingReady(cfg, blocklistManager.Snapshot(), stats)
		return nil
	})
	localReady := startPlugin(pluginCtx, "local_dns", localDNSReloader.ReloadLocalDNS)

	select {
	case <-signalCtx.Done():
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cancelPlugins()
	if refreshJobs != nil {
		if err := refreshJobs.Close(shutdownCtx); err != nil {
			coreholelog.Warn("refresh_jobs_shutdown", "error", err)
		}
	}
	if err := adminServer.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := dnsServer.Stop(shutdownCtx); err != nil {
		return err
	}
	for _, done := range []<-chan struct{}{filterReady, localReady} {
		select {
		case <-done:
		case <-shutdownCtx.Done():
			return shutdownCtx.Err()
		}
	}
	return nil
}

// A failed or unfinished loader leaves the runtime's fail-open defaults (or
// its last working plugin) in place. Listener startup never waits for it.
func startPlugin(ctx context.Context, name string, load func(context.Context) error) <-chan struct{} {
	done := make(chan struct{})
	coreholelog.Info("plugin_loading", "plugin", name, "fail_open", true)
	go func() {
		defer close(done)
		if err := load(ctx); err != nil {
			if ctx.Err() == nil {
				coreholelog.Warn("plugin_load_failed", "plugin", name, "fail_open", true, "error", err)
			}
			return
		}
		coreholelog.Info("plugin_ready", "plugin", name)
	}()
	return done
}

type corednsReloader interface {
	Reload(context.Context, config.Config) error
}

type dnsRuntimeReloader struct {
	server corednsReloader
}

func (r dnsRuntimeReloader) ReloadDNS(ctx context.Context, cfg config.Config) error {
	if r.server == nil {
		return nil
	}
	if err := r.server.Reload(ctx, cfg); err != nil {
		return err
	}
	coreplugin.Current().SetCacheEnabled(cfg.DNS.CacheEnabled())
	return nil
}

type runtimeConfigApplier struct {
	runtime *coreplugin.Runtime
}

func (a runtimeConfigApplier) ApplyRuntimeConfig(_ context.Context, cfg config.Config) error {
	runtime := a.runtime
	if runtime == nil {
		runtime = coreplugin.Current()
	}
	runtime.SetBlockingResponse(cfg.Blocking.Response)
	return nil
}

type runtimeBlocklistReloader struct {
	mu      sync.Mutex
	manager *blocklist.Manager
	rules   *filter.RuleDecider
	runtime *coreplugin.Runtime
}

func (r *runtimeBlocklistReloader) Reload(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.manager == nil {
		return nil
	}
	if err := r.manager.Reload(ctx); err != nil {
		return err
	}
	runtime := r.runtime
	if runtime == nil {
		runtime = coreplugin.Current()
	}
	if r.rules != nil {
		if err := r.rules.Reload(ctx); err != nil {
			return err
		}
		runtime.SetDecider(r.rules)
	} else {
		runtime.SetDecider(r.manager)
	}
	return nil
}

type blockingRuntimeController struct {
	store   config.Store
	runtime *coreplugin.Runtime
}

func (c blockingRuntimeController) Status(now time.Time) admin.BlockingStatus {
	runtime := c.runtime
	if runtime == nil {
		runtime = coreplugin.Current()
	}
	pause := runtime.BlockingPause()
	return admin.BlockingStatusFromPause(pause.Enabled, pause.Until, now)
}

func (c blockingRuntimeController) Pause(ctx context.Context, until time.Time) (admin.BlockingStatus, error) {
	if c.store == nil {
		return admin.BlockingStatus{}, fmt.Errorf("blocking pause requires config store")
	}
	cfg, err := c.store.Load(ctx)
	if err != nil {
		return admin.BlockingStatus{}, err
	}
	cfg.Blocking.Paused = true
	cfg.Blocking.PauseUntil = ""
	if !until.IsZero() {
		cfg.Blocking.PauseUntil = until.UTC().Format(time.RFC3339)
	}
	if err := c.store.Save(ctx, cfg); err != nil {
		return admin.BlockingStatus{}, err
	}
	runtime := c.runtime
	if runtime == nil {
		runtime = coreplugin.Current()
	}
	runtime.PauseBlocking(until)
	return c.Status(time.Now()), nil
}

func (c blockingRuntimeController) Resume(ctx context.Context) (admin.BlockingStatus, error) {
	if c.store == nil {
		return admin.BlockingStatus{}, fmt.Errorf("blocking resume requires config store")
	}
	cfg, err := c.store.Load(ctx)
	if err != nil {
		return admin.BlockingStatus{}, err
	}
	cfg.Blocking.Paused = false
	cfg.Blocking.PauseUntil = ""
	if err := c.store.Save(ctx, cfg); err != nil {
		return admin.BlockingStatus{}, err
	}
	runtime := c.runtime
	if runtime == nil {
		runtime = coreplugin.Current()
	}
	runtime.ResumeBlocking()
	return c.Status(time.Now()), nil
}

func applyBlockingPause(runtime *coreplugin.Runtime, cfg config.BlockingConfig) {
	if runtime == nil {
		runtime = coreplugin.Current()
	}
	if !cfg.Paused {
		runtime.ResumeBlocking()
		return
	}
	if cfg.PauseUntil == "" {
		runtime.PauseBlocking(time.Time{})
		return
	}
	until, err := time.Parse(time.RFC3339Nano, cfg.PauseUntil)
	if err != nil || !until.After(time.Now()) {
		runtime.ResumeBlocking()
		return
	}
	runtime.PauseBlocking(until)
}

type localDNSEnabledStore interface {
	ListEnabled(context.Context) ([]localdns.Record, error)
}

type localDNSRuntimeReloader struct {
	store   localDNSEnabledStore
	runtime *coreplugin.Runtime
}

func (r localDNSRuntimeReloader) ReloadLocalDNS(ctx context.Context) error {
	if r.store == nil {
		return nil
	}
	records, err := r.store.ListEnabled(ctx)
	if err != nil {
		return err
	}
	runtime := r.runtime
	if runtime == nil {
		runtime = coreplugin.Current()
	}
	runtime.SetLocalResolver(localdns.NewStaticResolver(records))
	return nil
}

func logConfigSource(configPath string, source config.Source, bootstrap config.Config, active config.Config, filterStats filter.BlocklistRuntimeStats) {
	coreholelog.Info(
		"active_config",
		"source", source,
		"config", configPath,
		"active_yaml_blocklist_paths", len(active.Blocking.Blocklists),
		"db_filter_lists_enabled", filterStats.EnabledLists,
		"db_filter_lists_imported", filterStats.ImportedEnabledLists,
		"db_filter_entries_enabled", filterStats.EnabledEntries,
	)
	if source == config.SourcePersisted && !reflect.DeepEqual(bootstrap, active) {
		coreholelog.Info(
			"persisted_config_active",
			"config", configPath,
			"yaml_blocklist_paths", len(bootstrap.Blocking.Blocklists),
			"active_yaml_blocklist_paths", len(active.Blocking.Blocklists),
		)
	}
}

func logStartup(configPath string, source config.Source, cfg config.Config, blocking blocklist.Snapshot, filterStats filter.BlocklistRuntimeStats) {
	logListeners(configPath, source, cfg)
	logBlockingReady(cfg, blocking, filterStats)
}

func logListeners(configPath string, source config.Source, cfg config.Config) {
	coreholelog.Info("corehole_started", "config", configPath, "config_source", source, "storage", cfg.Storage.Path)
	coreholelog.Info("admin_listening", "url", "http://"+cfg.Admin.Listen, "listen", cfg.Admin.Listen)
	coreholelog.Info("dns_listening", "listen", cfg.DNS.Listen, "udp", cfg.DNS.Listen, "tcp", cfg.DNS.Listen)
	for _, resolver := range cfg.DNS.Resolvers {
		if resolver.Enabled {
			coreholelog.Info(
				"upstream_resolver_enabled",
				"name", resolver.Name,
				"protocol", resolver.Protocol,
				"address", resolver.Address,
			)
		}
	}
}

func logBlockingReady(cfg config.Config, blocking blocklist.Snapshot, filterStats filter.BlocklistRuntimeStats) {
	coreholelog.Info(
		"blocking_ready",
		"response", cfg.Blocking.Response,
		"yaml_blocklist_paths", len(blocking.Paths),
		"bundled_enabled", blocking.Bundled,
		"db_filter_lists_enabled", filterStats.EnabledLists,
		"db_filter_lists_imported", filterStats.ImportedEnabledLists,
		"db_filter_entries_enabled", filterStats.EnabledEntries,
		"runtime_entries", blocking.EntryCount,
		"reload_status", blocking.Status,
	)
}

func adminConfigSnapshot(cfg config.Config) admin.ConfigSnapshot {
	upstreams := make([]admin.UpstreamSnapshot, 0, len(cfg.DNS.Resolvers))
	for _, resolver := range cfg.DNS.Resolvers {
		upstreams = append(upstreams, admin.UpstreamSnapshot{
			Name:          resolver.Name,
			Address:       resolver.Address,
			Protocol:      resolver.Protocol,
			TLSServerName: resolver.TLSServerName,
			Enabled:       resolver.Enabled,
		})
	}

	return admin.ConfigSnapshot{
		Storage:               cfg.Storage,
		DNSListen:             cfg.DNS.Listen,
		AdminListen:           cfg.Admin.Listen,
		Upstreams:             upstreams,
		CacheTTL:              cfg.DNS.CacheTTL,
		CacheSuccessTTL:       cfg.DNS.EffectiveCacheSuccessTTL(),
		CacheDenialTTL:        cfg.DNS.EffectiveCacheDenialTTL(),
		CacheSuccessCapacity:  cfg.DNS.CacheSuccessCapacity,
		CacheDenialCapacity:   cfg.DNS.CacheDenialCapacity,
		CachePrefetchAmount:   cfg.DNS.CachePrefetchAmount,
		CachePrefetchDuration: cfg.DNS.CachePrefetchDuration,
		CachePrefetchPercent:  cfg.DNS.CachePrefetchPercent,
		Rewrites:              append([]config.RewriteRule(nil), cfg.DNS.Rewrites...),
		BlockingResponse:      string(cfg.Blocking.Response),
		BlockingBundled:       cfg.Blocking.Bundled,
		BlockingPaused:        cfg.Blocking.Paused,
		BlockingPauseUntil:    cfg.Blocking.PauseUntil,
		Logging: admin.LoggingSnapshot{
			Level:  string(cfg.Logging.EffectiveLevel()),
			Format: string(cfg.Logging.EffectiveFormat()),
		},
		Blocklists:       append([]string(nil), cfg.Blocking.Blocklists...),
		StoragePath:      cfg.Storage.Path,
		AuditStoragePath: cfg.Storage.AuditPath,
	}
}

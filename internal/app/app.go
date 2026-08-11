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

	store, err := storage.Open(ctx, bootstrapCfg.Storage.Path)
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
	coreholelog.Configure(string(cfg.Logging.EffectiveLevel()), string(cfg.Logging.EffectiveFormat()))

	blocklist.SetBundledDefault(cfg.Blocking.Bundled)
	runtime := coreplugin.Current()
	runtime.SetBlockingResponse(cfg.Blocking.Response)
	applyBlockingPause(runtime, cfg.Blocking)
	runtime.SetCacheEnabled(cfg.DNS.CacheTTL > 0)
	filterRepo := filter.NewRepository(store.DB())
	filterService := filter.NewService(filterRepo)
	filterStats, err := filterRepo.BlocklistRuntimeStats(ctx)
	if err != nil {
		return fmt.Errorf("filter blocklist stats: %w", err)
	}
	logConfigSource(*configPath, initResult.Source, bootstrapCfg, cfg, filterStats)
	blocklistManager := blocklist.NewManagerWithBundledAndSources(cfg.Blocking.Blocklists, cfg.Blocking.Bundled, filter.NewBlocklistSource(filterRepo))
	if err := blocklistManager.Reload(ctx); err != nil {
		return err
	}
	runtime.SetDecider(blocklistManager)

	auditSink, err := audit.NewSQLiteSink(store.DB())
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
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
	if err := localDNSReloader.ReloadLocalDNS(ctx); err != nil {
		return fmt.Errorf("local dns runtime: %w", err)
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
			admin.NewSQLiteUserStore(store.DB()),
			admin.WithSessionStore(admin.NewSQLiteSessionStore(store.DB())),
			admin.WithSecureCookie(false),
			admin.WithConfigSnapshot(adminConfigSnapshot(cfg)),
			admin.WithConfigStoreAndDNSReloader(cfgStore, dnsRuntimeReloader{server: dnsServer}),
			admin.WithBlockingController(blockingRuntimeController{
				store:   cfgStore,
				runtime: runtime,
			}),
			admin.WithAuditReader(auditSink),
			admin.WithLocalDNSStore(localDNSRepo),
			admin.WithLocalDNSReloader(localDNSReloader),
			admin.WithFilterService(filterService),
			admin.WithFilterReloader(runtimeBlocklistReloader{
				manager: blocklistManager,
				runtime: runtime,
			}),
		),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		if err := adminServer.Serve(adminListener); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()

	logStartup(*configPath, initResult.Source, cfg, blocklistManager.Snapshot(), filterStats)

	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-signalCtx.Done():
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := adminServer.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return dnsServer.Stop(shutdownCtx)
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
	coreplugin.Current().SetCacheEnabled(cfg.DNS.CacheTTL > 0)
	return nil
}

type runtimeBlocklistReloader struct {
	manager *blocklist.Manager
	runtime *coreplugin.Runtime
}

func (r runtimeBlocklistReloader) Reload(ctx context.Context) error {
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
	runtime.SetDecider(r.manager)
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
		DNSListen:            cfg.DNS.Listen,
		AdminListen:          cfg.Admin.Listen,
		Upstreams:            upstreams,
		CacheTTL:             cfg.DNS.CacheTTL,
		CacheSuccessCapacity: cfg.DNS.CacheSuccessCapacity,
		CacheDenialCapacity:  cfg.DNS.CacheDenialCapacity,
		BlockingResponse:     string(cfg.Blocking.Response),
		BlockingBundled:      cfg.Blocking.Bundled,
		BlockingPaused:       cfg.Blocking.Paused,
		BlockingPauseUntil:   cfg.Blocking.PauseUntil,
		Logging: admin.LoggingSnapshot{
			Level:  string(cfg.Logging.EffectiveLevel()),
			Format: string(cfg.Logging.EffectiveFormat()),
		},
		Blocklists:  append([]string(nil), cfg.Blocking.Blocklists...),
		StoragePath: cfg.Storage.Path,
	}
}

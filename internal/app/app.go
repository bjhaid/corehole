package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
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

	blocklist.SetBundledDefault(cfg.Blocking.Bundled)
	runtime := coreplugin.Current()
	runtime.SetBlockingResponse(cfg.Blocking.Response)
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
	runtime.SetLocalResolver(localdns.NewDNSResolver(localDNSRepo))

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
			admin.WithAuditReader(auditSink),
			admin.WithLocalDNSStore(localDNSRepo),
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

func logConfigSource(configPath string, source config.Source, bootstrap config.Config, active config.Config, filterStats filter.BlocklistRuntimeStats) {
	log.Printf(
		"active config source=%s config=%s active_yaml_blocklist_paths=%d db_filter_lists_enabled=%d db_filter_lists_imported=%d db_filter_entries_enabled=%d",
		source,
		configPath,
		len(active.Blocking.Blocklists),
		filterStats.EnabledLists,
		filterStats.ImportedEnabledLists,
		filterStats.EnabledEntries,
	)
	if source == config.SourcePersisted && !reflect.DeepEqual(bootstrap, active) {
		log.Printf("persisted config active from SQLite app_config; YAML changes in %s are not applied until persisted config is updated or reseeded (yaml_blocklist_paths=%d active_yaml_blocklist_paths=%d)", configPath, len(bootstrap.Blocking.Blocklists), len(active.Blocking.Blocklists))
	}
}

func logStartup(configPath string, source config.Source, cfg config.Config, blocking blocklist.Snapshot, filterStats filter.BlocklistRuntimeStats) {
	log.Printf("corehole started config=%s config_source=%s storage=%s", configPath, source, cfg.Storage.Path)
	log.Printf("admin console listening on http://%s", cfg.Admin.Listen)
	log.Printf("dns listening on %s/udp and %s/tcp", cfg.DNS.Listen, cfg.DNS.Listen)
	for _, resolver := range cfg.DNS.Resolvers {
		if resolver.Enabled {
			log.Printf("upstream resolver enabled name=%s protocol=%s address=%s", resolver.Name, resolver.Protocol, resolver.Address)
		}
	}
	log.Printf(
		"blocking response=%s yaml_blocklist_paths=%d bundled_enabled=%t db_filter_lists_enabled=%d db_filter_lists_imported=%d db_filter_entries_enabled=%d runtime_entries=%d reload_status=%s",
		cfg.Blocking.Response,
		len(blocking.Paths),
		blocking.Bundled,
		filterStats.EnabledLists,
		filterStats.ImportedEnabledLists,
		filterStats.EnabledEntries,
		blocking.EntryCount,
		blocking.Status,
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
		DNSListen:        cfg.DNS.Listen,
		AdminListen:      cfg.Admin.Listen,
		Upstreams:        upstreams,
		BlockingResponse: string(cfg.Blocking.Response),
		Blocklists:       append([]string(nil), cfg.Blocking.Blocklists...),
		StoragePath:      cfg.Storage.Path,
	}
}

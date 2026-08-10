package admin

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/bjhaid/corehole/internal/audit"
	"github.com/bjhaid/corehole/internal/config"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
)

const (
	defaultQueriesLimit = 100
	maxQueriesLimit     = 500
)

type AuditReader interface {
	Recent(ctx context.Context, limit int) ([]audit.Event, error)
	Dropped() uint64
}

type AuditQueryReader interface {
	Query(ctx context.Context, opts audit.QueryOptions) ([]audit.Event, error)
}

type AuditTotalsReader interface {
	Totals(ctx context.Context) (audit.Totals, error)
}

type AuditStatsReader interface {
	Stats(ctx context.Context) (audit.Stats, error)
}

func WithAuditReader(reader AuditReader) Option {
	return func(s *Server) {
		if reader != nil {
			s.auditReader = reader
		}
	}
}

type ConfigSource interface {
	Snapshot(ctx context.Context) (ConfigSnapshot, error)
}

type ConfigUpdater interface {
	Update(ctx context.Context, req ConfigUpdateRequest) (ConfigUpdateResult, error)
}

type DNSReloader interface {
	ReloadDNS(ctx context.Context, cfg config.Config) error
}

type BlockingController interface {
	Status(time.Time) BlockingStatus
	Pause(ctx context.Context, until time.Time) (BlockingStatus, error)
	Resume(ctx context.Context) (BlockingStatus, error)
}

type ConfigSourceFunc func(context.Context) (ConfigSnapshot, error)

func (f ConfigSourceFunc) Snapshot(ctx context.Context) (ConfigSnapshot, error) {
	return f(ctx)
}

func WithConfigSnapshot(snapshot ConfigSnapshot) Option {
	return func(s *Server) {
		s.configSource = ConfigSourceFunc(func(context.Context) (ConfigSnapshot, error) {
			return snapshot, nil
		})
	}
}

func WithConfigSource(source ConfigSource) Option {
	return func(s *Server) {
		if source != nil {
			s.configSource = source
		}
	}
}

func WithConfigStore(store config.Store) Option {
	return func(s *Server) {
		if store == nil {
			return
		}
		manager := configStoreManager{store: store}
		s.configSource = manager
	}
}

func WithConfigStoreAndDNSReloader(store config.Store, reloader DNSReloader) Option {
	return func(s *Server) {
		if store == nil {
			return
		}
		manager := configStoreManager{store: store, dnsReloader: reloader}
		s.configSource = manager
	}
}

func WithBlockingController(controller BlockingController) Option {
	return func(s *Server) {
		if controller != nil {
			s.blocking = controller
		}
	}
}

type ConfigSnapshot struct {
	DNSListen             string
	AdminListen           string
	Upstreams             []UpstreamSnapshot
	CacheTTL              int
	DNSSEC                DNSSECSnapshot
	ConditionalForwarding ConditionalForwardingSnapshot
	BlockingResponse      string
	BlockingBundled       bool
	BlockingPaused        bool
	BlockingPauseUntil    string
	Blocklists            []string
	StoragePath           string
}

type ConfigUpdateRequest struct {
	DNS      *DNSConfigUpdate      `json:"dns,omitempty"`
	Admin    *AdminConfigUpdate    `json:"admin,omitempty"`
	Blocking *BlockingConfigUpdate `json:"blocking,omitempty"`
}

type DNSConfigUpdate struct {
	Listen                *string                      `json:"listen,omitempty"`
	Resolvers             *[]ResolverUpdate            `json:"resolvers,omitempty"`
	CacheTTL              *int                         `json:"cache_ttl,omitempty"`
	DNSSEC                *DNSSECUpdate                `json:"dnssec,omitempty"`
	ConditionalForwarding *ConditionalForwardingUpdate `json:"conditional_forwarding,omitempty"`
}

type DNSSECUpdate struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Mode    *string `json:"mode,omitempty"`
}

type ResolverUpdate struct {
	Name          string `json:"name"`
	Address       string `json:"address"`
	Protocol      string `json:"protocol"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	Enabled       *bool  `json:"enabled,omitempty"`
}

type ConditionalForwardingUpdate struct {
	Enabled       *bool   `json:"enabled,omitempty"`
	Domain        *string `json:"domain,omitempty"`
	Resolver      *string `json:"resolver,omitempty"`
	Protocol      *string `json:"protocol,omitempty"`
	TLSServerName *string `json:"tls_server_name,omitempty"`
}

type AdminConfigUpdate struct {
	Listen *string `json:"listen,omitempty"`
}

type BlockingConfigUpdate struct {
	Response   *string   `json:"response,omitempty"`
	Bundled    *bool     `json:"bundled,omitempty"`
	Blocklists *[]string `json:"blocklists,omitempty"`
}

type ConfigUpdateResult struct {
	Snapshot        ConfigSnapshot
	RestartRequired bool
}

type UpstreamSnapshot struct {
	Name          string `json:"name"`
	Address       string `json:"address"`
	Protocol      string `json:"protocol"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	Enabled       bool   `json:"enabled"`
}

type ConditionalForwardingSnapshot struct {
	Enabled       bool   `json:"enabled"`
	Domain        string `json:"domain"`
	Resolver      string `json:"resolver"`
	Protocol      string `json:"protocol,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
}

type DNSSECSnapshot struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
}

type dashboardResponse struct {
	SetupRequired        bool               `json:"setup_required"`
	Authenticated        bool               `json:"authenticated"`
	TotalQueries         int64              `json:"total_queries"`
	BlockedQueries       int64              `json:"blocked_queries"`
	AllowedQueries       int64              `json:"allowed_queries"`
	TotalRecentQueries   int                `json:"total_recent_queries"`
	BlockedRecentQueries int                `json:"blocked_recent_queries"`
	AllowedRecentQueries int                `json:"allowed_recent_queries"`
	DroppedAuditEvents   uint64             `json:"dropped_audit_events"`
	Upstreams            []UpstreamSnapshot `json:"upstreams"`
	Blocklists           []string           `json:"blocklists"`
	BlocklistCount       int                `json:"blocklist_count"`
	DNSListen            string             `json:"dns_listen"`
	AdminListen          string             `json:"admin_listen"`
	BlockingResponse     string             `json:"blocking_response"`
	BlockingBundled      bool               `json:"blocking_bundled"`
	BlockingPaused       bool               `json:"blocking_paused"`
	BlockingPauseUntil   string             `json:"blocking_pause_until,omitempty"`
}

type queriesResponse struct {
	Queries        []queryEventResponse `json:"queries"`
	Events         []queryEventResponse `json:"events"`
	Limit          int                  `json:"limit"`
	Offset         int                  `json:"offset"`
	NextOffset     *int                 `json:"next_offset"`
	PreviousOffset *int                 `json:"previous_offset"`
	HasNext        bool                 `json:"has_next"`
	HasPrevious    bool                 `json:"has_previous"`
	Sort           string               `json:"sort"`
	Order          string               `json:"order"`
	// Deliberately no total_count: arbitrary filtered counts over audit_events are
	// not cheap across all supported filter/sort combinations with current indexes.
}

type queryEventResponse struct {
	Timestamp         time.Time `json:"timestamp"`
	ClientIP          string    `json:"client_ip"`
	QueryName         string    `json:"query_name"`
	QueryType         uint16    `json:"query_type"`
	Action            string    `json:"action"`
	Reason            string    `json:"reason"`
	Response          string    `json:"response"`
	DurationMS        int64     `json:"duration_ms"`
	RuleID            int64     `json:"rule_id"`
	BlocklistID       int64     `json:"blocklist_id"`
	Upstream          string    `json:"upstream_resolver"`
	CacheStatus       string    `json:"cache_status"`
	ForwardDurationMS int64     `json:"forward_duration_ms"`
	RetryCount        int       `json:"retry_count"`
	ForwardError      string    `json:"forward_error"`
}

type configResponse struct {
	DNSListen             string                        `json:"dns_listen"`
	AdminListen           string                        `json:"admin_listen"`
	Upstreams             []UpstreamSnapshot            `json:"upstreams"`
	CacheTTL              int                           `json:"cache_ttl"`
	DNSSEC                DNSSECSnapshot                `json:"dnssec"`
	ConditionalForwarding ConditionalForwardingSnapshot `json:"conditional_forwarding"`
	BlockingResponse      string                        `json:"blocking_response"`
	BlockingBundled       bool                          `json:"blocking_bundled"`
	BlockingPaused        bool                          `json:"blocking_paused"`
	BlockingPauseUntil    string                        `json:"blocking_pause_until,omitempty"`
	Blocklists            []string                      `json:"blocklists"`
	BlocklistPaths        []string                      `json:"blocklist_paths"`
	BlocklistCount        int                           `json:"blocklist_count"`
	StoragePath           string                        `json:"storage_path"`
}

type configUpdateResponse struct {
	Config          configResponse `json:"config"`
	RestartRequired bool           `json:"restart_required"`
}

type BlockingStatus struct {
	Paused           bool   `json:"paused"`
	Indefinite       bool   `json:"indefinite"`
	PauseUntil       string `json:"pause_until,omitempty"`
	RemainingSeconds int64  `json:"remaining_seconds"`
}

type blockingStatusRequest struct {
	Paused          *bool   `json:"paused"`
	DurationSeconds *int64  `json:"duration_seconds,omitempty"`
	PauseUntil      *string `json:"pause_until,omitempty"`
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	setup, err := s.userStore.IsSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard_unavailable")
		return
	}

	events, err := s.recentAuditEvents(r.Context(), defaultQueriesLimit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard_unavailable")
		return
	}
	stats, err := s.auditStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard_unavailable")
		return
	}
	snapshot, err := s.configSnapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard_unavailable")
		return
	}

	res := dashboardResponse{
		SetupRequired:      !setup,
		Authenticated:      s.authenticated(r),
		TotalQueries:       stats.TotalQueries,
		BlockedQueries:     stats.BlockedQueries,
		AllowedQueries:     stats.AllowedQueries,
		TotalRecentQueries: len(events),
		DroppedAuditEvents: stats.DroppedEvents,
		Upstreams:          cloneUpstreams(snapshot.Upstreams),
		Blocklists:         cloneStrings(snapshot.Blocklists),
		BlocklistCount:     len(snapshot.Blocklists),
		DNSListen:          snapshot.DNSListen,
		AdminListen:        snapshot.AdminListen,
		BlockingResponse:   snapshot.BlockingResponse,
		BlockingBundled:    snapshot.BlockingBundled,
		BlockingPaused:     snapshot.BlockingPaused,
		BlockingPauseUntil: snapshot.BlockingPauseUntil,
	}
	for _, event := range events {
		switch string(event.Action) {
		case "block":
			res.BlockedRecentQueries++
		case "allow":
			res.AllowedRecentQueries++
		}
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleQueries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	limit, ok := parseQueriesLimit(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_limit")
		return
	}
	offset, ok := parseQueriesOffset(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_offset")
		return
	}
	opts, ok := parseQueryOptions(r, limit, offset)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_query_options")
		return
	}
	events, page, err := s.queryAuditEventsPage(r.Context(), opts, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "queries_unavailable")
		return
	}
	settings, err := s.auditSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "queries_unavailable")
		return
	}

	queries := queryEventResponses(audit.ProjectEvents(events, settings.PrivacyLevel))
	writeJSON(w, http.StatusOK, queriesResponse{
		Queries:        queries,
		Events:         queries,
		Limit:          page.Limit,
		Offset:         page.Offset,
		NextOffset:     page.NextOffset,
		PreviousOffset: page.PreviousOffset,
		HasNext:        page.HasNext,
		HasPrevious:    page.HasPrevious,
		Sort:           page.Sort,
		Order:          page.Order,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfig(w, r)
	case http.MethodPut:
		s.handlePutConfig(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleBlockingStatus(w http.ResponseWriter, r *http.Request) {
	if s.blocking == nil {
		writeError(w, http.StatusServiceUnavailable, "blocking_control_unavailable")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.blocking.Status(time.Now()))
	case http.MethodPut:
		var req blockingStatusRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Paused == nil {
			writeError(w, http.StatusBadRequest, "paused_required")
			return
		}
		if !*req.Paused {
			status, err := s.blocking.Resume(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "blocking_resume_failed")
				return
			}
			writeJSON(w, http.StatusOK, status)
			return
		}

		until, ok := parseBlockingPauseUntil(req)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_pause_duration")
			return
		}
		status, err := s.blocking.Pause(r.Context(), until)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "blocking_pause_failed")
			return
		}
		writeJSON(w, http.StatusOK, status)
	default:
		methodNotAllowed(w)
	}
}

func parseBlockingPauseUntil(req blockingStatusRequest) (time.Time, bool) {
	if req.DurationSeconds != nil && req.PauseUntil != nil && strings.TrimSpace(*req.PauseUntil) != "" {
		return time.Time{}, false
	}
	if req.DurationSeconds != nil {
		if *req.DurationSeconds <= 0 {
			return time.Time{}, false
		}
		return time.Now().Add(time.Duration(*req.DurationSeconds) * time.Second).UTC(), true
	}
	if req.PauseUntil != nil {
		raw := strings.TrimSpace(*req.PauseUntil)
		if raw == "" {
			return time.Time{}, true
		}
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, false
		}
		if !until.After(time.Now()) {
			return time.Time{}, false
		}
		return until.UTC(), true
	}
	return time.Time{}, true
}

func BlockingStatusFromPause(paused bool, until time.Time, now time.Time) BlockingStatus {
	if now.IsZero() {
		now = time.Now()
	}
	if !paused {
		return BlockingStatus{}
	}
	if until.IsZero() {
		return BlockingStatus{Paused: true, Indefinite: true}
	}
	if !until.After(now) {
		return BlockingStatus{}
	}
	return BlockingStatus{
		Paused:           true,
		PauseUntil:       until.UTC().Format(time.RFC3339),
		RemainingSeconds: int64(until.Sub(now).Seconds()),
	}
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.configSnapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "config_unavailable")
		return
	}

	writeJSON(w, http.StatusOK, configResponseFromSnapshot(snapshot))
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	updater, ok := s.configSource.(ConfigUpdater)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "config_update_unavailable")
		return
	}

	var req ConfigUpdateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	result, err := updater.Update(r.Context(), req)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) || errors.Is(err, errInvalidConfigUpdate) {
			writeError(w, http.StatusBadRequest, "invalid_config")
			return
		}
		writeError(w, http.StatusInternalServerError, "config_update_failed")
		return
	}

	writeJSON(w, http.StatusOK, configUpdateResponse{
		Config:          configResponseFromSnapshot(result.Snapshot),
		RestartRequired: result.RestartRequired,
	})
}

func (s *Server) recentAuditEvents(ctx context.Context, limit int) ([]audit.Event, error) {
	if s.auditReader == nil {
		return []audit.Event{}, nil
	}
	events, err := s.auditReader.Recent(ctx, limit)
	if err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Server) auditStats(ctx context.Context) (audit.Stats, error) {
	if s.auditReader == nil {
		return audit.Stats{}, nil
	}
	if reader, ok := s.auditReader.(AuditStatsReader); ok {
		return reader.Stats(ctx)
	}
	stats := audit.Stats{DroppedEvents: s.auditReader.Dropped()}
	if reader, ok := s.auditReader.(AuditTotalsReader); ok {
		totals, err := reader.Totals(ctx)
		if err != nil {
			return audit.Stats{}, err
		}
		stats.Totals = totals
	}
	return stats, nil
}

func (s *Server) queryAuditEvents(ctx context.Context, opts audit.QueryOptions) ([]audit.Event, error) {
	if s.auditReader == nil {
		return []audit.Event{}, nil
	}
	if reader, ok := s.auditReader.(AuditQueryReader); ok {
		return reader.Query(ctx, opts)
	}
	return s.auditReader.Recent(ctx, opts.Limit)
}

type queryPage struct {
	Limit          int
	Offset         int
	NextOffset     *int
	PreviousOffset *int
	HasNext        bool
	HasPrevious    bool
	Sort           string
	Order          string
}

func (s *Server) queryAuditEventsPage(ctx context.Context, opts audit.QueryOptions, requestedLimit int) ([]audit.Event, queryPage, error) {
	page := queryPage{
		Limit:       requestedLimit,
		Offset:      opts.Offset,
		HasPrevious: opts.Offset > 0,
		Sort:        string(canonicalQuerySort(opts.Sort)),
		Order:       string(canonicalQueryOrder(opts.Order)),
	}
	if page.HasPrevious {
		previous := opts.Offset - requestedLimit
		if previous < 0 {
			previous = 0
		}
		page.PreviousOffset = &previous
	}

	opts.Limit = requestedLimit + 1
	events, err := s.queryAuditEvents(ctx, opts)
	if err != nil {
		return nil, page, err
	}
	if len(events) > requestedLimit {
		page.HasNext = true
		next := opts.Offset + requestedLimit
		page.NextOffset = &next
		events = events[:requestedLimit]
	}

	return events, page, nil
}

func (s *Server) configSnapshot(ctx context.Context) (ConfigSnapshot, error) {
	if s.configSource == nil {
		return ConfigSnapshot{
			BlockingBundled: config.Default().Blocking.Bundled,
			DNSSEC:          DNSSECSnapshot{Enabled: false, Mode: string(config.DNSSECModeOff)},
			Upstreams:       []UpstreamSnapshot{},
			Blocklists:      []string{},
		}, nil
	}
	snapshot, err := s.configSource.Snapshot(ctx)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	snapshot.Upstreams = cloneUpstreams(snapshot.Upstreams)
	snapshot.Blocklists = cloneStrings(snapshot.Blocklists)
	return snapshot, nil
}

func configResponseFromSnapshot(snapshot ConfigSnapshot) configResponse {
	blocklists := cloneStrings(snapshot.Blocklists)
	return configResponse{
		DNSListen:             snapshot.DNSListen,
		AdminListen:           snapshot.AdminListen,
		Upstreams:             cloneUpstreams(snapshot.Upstreams),
		CacheTTL:              snapshot.CacheTTL,
		DNSSEC:                snapshot.DNSSEC,
		ConditionalForwarding: snapshot.ConditionalForwarding,
		BlockingResponse:      snapshot.BlockingResponse,
		BlockingBundled:       snapshot.BlockingBundled,
		BlockingPaused:        snapshot.BlockingPaused,
		BlockingPauseUntil:    snapshot.BlockingPauseUntil,
		Blocklists:            blocklists,
		BlocklistPaths:        blocklists,
		BlocklistCount:        len(blocklists),
		StoragePath:           snapshot.StoragePath,
	}
}

type configStoreManager struct {
	store       config.Store
	dnsReloader DNSReloader
}

func (m configStoreManager) Snapshot(ctx context.Context) (ConfigSnapshot, error) {
	cfg, err := m.store.Load(ctx)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return snapshotFromConfig(cfg), nil
}

func (m configStoreManager) Update(ctx context.Context, req ConfigUpdateRequest) (ConfigUpdateResult, error) {
	current, err := m.store.Load(ctx)
	if err != nil {
		return ConfigUpdateResult{}, err
	}

	next := applyConfigUpdate(current, req)
	if err := next.Validate(); err != nil {
		return ConfigUpdateResult{}, errInvalidConfigUpdate
	}
	dnsReloaded := false
	if shouldReloadDNSImmediately(current, next, m.dnsReloader) {
		if err := m.dnsReloader.ReloadDNS(ctx, next); err != nil {
			return ConfigUpdateResult{}, err
		}
		dnsReloaded = true
	}
	if err := m.store.Save(ctx, next); err != nil {
		return ConfigUpdateResult{}, err
	}

	return ConfigUpdateResult{
		Snapshot:        snapshotFromConfig(next),
		RestartRequired: restartRequired(current, next, dnsReloaded),
	}, nil
}

var errInvalidConfigUpdate = errors.New("invalid config update")

func applyConfigUpdate(cfg config.Config, req ConfigUpdateRequest) config.Config {
	if req.DNS != nil {
		if req.DNS.Listen != nil {
			cfg.DNS.Listen = *req.DNS.Listen
		}
		if req.DNS.Resolvers != nil {
			cfg.DNS.Resolvers = resolverUpdatesToConfig(*req.DNS.Resolvers)
		}
		if req.DNS.CacheTTL != nil {
			cfg.DNS.CacheTTL = *req.DNS.CacheTTL
		}
		if req.DNS.DNSSEC != nil {
			cfg.DNS.DNSSEC = dnssecUpdateToConfig(cfg.DNS.DNSSEC, *req.DNS.DNSSEC)
		}
		if req.DNS.ConditionalForwarding != nil {
			cfg.DNS.ConditionalForwarding = conditionalForwardingUpdateToConfig(cfg.DNS.ConditionalForwarding, *req.DNS.ConditionalForwarding)
		}
	}
	if req.Admin != nil && req.Admin.Listen != nil {
		cfg.Admin.Listen = *req.Admin.Listen
	}
	if req.Blocking != nil {
		if req.Blocking.Response != nil {
			cfg.Blocking.Response = coreholedns.BlockingResponse(*req.Blocking.Response)
		}
		if req.Blocking.Bundled != nil {
			cfg.Blocking.Bundled = *req.Blocking.Bundled
		}
		if req.Blocking.Blocklists != nil {
			cfg.Blocking.Blocklists = cloneStrings(*req.Blocking.Blocklists)
		}
	}
	return cfg
}

func dnssecUpdateToConfig(current config.DNSSECConfig, update DNSSECUpdate) config.DNSSECConfig {
	if update.Enabled != nil {
		current.Enabled = *update.Enabled
	}
	if update.Mode != nil {
		current.Mode = config.DNSSECMode(strings.ToLower(strings.TrimSpace(*update.Mode)))
		if update.Enabled == nil {
			switch current.Mode {
			case config.DNSSECModeUpstream:
				current.Enabled = true
			case config.DNSSECModeOff:
				current.Enabled = false
			}
		}
	}
	if update.Enabled != nil && update.Mode == nil {
		if *update.Enabled {
			current.Mode = config.DNSSECModeUpstream
		} else {
			current.Mode = config.DNSSECModeOff
		}
	}
	return current
}

func conditionalForwardingUpdateToConfig(current config.ConditionalForwarding, update ConditionalForwardingUpdate) config.ConditionalForwarding {
	if update.Enabled != nil {
		current.Enabled = *update.Enabled
	}
	if update.Domain != nil {
		current.Domain = *update.Domain
	}
	if update.Resolver != nil {
		current.Resolver = *update.Resolver
	}
	if update.Protocol != nil {
		current.Protocol = *update.Protocol
	}
	if update.TLSServerName != nil {
		current.TLSServerName = *update.TLSServerName
	}
	if !current.Enabled {
		current.Domain = ""
		current.Resolver = ""
		current.Protocol = ""
		current.TLSServerName = ""
	}
	return current
}

func resolverUpdatesToConfig(updates []ResolverUpdate) []config.Resolver {
	if len(updates) == 0 {
		return []config.Resolver{}
	}
	resolvers := make([]config.Resolver, 0, len(updates))
	for _, update := range updates {
		enabled := true
		if update.Enabled != nil {
			enabled = *update.Enabled
		}
		resolvers = append(resolvers, config.Resolver{
			Name:          update.Name,
			Address:       update.Address,
			Protocol:      update.Protocol,
			TLSServerName: update.TLSServerName,
			Enabled:       enabled,
		})
	}
	return resolvers
}

func snapshotFromConfig(cfg config.Config) ConfigSnapshot {
	upstreams := make([]UpstreamSnapshot, 0, len(cfg.DNS.Resolvers))
	for _, resolver := range cfg.DNS.Resolvers {
		upstreams = append(upstreams, UpstreamSnapshot{
			Name:          resolver.Name,
			Address:       resolver.Address,
			Protocol:      resolver.Protocol,
			TLSServerName: resolver.TLSServerName,
			Enabled:       resolver.Enabled,
		})
	}

	return ConfigSnapshot{
		DNSListen:   cfg.DNS.Listen,
		AdminListen: cfg.Admin.Listen,
		Upstreams:   upstreams,
		CacheTTL:    cfg.DNS.CacheTTL,
		DNSSEC: DNSSECSnapshot{
			Enabled: cfg.DNS.DNSSEC.Enabled,
			Mode:    string(cfg.DNS.DNSSEC.EffectiveMode()),
		},
		ConditionalForwarding: ConditionalForwardingSnapshot{
			Enabled:       cfg.DNS.ConditionalForwarding.Enabled,
			Domain:        cfg.DNS.ConditionalForwarding.Domain,
			Resolver:      cfg.DNS.ConditionalForwarding.Resolver,
			Protocol:      cfg.DNS.ConditionalForwarding.Protocol,
			TLSServerName: cfg.DNS.ConditionalForwarding.TLSServerName,
		},
		BlockingResponse:   string(cfg.Blocking.Response),
		BlockingBundled:    cfg.Blocking.Bundled,
		BlockingPaused:     cfg.Blocking.Paused,
		BlockingPauseUntil: cfg.Blocking.PauseUntil,
		Blocklists:         cloneStrings(cfg.Blocking.Blocklists),
		StoragePath:        cfg.Storage.Path,
	}
}

func shouldReloadDNSImmediately(current config.Config, next config.Config, reloader DNSReloader) bool {
	return reloader != nil &&
		current.DNS.Listen == next.DNS.Listen &&
		!reflect.DeepEqual(current.DNS, next.DNS)
}

func restartRequired(current config.Config, next config.Config, dnsReloaded bool) bool {
	dnsRestartRequired := !reflect.DeepEqual(current.DNS, next.DNS) && !dnsReloaded
	return dnsRestartRequired ||
		current.Admin.Listen != next.Admin.Listen ||
		!reflect.DeepEqual(current.Blocking.Blocklists, next.Blocking.Blocklists)
}

func parseQueriesLimit(r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultQueriesLimit, true
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return 0, false
	}
	if limit > maxQueriesLimit {
		return maxQueriesLimit, true
	}
	return limit, true
}

func parseQueriesOffset(r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("offset")
	if raw == "" {
		return 0, true
	}
	offset, err := strconv.Atoi(raw)
	if err != nil || offset < 0 {
		return 0, false
	}
	return offset, true
}

func parseQueryOptions(r *http.Request, limit int, offset int) (audit.QueryOptions, bool) {
	values := r.URL.Query()
	opts := audit.QueryOptions{Limit: limit, Offset: offset}

	sort, ok := parseQuerySort(values.Get("sort"))
	if !ok {
		return audit.QueryOptions{}, false
	}
	opts.Sort = sort
	order, ok := parseQueryOrder(values.Get("order"))
	if !ok {
		return audit.QueryOptions{}, false
	}
	opts.Order = order

	from, ok := parseOptionalQueryTime(firstQueryValue(values, "from", "since"))
	if !ok {
		return audit.QueryOptions{}, false
	}
	opts.From = from
	to, ok := parseOptionalQueryTime(values.Get("to"))
	if !ok {
		return audit.QueryOptions{}, false
	}
	opts.To = to

	opts.ClientIP = strings.TrimSpace(values.Get("client_ip"))
	opts.QueryName = strings.TrimSpace(firstQueryValue(values, "query_name", "domain"))
	if raw := firstQueryValue(values, "query_type", "type"); strings.TrimSpace(raw) != "" {
		queryType, ok := parseQueryType(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.QueryType = queryType
		opts.HasQueryType = true
	}
	opts.Action = strings.ToLower(strings.TrimSpace(values.Get("action")))
	opts.Response = strings.ToUpper(strings.TrimSpace(values.Get("response")))
	if raw := values.Get("rule_id"); strings.TrimSpace(raw) != "" {
		ruleID, ok := parseNonNegativeInt64(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.RuleID = ruleID
		opts.HasRuleID = true
	}
	if raw := values.Get("blocklist_id"); strings.TrimSpace(raw) != "" {
		blocklistID, ok := parseNonNegativeInt64(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.BlocklistID = blocklistID
		opts.HasBlocklistID = true
	}
	if raw := values.Get("duration_ns"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseNonNegativeInt64(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.DurationNS = durationNS
		opts.HasDurationNS = true
	}
	if raw := values.Get("duration_ms"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseDurationMS(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.DurationNS = durationNS
		opts.HasDurationNS = true
	}
	if raw := values.Get("duration_min_ns"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseNonNegativeInt64(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.DurationMinNS = durationNS
		opts.HasDurationMin = true
	}
	if raw := firstQueryValue(values, "duration_min_ms", "duration_min"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseDurationMS(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.DurationMinNS = durationNS
		opts.HasDurationMin = true
	}
	if raw := values.Get("duration_max_ns"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseNonNegativeInt64(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.DurationMaxNS = durationNS
		opts.HasDurationMax = true
	}
	if raw := firstQueryValue(values, "duration_max_ms", "duration_max"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseDurationMS(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.DurationMaxNS = durationNS
		opts.HasDurationMax = true
	}
	opts.Upstream = strings.TrimSpace(firstQueryValue(values, "upstream_resolver", "upstream"))
	opts.CacheStatus = strings.ToLower(strings.TrimSpace(firstQueryValue(values, "cache_status", "cache")))
	if raw := firstQueryValue(values, "forward_duration_min_ns", "forward_min_ns"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseNonNegativeInt64(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.ForwardMinNS = durationNS
		opts.HasForwardMin = true
	}
	if raw := firstQueryValue(values, "forward_duration_min_ms", "forward_min"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseDurationMS(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.ForwardMinNS = durationNS
		opts.HasForwardMin = true
	}
	if raw := firstQueryValue(values, "forward_duration_max_ns", "forward_max_ns"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseNonNegativeInt64(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.ForwardMaxNS = durationNS
		opts.HasForwardMax = true
	}
	if raw := firstQueryValue(values, "forward_duration_max_ms", "forward_max"); strings.TrimSpace(raw) != "" {
		durationNS, ok := parseDurationMS(raw)
		if !ok {
			return audit.QueryOptions{}, false
		}
		opts.ForwardMaxNS = durationNS
		opts.HasForwardMax = true
	}
	if raw := values.Get("retry_count"); strings.TrimSpace(raw) != "" {
		retryCount, ok := parseInt(raw)
		if !ok || retryCount < -1 {
			return audit.QueryOptions{}, false
		}
		opts.RetryCount = retryCount
		opts.HasRetryCount = true
	}
	opts.ForwardError = strings.TrimSpace(firstQueryValue(values, "forward_error", "upstream_error"))

	return opts, true
}

func canonicalQuerySort(sort audit.QuerySortField) audit.QuerySortField {
	if sort == "" {
		return audit.QuerySortTimestamp
	}
	return sort
}

func canonicalQueryOrder(order audit.QuerySortOrder) audit.QuerySortOrder {
	if order == "" {
		return audit.QuerySortDESC
	}
	return order
}

func firstQueryValue(values url.Values, names ...string) string {
	for _, name := range names {
		if raw := values.Get(name); raw != "" {
			return raw
		}
	}
	return ""
}

func parseQuerySort(raw string) (audit.QuerySortField, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", true
	case "timestamp", "time":
		return audit.QuerySortTimestamp, true
	case "client_ip", "client":
		return audit.QuerySortClientIP, true
	case "query_name", "domain":
		return audit.QuerySortQueryName, true
	case "query_type", "type":
		return audit.QuerySortQueryType, true
	case "action":
		return audit.QuerySortAction, true
	case "response":
		return audit.QuerySortResponse, true
	case "rule_id":
		return audit.QuerySortRuleID, true
	case "blocklist_id":
		return audit.QuerySortBlocklistID, true
	case "duration_ns":
		return audit.QuerySortDurationNS, true
	case "duration_ms", "duration":
		return audit.QuerySortDurationMS, true
	case "upstream_resolver", "upstream":
		return audit.QuerySortUpstream, true
	case "cache_status", "cache":
		return audit.QuerySortCacheStatus, true
	case "forward_duration_ns":
		return audit.QuerySortForwardNS, true
	case "forward_duration_ms", "forward_duration", "forward":
		return audit.QuerySortForwardMS, true
	case "retry_count", "retries":
		return audit.QuerySortRetryCount, true
	case "forward_error", "upstream_error":
		return audit.QuerySortForwardErr, true
	default:
		return "", false
	}
}

func parseQueryOrder(raw string) (audit.QuerySortOrder, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", true
	case "asc", "ascending":
		return audit.QuerySortASC, true
	case "desc", "descending":
		return audit.QuerySortDESC, true
	default:
		return "", false
	}
}

func parseOptionalQueryTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, true
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if value, err := time.Parse(layout, raw); err == nil {
			return value, true
		}
	}
	return time.Time{}, false
}

func parseQueryType(raw string) (uint16, bool) {
	raw = strings.ToUpper(strings.TrimSpace(raw))
	qtypeNames := map[string]uint16{
		"A":     1,
		"NS":    2,
		"CNAME": 5,
		"SOA":   6,
		"PTR":   12,
		"MX":    15,
		"TXT":   16,
		"AAAA":  28,
		"SRV":   33,
		"HTTPS": 65,
	}
	if value, ok := qtypeNames[raw]; ok {
		return value, true
	}
	if strings.HasPrefix(raw, "TYPE") {
		raw = strings.TrimPrefix(raw, "TYPE")
	}
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(value), true
}

func parseNonNegativeInt64(raw string) (int64, bool) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}

func parseInt(raw string) (int, bool) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	return value, true
}

func parseDurationMS(raw string) (int64, bool) {
	value, ok := parseNonNegativeInt64(raw)
	if !ok || value > math.MaxInt64/int64(time.Millisecond) {
		return 0, false
	}
	return value * int64(time.Millisecond), true
}

func clientIPString(event audit.Event) string {
	if !event.ClientIP.IsValid() {
		return ""
	}
	return event.ClientIP.String()
}

func queryEventResponses(events []audit.Event) []queryEventResponse {
	queries := make([]queryEventResponse, 0, len(events))
	for _, event := range events {
		queries = append(queries, queryEventResponse{
			Timestamp:         event.Timestamp,
			ClientIP:          clientIPString(event),
			QueryName:         event.QueryName,
			QueryType:         event.QueryType,
			Action:            string(event.Action),
			Reason:            event.Reason,
			Response:          event.Response,
			DurationMS:        event.Duration.Milliseconds(),
			RuleID:            event.RuleID,
			BlocklistID:       event.BlocklistID,
			Upstream:          event.Upstream,
			CacheStatus:       event.CacheStatus,
			ForwardDurationMS: event.ForwardDuration.Milliseconds(),
			RetryCount:        event.RetryCount,
			ForwardError:      event.ForwardError,
		})
	}
	return queries
}

func cloneUpstreams(upstreams []UpstreamSnapshot) []UpstreamSnapshot {
	if len(upstreams) == 0 {
		return []UpstreamSnapshot{}
	}
	cloned := make([]UpstreamSnapshot, len(upstreams))
	copy(cloned, upstreams)
	return cloned
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

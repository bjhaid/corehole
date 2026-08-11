package admin

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/bjhaid/corehole/internal/audit"
)

type auditSettingsReader interface {
	Settings(context.Context) (audit.Settings, error)
}

type auditSettingsWriter interface {
	SetSettings(context.Context, audit.Settings) error
}

type auditSummaryReader interface {
	Summary(context.Context, audit.SummaryOptions) (audit.Summary, error)
}

type auditRetentionCleaner interface {
	CleanupExpired(context.Context, time.Time) (int64, error)
}

type analyticsSummaryResponse struct {
	PrivacyLevel      int                    `json:"privacy_level"`
	TotalQueryCount   int64                  `json:"total_query_count"`
	TotalsByAction    []actionTotalResponse  `json:"totals_by_action"`
	TotalsByCache     []cacheTotalResponse   `json:"totals_by_cache"`
	TopQueriedDomains []domainTotalResponse  `json:"top_queried_domains"`
	TopBlockedDomains []domainTotalResponse  `json:"top_blocked_domains"`
	TopClients        []clientTotalResponse  `json:"top_clients"`
	TopBlockedClients []clientTotalResponse  `json:"top_blocked_clients"`
	RecentTimeBuckets []timeBucketResponse   `json:"recent_time_buckets"`
	ClientTimeBuckets []clientBucketResponse `json:"client_time_buckets"`
}

type actionTotalResponse struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

type cacheTotalResponse struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type domainTotalResponse struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

type clientTotalResponse struct {
	ClientIP string `json:"client_ip"`
	Count    int    `json:"count"`
}

type timeBucketResponse struct {
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Total   int       `json:"total"`
	Allowed int       `json:"allowed"`
	Blocked int       `json:"blocked"`
}

type clientBucketResponse struct {
	Start   time.Time             `json:"start"`
	End     time.Time             `json:"end"`
	Total   int                   `json:"total"`
	Clients []clientTotalResponse `json:"clients"`
}

type analyticsSettingsResponse struct {
	PrivacyLevel             int   `json:"privacy_level"`
	RetentionDurationSeconds int64 `json:"retention_duration_seconds"`
	RetentionEnabled         bool  `json:"retention_enabled"`
}

type analyticsSettingsUpdateRequest struct {
	PrivacyLevel             *int   `json:"privacy_level,omitempty"`
	RetentionDurationSeconds *int64 `json:"retention_duration_seconds,omitempty"`
}

type analyticsCleanupResponse struct {
	Deleted int64 `json:"deleted"`
}

func (s *Server) handleAnalyticsQueries(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusInternalServerError, "analytics_unavailable")
		return
	}
	settings, err := s.auditSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analytics_unavailable")
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

func (s *Server) handleAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	reader, ok := s.auditReader.(auditSummaryReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "analytics_unavailable")
		return
	}

	opts, ok := parseSummaryOptions(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_analytics_options")
		return
	}
	summary, err := reader.Summary(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analytics_unavailable")
		return
	}
	settings, err := s.auditSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analytics_unavailable")
		return
	}

	projected := audit.ProjectSummary(summary, settings.PrivacyLevel)
	writeJSON(w, http.StatusOK, analyticsSummaryResponseFromAudit(projected, settings.PrivacyLevel))
}

func (s *Server) handleAnalyticsSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := s.auditSettings(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "analytics_settings_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, analyticsSettingsResponseFromAudit(settings))
	case http.MethodPut:
		writer, ok := s.auditReader.(auditSettingsWriter)
		if !ok {
			writeError(w, http.StatusServiceUnavailable, "analytics_settings_unavailable")
			return
		}
		settings, err := s.auditSettings(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "analytics_settings_unavailable")
			return
		}
		var req analyticsSettingsUpdateRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.PrivacyLevel != nil {
			settings.PrivacyLevel = audit.PrivacyLevel(*req.PrivacyLevel)
		}
		if req.RetentionDurationSeconds != nil {
			if *req.RetentionDurationSeconds < 0 {
				writeError(w, http.StatusBadRequest, "invalid_analytics_settings")
				return
			}
			settings.RetentionDuration = time.Duration(*req.RetentionDurationSeconds) * time.Second
		}
		if err := writer.SetSettings(r.Context(), settings); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_analytics_settings")
			return
		}
		writeJSON(w, http.StatusOK, analyticsSettingsResponseFromAudit(settings))
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleAnalyticsCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	cleaner, ok := s.auditReader.(auditRetentionCleaner)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "analytics_cleanup_unavailable")
		return
	}
	deleted, err := cleaner.CleanupExpired(r.Context(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analytics_cleanup_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, analyticsCleanupResponse{Deleted: deleted})
}

func (s *Server) auditSettings(ctx context.Context) (audit.Settings, error) {
	reader, ok := s.auditReader.(auditSettingsReader)
	if !ok {
		return audit.DefaultSettings(), nil
	}
	return reader.Settings(ctx)
}

func analyticsSummaryResponseFromAudit(summary audit.Summary, level audit.PrivacyLevel) analyticsSummaryResponse {
	return analyticsSummaryResponse{
		PrivacyLevel:      int(level),
		TotalQueryCount:   summary.TotalQueryCount,
		TotalsByAction:    actionTotalResponses(summary.TotalsByAction),
		TotalsByCache:     cacheTotalResponses(summary.TotalsByCache),
		TopQueriedDomains: domainTotalResponses(summary.TopQueriedDomains),
		TopBlockedDomains: domainTotalResponses(summary.TopBlockedDomains),
		TopClients:        clientTotalResponses(summary.TopClients),
		TopBlockedClients: clientTotalResponses(summary.TopBlockedClients),
		RecentTimeBuckets: timeBucketResponses(summary.RecentTimeBuckets),
		ClientTimeBuckets: clientBucketResponses(summary.ClientTimeBuckets),
	}
}

func analyticsSettingsResponseFromAudit(settings audit.Settings) analyticsSettingsResponse {
	return analyticsSettingsResponse{
		PrivacyLevel:             int(settings.PrivacyLevel),
		RetentionDurationSeconds: int64(settings.RetentionDuration / time.Second),
		RetentionEnabled:         settings.RetentionDuration > 0,
	}
}

func actionTotalResponses(totals []audit.ActionTotal) []actionTotalResponse {
	if len(totals) == 0 {
		return []actionTotalResponse{}
	}
	responses := make([]actionTotalResponse, 0, len(totals))
	for _, total := range totals {
		responses = append(responses, actionTotalResponse{
			Action: total.Action,
			Count:  total.Count,
		})
	}
	return responses
}

func cacheTotalResponses(totals []audit.NamedTotal) []cacheTotalResponse {
	if len(totals) == 0 {
		return []cacheTotalResponse{}
	}
	res := make([]cacheTotalResponse, 0, len(totals))
	for _, total := range totals {
		res = append(res, cacheTotalResponse{Status: total.Name, Count: total.Count})
	}
	return res
}

func domainTotalResponses(totals []audit.NamedTotal) []domainTotalResponse {
	if len(totals) == 0 {
		return []domainTotalResponse{}
	}
	responses := make([]domainTotalResponse, 0, len(totals))
	for _, total := range totals {
		responses = append(responses, domainTotalResponse{
			Domain: total.Name,
			Count:  total.Count,
		})
	}
	return responses
}

func clientTotalResponses(totals []audit.NamedTotal) []clientTotalResponse {
	if len(totals) == 0 {
		return []clientTotalResponse{}
	}
	responses := make([]clientTotalResponse, 0, len(totals))
	for _, total := range totals {
		responses = append(responses, clientTotalResponse{
			ClientIP: total.Name,
			Count:    total.Count,
		})
	}
	return responses
}

func timeBucketResponses(buckets []audit.TimeBucket) []timeBucketResponse {
	if len(buckets) == 0 {
		return []timeBucketResponse{}
	}
	responses := make([]timeBucketResponse, 0, len(buckets))
	for _, bucket := range buckets {
		responses = append(responses, timeBucketResponse{
			Start:   bucket.Start,
			End:     bucket.End,
			Total:   bucket.Total,
			Allowed: bucket.Allowed,
			Blocked: bucket.Blocked,
		})
	}
	return responses
}

func clientBucketResponses(buckets []audit.ClientTimeBucket) []clientBucketResponse {
	if len(buckets) == 0 {
		return []clientBucketResponse{}
	}
	responses := make([]clientBucketResponse, 0, len(buckets))
	for _, bucket := range buckets {
		responses = append(responses, clientBucketResponse{
			Start:   bucket.Start,
			End:     bucket.End,
			Total:   bucket.Total,
			Clients: clientTotalResponses(bucket.Clients),
		})
	}
	return responses
}

func parseSummaryOptions(r *http.Request) (audit.SummaryOptions, bool) {
	query := r.URL.Query()
	opts := audit.SummaryOptions{}

	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			return audit.SummaryOptions{}, false
		}
		opts.TopLimit = limit
	}
	if raw := query.Get("bucket_count"); raw != "" {
		count, err := strconv.Atoi(raw)
		if err != nil || count <= 0 {
			return audit.SummaryOptions{}, false
		}
		opts.BucketCount = count
	}
	if raw := query.Get("bucket_seconds"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds <= 0 {
			return audit.SummaryOptions{}, false
		}
		opts.BucketInterval = time.Duration(seconds) * time.Second
	}
	if raw := query.Get("since"); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return audit.SummaryOptions{}, false
		}
		opts.Since = since
	}
	return opts, true
}

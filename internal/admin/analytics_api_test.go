package admin

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/audit"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
)

func TestAnalyticsEndpointsRequireSession(t *testing.T) {
	server := newTestServer(WithAuditReader(&fakeAnalyticsReader{}))

	tests := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/analytics/queries"},
		{method: http.MethodGet, path: "/api/analytics/summary"},
		{method: http.MethodGet, path: "/api/analytics/settings"},
		{method: http.MethodPut, path: "/api/analytics/settings"},
		{method: http.MethodPost, path: "/api/analytics/cleanup"},
	}
	for _, tt := range tests {
		var resCode int
		switch tt.method {
		case http.MethodGet:
			resCode = get(t, server, tt.path, nil).Code
		case http.MethodPut:
			resCode = putJSON(t, server, tt.path, map[string]any{}, nil).Code
		case http.MethodPost:
			resCode = postJSON(t, server, tt.path, nil, nil).Code
		}
		if resCode != http.StatusUnauthorized {
			t.Fatalf("%s %s status code = %d, want %d", tt.method, tt.path, resCode, http.StatusUnauthorized)
		}
	}
}

func TestAnalyticsSummarySuccessAppliesPrivacy(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	reader := &fakeAnalyticsReader{
		settings: audit.Settings{PrivacyLevel: audit.PrivacyLevelHideClientAndDomain},
		summary: audit.Summary{
			TotalQueryCount:   20,
			TotalsByAction:    []audit.ActionTotal{{Action: "block", Count: 3}, {Action: "allow", Count: 1}},
			TopQueriedDomains: []audit.NamedTotal{{Name: "ads.example.", Count: 3}, {Name: "example.com.", Count: 1}},
			TopBlockedDomains: []audit.NamedTotal{{Name: "ads.example.", Count: 3}},
			TopClients:        []audit.NamedTotal{{Name: "192.0.2.10", Count: 4}},
			TopBlockedClients: []audit.NamedTotal{{Name: "192.0.2.10", Count: 3}},
			RecentTimeBuckets: []audit.TimeBucket{{
				Start:   now.Add(-time.Hour),
				End:     now,
				Total:   4,
				Allowed: 1,
				Blocked: 3,
			}},
			ClientTimeBuckets: []audit.ClientTimeBucket{{
				Start: now.Add(-time.Hour),
				End:   now,
				Total: 4,
				Clients: []audit.NamedTotal{
					{Name: "192.0.2.10", Count: 3},
					{Name: "192.0.2.20", Count: 1},
				},
			}},
		},
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/analytics/summary?limit=5&bucket_count=2&bucket_seconds=60", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	body := decodeResponse[analyticsSummaryResponse](t, res)

	if body.PrivacyLevel != 2 {
		t.Fatalf("privacy_level = %d, want 2", body.PrivacyLevel)
	}
	if body.TotalQueryCount != 20 {
		t.Fatalf("total_query_count = %d, want 20", body.TotalQueryCount)
	}
	if len(body.TopQueriedDomains) != 1 || body.TopQueriedDomains[0].Domain != "" || body.TopQueriedDomains[0].Count != 4 {
		t.Fatalf("top queried domains = %#v, want collapsed hidden domain", body.TopQueriedDomains)
	}
	if len(body.TopBlockedDomains) != 1 || body.TopBlockedDomains[0].Domain != "" || body.TopBlockedDomains[0].Count != 3 {
		t.Fatalf("top blocked domains = %#v, want hidden domain", body.TopBlockedDomains)
	}
	if len(body.TopClients) != 1 || body.TopClients[0].ClientIP != "" || body.TopClients[0].Count != 4 {
		t.Fatalf("top clients = %#v, want hidden client", body.TopClients)
	}
	if len(body.TopBlockedClients) != 1 || body.TopBlockedClients[0].ClientIP != "" || body.TopBlockedClients[0].Count != 3 {
		t.Fatalf("top blocked clients = %#v, want hidden client", body.TopBlockedClients)
	}
	if len(body.ClientTimeBuckets) != 1 ||
		body.ClientTimeBuckets[0].Total != 4 ||
		len(body.ClientTimeBuckets[0].Clients) != 1 ||
		body.ClientTimeBuckets[0].Clients[0].ClientIP != "" ||
		body.ClientTimeBuckets[0].Clients[0].Count != 4 {
		t.Fatalf("client time buckets = %#v, want hidden client bucket", body.ClientTimeBuckets)
	}
	if reader.summaryOpts.TopLimit != 5 || reader.summaryOpts.BucketCount != 2 || reader.summaryOpts.BucketInterval != time.Minute {
		t.Fatalf("summary options = %#v", reader.summaryOpts)
	}
}

func TestQueryAPIsApplyPrivacy(t *testing.T) {
	timestamp := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	reader := &fakeAnalyticsReader{
		settings: audit.Settings{PrivacyLevel: audit.PrivacyLevelHideClientAndDomain},
		events: []audit.Event{{
			Timestamp: timestamp,
			ClientIP:  netip.MustParseAddr("192.0.2.10"),
			QueryName: "ads.example.",
			QueryType: 1,
			Action:    coreholedns.ActionBlock,
		}},
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	for _, path := range []string{"/api/queries", "/api/analytics/queries"} {
		res := get(t, server, path, cookie)
		if res.Code != http.StatusOK {
			t.Fatalf("%s status code = %d, want %d: %s", path, res.Code, http.StatusOK, res.Body.String())
		}
		body := decodeResponse[queriesResponse](t, res)
		if len(body.Queries) != 1 {
			t.Fatalf("%s queries length = %d, want 1", path, len(body.Queries))
		}
		if body.Queries[0].ClientIP != "" || body.Queries[0].QueryName != "" {
			t.Fatalf("%s query = %#v, want hidden client and query", path, body.Queries[0])
		}
	}
}

func TestAnalyticsSettingsAndCleanupSuccess(t *testing.T) {
	reader := &fakeAnalyticsReader{
		cleanupDeleted: 2,
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	update := putJSON(t, server, "/api/analytics/settings", map[string]any{
		"privacy_level":              1,
		"retention_duration_seconds": int64(3600),
	}, cookie)
	if update.Code != http.StatusOK {
		t.Fatalf("settings update status code = %d, want %d: %s", update.Code, http.StatusOK, update.Body.String())
	}
	settingsBody := decodeResponse[analyticsSettingsResponse](t, update)
	if settingsBody.PrivacyLevel != 1 || settingsBody.RetentionDurationSeconds != 3600 || !settingsBody.RetentionEnabled {
		t.Fatalf("settings response = %#v", settingsBody)
	}
	if reader.settings.PrivacyLevel != audit.PrivacyLevelHideClient || reader.settings.RetentionDuration != time.Hour {
		t.Fatalf("saved settings = %#v", reader.settings)
	}

	cleanup := postJSON(t, server, "/api/analytics/cleanup", nil, cookie)
	if cleanup.Code != http.StatusOK {
		t.Fatalf("cleanup status code = %d, want %d: %s", cleanup.Code, http.StatusOK, cleanup.Body.String())
	}
	cleanupBody := decodeResponse[analyticsCleanupResponse](t, cleanup)
	if cleanupBody.Deleted != 2 || reader.cleanupCalls != 1 {
		t.Fatalf("cleanup response = %#v calls=%d", cleanupBody, reader.cleanupCalls)
	}
}

type fakeAnalyticsReader struct {
	events         []audit.Event
	dropped        uint64
	settings       audit.Settings
	summary        audit.Summary
	limit          int
	queryOpts      audit.QueryOptions
	queryCalled    bool
	summaryOpts    audit.SummaryOptions
	cleanupDeleted int64
	cleanupCalls   int
}

func (r *fakeAnalyticsReader) Recent(_ context.Context, limit int) ([]audit.Event, error) {
	r.limit = limit
	return r.events, nil
}

func (r *fakeAnalyticsReader) Query(_ context.Context, opts audit.QueryOptions) ([]audit.Event, error) {
	r.queryCalled = true
	r.queryOpts = opts
	r.limit = opts.Limit
	return r.events, nil
}

func (r *fakeAnalyticsReader) Dropped() uint64 {
	return r.dropped
}

func (r *fakeAnalyticsReader) Settings(context.Context) (audit.Settings, error) {
	return r.settings, nil
}

func (r *fakeAnalyticsReader) SetSettings(_ context.Context, settings audit.Settings) error {
	r.settings = settings
	return nil
}

func (r *fakeAnalyticsReader) Summary(_ context.Context, opts audit.SummaryOptions) (audit.Summary, error) {
	r.summaryOpts = opts
	return r.summary, nil
}

func (r *fakeAnalyticsReader) CleanupExpired(context.Context, time.Time) (int64, error) {
	r.cleanupCalls++
	return r.cleanupDeleted, nil
}

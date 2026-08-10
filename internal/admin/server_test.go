package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/audit"
	"github.com/bjhaid/corehole/internal/config"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/bjhaid/corehole/internal/storage"
)

func TestStatusBeforeSetup(t *testing.T) {
	server := newTestServer()

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	server.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusOK)
	}

	body := decodeResponse[statusResponse](t, res)
	if !body.SetupRequired {
		t.Fatal("setup_required = false, want true")
	}
	if body.Authenticated {
		t.Fatal("authenticated = true, want false")
	}
}

func TestConsoleRootRedirectsToDashboard(t *testing.T) {
	server := newTestServer()

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	server.ServeHTTP(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusFound)
	}
	if got := res.Header().Get("Location"); got != "/admin/dashboard" {
		t.Fatalf("location = %q, want /admin/dashboard", got)
	}
}

func TestConsoleUnknownPathReturnsNotFound(t *testing.T) {
	server := newTestServer()

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	server.ServeHTTP(res, req)

	if res.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusNotFound)
	}
}

func TestSetupCreatesAdminAndSession(t *testing.T) {
	server := newTestServer()

	res := postJSON(t, server, "/api/setup", map[string]string{"password": "correct horse battery staple"}, nil)
	if res.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusCreated)
	}

	cookie := sessionCookie(t, res)
	if !cookie.HttpOnly {
		t.Fatal("session cookie HttpOnly = false, want true")
	}
	if !cookie.Secure {
		t.Fatal("session cookie Secure = false, want true")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie SameSite = %v, want %v", cookie.SameSite, http.SameSiteStrictMode)
	}
	if cookie.Path != "/" {
		t.Fatalf("session cookie Path = %q, want /", cookie.Path)
	}
	if cookie.MaxAge <= 0 {
		t.Fatalf("session cookie MaxAge = %d, want positive", cookie.MaxAge)
	}

	status := statusWithCookie(t, server, cookie)
	if status.SetupRequired {
		t.Fatal("setup_required = true, want false")
	}
	if !status.Authenticated {
		t.Fatal("authenticated = false, want true")
	}
}

func TestSetupCannotRunTwice(t *testing.T) {
	server := newTestServer()

	first := postJSON(t, server, "/api/setup", map[string]string{"password": "first password"}, nil)
	if first.Code != http.StatusCreated {
		t.Fatalf("first setup status code = %d, want %d", first.Code, http.StatusCreated)
	}

	second := postJSON(t, server, "/api/setup", map[string]string{"password": "second password"}, nil)
	if second.Code != http.StatusConflict {
		t.Fatalf("second setup status code = %d, want %d", second.Code, http.StatusConflict)
	}
}

func TestLoginBehavior(t *testing.T) {
	server := newTestServer()

	beforeSetup := postJSON(t, server, "/api/login", map[string]string{"password": "password"}, nil)
	if beforeSetup.Code != http.StatusConflict {
		t.Fatalf("login before setup status code = %d, want %d", beforeSetup.Code, http.StatusConflict)
	}

	setup := postJSON(t, server, "/api/setup", map[string]string{"password": "correct password"}, nil)
	if setup.Code != http.StatusCreated {
		t.Fatalf("setup status code = %d, want %d", setup.Code, http.StatusCreated)
	}

	wrongPassword := postJSON(t, server, "/api/login", map[string]string{"password": "wrong password"}, nil)
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status code = %d, want %d", wrongPassword.Code, http.StatusUnauthorized)
	}
	if got := wrongPassword.Result().Cookies(); len(got) != 0 {
		t.Fatalf("wrong password set %d cookies, want 0", len(got))
	}

	login := postJSON(t, server, "/api/login", map[string]string{"password": "correct password"}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login status code = %d, want %d", login.Code, http.StatusOK)
	}

	status := statusWithCookie(t, server, sessionCookie(t, login))
	if !status.Authenticated {
		t.Fatal("authenticated = false, want true")
	}
}

func TestLogoutRequiresAndInvalidatesSession(t *testing.T) {
	server := newTestServer()

	unauthenticated := postJSON(t, server, "/api/logout", nil, nil)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated logout status code = %d, want %d", unauthenticated.Code, http.StatusUnauthorized)
	}

	setup := postJSON(t, server, "/api/setup", map[string]string{"password": "correct password"}, nil)
	if setup.Code != http.StatusCreated {
		t.Fatalf("setup status code = %d, want %d", setup.Code, http.StatusCreated)
	}
	cookie := sessionCookie(t, setup)

	logout := postJSON(t, server, "/api/logout", nil, cookie)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout status code = %d, want %d", logout.Code, http.StatusNoContent)
	}
	expired := sessionCookie(t, logout)
	if expired.MaxAge != -1 {
		t.Fatalf("expired cookie MaxAge = %d, want -1", expired.MaxAge)
	}

	status := statusWithCookie(t, server, cookie)
	if status.Authenticated {
		t.Fatal("authenticated = true after logout, want false")
	}
}

func TestProtectedAPIRequiresSession(t *testing.T) {
	server := newTestServer()

	for _, path := range []string{"/api/dashboard", "/api/queries", "/api/config", "/api/blocking/status", "/api/api-keys"} {
		res := get(t, server, path, nil)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("%s status code = %d, want %d", path, res.Code, http.StatusUnauthorized)
		}
	}
	res := putJSON(t, server, "/api/config", map[string]any{}, nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("PUT /api/config status code = %d, want %d", res.Code, http.StatusUnauthorized)
	}

	status := get(t, server, "/api/status", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", status.Code, http.StatusOK)
	}
}

func TestAPIKeyCreateListAndRevoke(t *testing.T) {
	server := newTestServer()
	cookie := setupSession(t, server)

	create := postJSON(t, server, "/api/api-keys", map[string]string{"name": "automation"}, cookie)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status code = %d, want %d: %s", create.Code, http.StatusCreated, create.Body.String())
	}
	created := decodeResponse[apiKeyCreateResponse](t, create)
	if created.Key == "" {
		t.Fatal("created key is empty")
	}
	if !bytes.HasPrefix([]byte(created.Key), []byte(apiKeySecretPrefix)) {
		t.Fatalf("created key prefix = %q, want %q", created.Key[:len(apiKeySecretPrefix)], apiKeySecretPrefix)
	}
	if created.APIKey.ID == 0 || created.APIKey.Name != "automation" {
		t.Fatalf("created api key metadata = %#v", created.APIKey)
	}
	if created.APIKey.Last4 != apiKeyLast4(created.Key) {
		t.Fatalf("created last4 = %q, want %q", created.APIKey.Last4, apiKeyLast4(created.Key))
	}

	list := get(t, server, "/api/api-keys", cookie)
	if list.Code != http.StatusOK {
		t.Fatalf("list status code = %d, want %d", list.Code, http.StatusOK)
	}
	if bytes.Contains(list.Body.Bytes(), []byte(created.Key)) {
		t.Fatal("list response contained raw api key")
	}
	listed := decodeResponse[apiKeyListResponse](t, list)
	if len(listed.APIKeys) != 1 {
		t.Fatalf("listed api keys = %d, want 1", len(listed.APIKeys))
	}
	if listed.APIKeys[0].ID != created.APIKey.ID || listed.APIKeys[0].Name != "automation" {
		t.Fatalf("listed api key = %#v, want created metadata", listed.APIKeys[0])
	}

	revoke := deleteReq(t, server, "/api/api-keys/"+strconv.FormatInt(created.APIKey.ID, 10), cookie)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke status code = %d, want %d", revoke.Code, http.StatusNoContent)
	}

	afterRevoke := get(t, server, "/api/api-keys", cookie)
	listed = decodeResponse[apiKeyListResponse](t, afterRevoke)
	if len(listed.APIKeys) != 1 {
		t.Fatalf("api keys after revoke = %d, want 1", len(listed.APIKeys))
	}
	if !listed.APIKeys[0].Disabled || listed.APIKeys[0].RevokedAt == nil {
		t.Fatalf("revoked api key = %#v, want disabled with revoked_at", listed.APIKeys[0])
	}
}

func TestBearerAPIKeyAuthenticatesProtectedAPI(t *testing.T) {
	server := newTestServer()
	cookie := setupSession(t, server)
	created := createTestAPIKey(t, server, cookie, "automation")

	res := getWithBearer(t, server, "/api/config", created.Key)
	if res.Code != http.StatusOK {
		t.Fatalf("bearer auth status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}

	list := get(t, server, "/api/api-keys", cookie)
	listed := decodeResponse[apiKeyListResponse](t, list)
	if len(listed.APIKeys) != 1 {
		t.Fatalf("listed api keys = %d, want 1", len(listed.APIKeys))
	}
	if listed.APIKeys[0].LastUsedAt == nil {
		t.Fatal("last_used_at = nil after bearer-authenticated request, want timestamp")
	}
}

func TestSQLiteAPIKeyPersistsAcrossServerReconstruction(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "corehole.db")
	store := openTestStoragePath(t, ctx, dbPath)
	server := newTestServerWithUserStore(NewSQLiteUserStore(store.DB()))
	cookie := setupSession(t, server)
	created := createTestAPIKey(t, server, cookie, "automation")

	list := get(t, server, "/api/api-keys", cookie)
	if list.Code != http.StatusOK {
		t.Fatalf("list status code = %d, want %d", list.Code, http.StatusOK)
	}
	if bytes.Contains(list.Body.Bytes(), []byte(created.Key)) {
		t.Fatal("list response contained raw api key")
	}
	listed := decodeResponse[apiKeyListResponse](t, list)
	if len(listed.APIKeys) != 1 {
		t.Fatalf("listed api keys = %d, want 1", len(listed.APIKeys))
	}
	if listed.APIKeys[0].ID != created.APIKey.ID || listed.APIKeys[0].Prefix != apiKeyPrefix(created.Key) || listed.APIKeys[0].Last4 != apiKeyLast4(created.Key) {
		t.Fatalf("listed api key metadata = %#v, want created key prefix/last4", listed.APIKeys[0])
	}
	assertStoredAPIKeyMetadataOnly(t, ctx, store, created)
	closeTestStorage(t, ctx, store)

	store = openTestStoragePath(t, ctx, dbPath)
	restarted := newTestServerWithUserStore(NewSQLiteUserStore(store.DB()))

	authenticated := getWithBearer(t, restarted, "/api/config", created.Key)
	if authenticated.Code != http.StatusOK {
		t.Fatalf("restarted bearer auth status code = %d, want %d: %s", authenticated.Code, http.StatusOK, authenticated.Body.String())
	}
	closeTestStorage(t, ctx, store)

	store = openTestStoragePath(t, ctx, dbPath)
	defer closeTestStorage(t, ctx, store)
	restarted = newTestServerWithUserStore(NewSQLiteUserStore(store.DB()))
	loginCookie := loginSession(t, restarted, "correct password")
	afterUse := get(t, restarted, "/api/api-keys", loginCookie)
	if afterUse.Code != http.StatusOK {
		t.Fatalf("list after restart status code = %d, want %d", afterUse.Code, http.StatusOK)
	}
	listed = decodeResponse[apiKeyListResponse](t, afterUse)
	if len(listed.APIKeys) != 1 {
		t.Fatalf("listed api keys after restart = %d, want 1", len(listed.APIKeys))
	}
	if listed.APIKeys[0].LastUsedAt == nil {
		t.Fatal("last_used_at = nil after successful bearer auth and restart, want persisted timestamp")
	}
}

func TestSQLiteRevokedAPIKeyRemainsRevokedAcrossServerReconstruction(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "corehole.db")
	store := openTestStoragePath(t, ctx, dbPath)
	server := newTestServerWithUserStore(NewSQLiteUserStore(store.DB()))
	cookie := setupSession(t, server)
	created := createTestAPIKey(t, server, cookie, "automation")

	revoke := deleteReq(t, server, "/api/api-keys/"+strconv.FormatInt(created.APIKey.ID, 10), cookie)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke status code = %d, want %d", revoke.Code, http.StatusNoContent)
	}
	closeTestStorage(t, ctx, store)

	store = openTestStoragePath(t, ctx, dbPath)
	defer closeTestStorage(t, ctx, store)
	restarted := newTestServerWithUserStore(NewSQLiteUserStore(store.DB()))

	revoked := getWithBearer(t, restarted, "/api/config", created.Key)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key after restart status code = %d, want %d", revoked.Code, http.StatusUnauthorized)
	}

	loginCookie := loginSession(t, restarted, "correct password")
	list := get(t, restarted, "/api/api-keys", loginCookie)
	if list.Code != http.StatusOK {
		t.Fatalf("list status code = %d, want %d", list.Code, http.StatusOK)
	}
	listed := decodeResponse[apiKeyListResponse](t, list)
	if len(listed.APIKeys) != 1 {
		t.Fatalf("listed api keys = %d, want 1", len(listed.APIKeys))
	}
	if !listed.APIKeys[0].Disabled || listed.APIKeys[0].RevokedAt == nil {
		t.Fatalf("revoked api key after restart = %#v, want disabled with revoked_at", listed.APIKeys[0])
	}
}

func TestAPIKeyAuthenticationFailures(t *testing.T) {
	server := newTestServer()
	cookie := setupSession(t, server)
	created := createTestAPIKey(t, server, cookie, "automation")

	invalid := getWithBearer(t, server, "/api/config", "not-a-real-key")
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid key status code = %d, want %d", invalid.Code, http.StatusUnauthorized)
	}

	revoke := deleteReq(t, server, "/api/api-keys/"+strconv.FormatInt(created.APIKey.ID, 10), cookie)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke status code = %d, want %d", revoke.Code, http.StatusNoContent)
	}

	revoked := getWithBearer(t, server, "/api/config", created.Key)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key status code = %d, want %d", revoked.Code, http.StatusUnauthorized)
	}
}

func TestCookieAuthStillWorksWithAPIKeyStore(t *testing.T) {
	server := newTestServer()
	cookie := setupSession(t, server)

	res := get(t, server, "/api/config", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("cookie auth status code = %d, want %d", res.Code, http.StatusOK)
	}
}

func TestDashboardPayload(t *testing.T) {
	reader := &fakeAuditReader{
		events: []audit.Event{
			{Action: coreholedns.ActionAllow, QueryName: "example.com."},
			{Action: coreholedns.ActionBlock, QueryName: "ads.example."},
			{Action: coreholedns.ActionBlock, QueryName: "track.example."},
		},
		dropped: 4,
		totals: audit.Totals{
			TotalQueries:   200,
			AllowedQueries: 150,
			BlockedQueries: 50,
		},
	}
	server := newTestServer(
		WithAuditReader(reader),
		WithConfigSnapshot(ConfigSnapshot{
			DNSListen:        ":5353",
			AdminListen:      "127.0.0.1:8080",
			BlockingResponse: "nxdomain",
			StoragePath:      "corehole.db",
			Upstreams: []UpstreamSnapshot{{
				Name:     "cloudflare",
				Address:  "1.1.1.1:53",
				Protocol: "udp",
			}},
			Blocklists: []string{"ads.txt", "tracking.txt"},
		}),
	)
	cookie := setupSession(t, server)

	res := get(t, server, "/api/dashboard", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusOK)
	}
	body := decodeResponse[dashboardResponse](t, res)

	if body.SetupRequired {
		t.Fatal("setup_required = true, want false")
	}
	if !body.Authenticated {
		t.Fatal("authenticated = false, want true")
	}
	if body.TotalQueries != 200 {
		t.Fatalf("total_queries = %d, want 200", body.TotalQueries)
	}
	if body.BlockedQueries != 50 {
		t.Fatalf("blocked_queries = %d, want 50", body.BlockedQueries)
	}
	if body.AllowedQueries != 150 {
		t.Fatalf("allowed_queries = %d, want 150", body.AllowedQueries)
	}
	if body.TotalRecentQueries != 3 {
		t.Fatalf("total_recent_queries = %d, want 3", body.TotalRecentQueries)
	}
	if body.BlockedRecentQueries != 2 {
		t.Fatalf("blocked_recent_queries = %d, want 2", body.BlockedRecentQueries)
	}
	if body.AllowedRecentQueries != 1 {
		t.Fatalf("allowed_recent_queries = %d, want 1", body.AllowedRecentQueries)
	}
	if body.DroppedAuditEvents != 4 {
		t.Fatalf("dropped_audit_events = %d, want 4", body.DroppedAuditEvents)
	}
	if body.DNSListen != ":5353" || body.AdminListen != "127.0.0.1:8080" || body.BlockingResponse != "nxdomain" {
		t.Fatalf("unexpected listener/blocking fields: %#v", body)
	}
	if len(body.Upstreams) != 1 || body.Upstreams[0].Name != "cloudflare" {
		t.Fatalf("upstreams = %#v, want cloudflare entry", body.Upstreams)
	}
	if body.BlocklistCount != 2 || len(body.Blocklists) != 2 {
		t.Fatalf("blocklists = %#v count=%d, want 2 entries", body.Blocklists, body.BlocklistCount)
	}
}

func TestDashboardUsesAllTimeAuditTotalsFromSQLiteReader(t *testing.T) {
	ctx := context.Background()
	store := openTestStorage(t, ctx)
	defer closeTestStorage(t, ctx, store)

	sink, err := audit.NewSQLiteSink(
		store.DB(),
		audit.WithBatchSize(1),
		audit.WithFlushInterval(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewSQLiteSink() error = %v", err)
	}
	defer func() {
		if err := sink.Close(ctx); err != nil {
			t.Fatalf("SQLiteSink.Close() error = %v", err)
		}
	}()

	server := newTestServerWithUserStore(NewSQLiteUserStore(store.DB()), WithAuditReader(sink))
	cookie := setupSession(t, server)

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	sink.Record(ctx, audit.Event{Timestamp: base, QueryName: "one.example.", QueryType: 1, Action: coreholedns.ActionAllow})
	sink.Record(ctx, audit.Event{Timestamp: base.Add(time.Second), QueryName: "two.example.", QueryType: 1, Action: coreholedns.ActionBlock})
	sink.Record(ctx, audit.Event{Timestamp: base.Add(2 * time.Second), QueryName: "three.example.", QueryType: 1, Action: coreholedns.ActionBlock})
	waitForDashboardTotals(t, ctx, sink, audit.Totals{TotalQueries: 3, AllowedQueries: 1, BlockedQueries: 2})

	first := get(t, server, "/api/dashboard", cookie)
	if first.Code != http.StatusOK {
		t.Fatalf("first dashboard status code = %d, want %d: %s", first.Code, http.StatusOK, first.Body.String())
	}
	firstBody := decodeResponse[dashboardResponse](t, first)
	if firstBody.TotalQueries != 3 || firstBody.AllowedQueries != 1 || firstBody.BlockedQueries != 2 {
		t.Fatalf("first dashboard totals = %#v, want total 3 allowed 1 blocked 2", firstBody)
	}

	sink.Record(ctx, audit.Event{Timestamp: base.Add(3 * time.Second), QueryName: "four.example.", QueryType: 1, Action: coreholedns.ActionAllow})
	waitForDashboardTotals(t, ctx, sink, audit.Totals{TotalQueries: 4, AllowedQueries: 2, BlockedQueries: 2})

	refreshed := get(t, server, "/api/dashboard", cookie)
	if refreshed.Code != http.StatusOK {
		t.Fatalf("refreshed dashboard status code = %d, want %d: %s", refreshed.Code, http.StatusOK, refreshed.Body.String())
	}
	refreshedBody := decodeResponse[dashboardResponse](t, refreshed)
	if refreshedBody.TotalQueries != 4 || refreshedBody.AllowedQueries != 2 || refreshedBody.BlockedQueries != 2 {
		t.Fatalf("refreshed dashboard totals = %#v, want total 4 allowed 2 blocked 2", refreshedBody)
	}
}

func TestQueriesPayloadAndLimit(t *testing.T) {
	timestamp := time.Date(2026, 8, 9, 12, 30, 0, 0, time.UTC)
	reader := &fakeAuditReader{
		events: []audit.Event{{
			Timestamp:       timestamp,
			ClientIP:        netip.MustParseAddr("192.0.2.10"),
			QueryName:       "ads.example.",
			QueryType:       1,
			Action:          coreholedns.ActionBlock,
			Reason:          "blocklist deny match",
			Response:        "NXDOMAIN",
			Duration:        25 * time.Millisecond,
			RuleID:          42,
			BlocklistID:     7,
			Upstream:        "1.1.1.1:53",
			CacheStatus:     "miss",
			ForwardDuration: 24 * time.Millisecond,
			RetryCount:      -1,
			ForwardError:    "upstream timeout",
		}},
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/queries", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusOK)
	}
	if reader.limit != defaultQueriesLimit+1 {
		t.Fatalf("internal default limit = %d, want %d", reader.limit, defaultQueriesLimit+1)
	}
	if !bytes.Contains(res.Body.Bytes(), []byte(`"query_name":"ads.example."`)) {
		t.Fatalf("queries response missing populated query_name: %s", res.Body.String())
	}

	body := decodeResponse[queriesResponse](t, res)
	if len(body.Queries) != 1 {
		t.Fatalf("queries length = %d, want 1", len(body.Queries))
	}
	if body.Limit != defaultQueriesLimit || body.Offset != 0 || body.HasNext || body.HasPrevious || body.NextOffset != nil || body.PreviousOffset != nil {
		t.Fatalf("pagination metadata = %#v", body)
	}
	if body.Sort != "timestamp" || body.Order != "desc" {
		t.Fatalf("sort metadata = sort %q order %q, want timestamp desc", body.Sort, body.Order)
	}
	query := body.Queries[0]
	if !query.Timestamp.Equal(timestamp) {
		t.Fatalf("timestamp = %s, want %s", query.Timestamp, timestamp)
	}
	if query.ClientIP != "192.0.2.10" ||
		query.QueryName != "ads.example." ||
		query.QueryType != 1 ||
		query.Action != "block" ||
		query.Reason != "blocklist deny match" ||
		query.Response != "NXDOMAIN" ||
		query.DurationMS != 25 ||
		query.RuleID != 42 ||
		query.BlocklistID != 7 ||
		query.Upstream != "1.1.1.1:53" ||
		query.CacheStatus != "miss" ||
		query.ForwardDurationMS != 24 ||
		query.RetryCount != -1 ||
		query.ForwardError != "upstream timeout" {
		t.Fatalf("query payload = %#v", query)
	}

	capped := get(t, server, "/api/queries?limit=999", cookie)
	if capped.Code != http.StatusOK {
		t.Fatalf("capped status code = %d, want %d", capped.Code, http.StatusOK)
	}
	if reader.limit != maxQueriesLimit+1 {
		t.Fatalf("capped internal limit = %d, want %d", reader.limit, maxQueriesLimit+1)
	}
}

func TestQueriesPassesFilterAndSortOptions(t *testing.T) {
	timestamp := time.Date(2026, 8, 9, 12, 30, 0, 0, time.UTC)
	reader := &fakeAuditReader{
		events: []audit.Event{{
			Timestamp:       timestamp,
			ClientIP:        netip.MustParseAddr("192.0.2.10"),
			QueryName:       "ads.example.",
			QueryType:       28,
			Action:          coreholedns.ActionBlock,
			Response:        "NXDOMAIN",
			Duration:        25 * time.Millisecond,
			RuleID:          42,
			BlocklistID:     7,
			Upstream:        "1.1.1.1:53",
			CacheStatus:     "miss",
			ForwardDuration: 24 * time.Millisecond,
			RetryCount:      -1,
			ForwardError:    "upstream timeout",
		}},
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/queries?limit=50&offset=100&sort=upstream_resolver&order=asc&from=2026-08-09T12:00:00Z&to=2026-08-09T13:00:00Z&client_ip=192.0.2.10&domain=ads.example.&type=AAAA&action=block&response=nxdomain&rule_id=42&blocklist_id=7&duration_min=20&duration_max=30&upstream_resolver=1.1.1.1:53&cache_status=miss&forward_duration_min_ms=20&forward_duration_max_ms=30&retry_count=-1&forward_error=upstream+timeout", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	if !reader.queryCalled {
		t.Fatal("Query() was not called")
	}
	opts := reader.queryOpts
	if opts.Limit != 51 ||
		opts.Offset != 100 ||
		opts.Sort != audit.QuerySortUpstream ||
		opts.Order != audit.QuerySortASC ||
		opts.ClientIP != "192.0.2.10" ||
		opts.QueryName != "ads.example." ||
		opts.QueryType != 28 ||
		!opts.HasQueryType ||
		opts.Action != "block" ||
		opts.Response != "NXDOMAIN" ||
		opts.RuleID != 42 ||
		!opts.HasRuleID ||
		opts.BlocklistID != 7 ||
		!opts.HasBlocklistID ||
		opts.DurationMinNS != int64(20*time.Millisecond) ||
		!opts.HasDurationMin ||
		opts.DurationMaxNS != int64(30*time.Millisecond) ||
		!opts.HasDurationMax ||
		opts.Upstream != "1.1.1.1:53" ||
		opts.CacheStatus != "miss" ||
		opts.ForwardMinNS != int64(20*time.Millisecond) ||
		!opts.HasForwardMin ||
		opts.ForwardMaxNS != int64(30*time.Millisecond) ||
		!opts.HasForwardMax ||
		opts.RetryCount != -1 ||
		!opts.HasRetryCount ||
		opts.ForwardError != "upstream timeout" {
		t.Fatalf("query options = %#v", opts)
	}
	if opts.From.IsZero() || opts.To.IsZero() {
		t.Fatalf("query time range = from %s to %s, want populated", opts.From, opts.To)
	}
}

func TestQueriesPaginationMetadataOmitsTotalCountBecauseFilteredCountCanBeExpensive(t *testing.T) {
	reader := &fakeAuditReader{
		events: []audit.Event{
			{Timestamp: time.Date(2026, 8, 9, 12, 30, 0, 0, time.UTC), QueryName: "one.example."},
			{Timestamp: time.Date(2026, 8, 9, 12, 29, 0, 0, time.UTC), QueryName: "two.example."},
			{Timestamp: time.Date(2026, 8, 9, 12, 28, 0, 0, time.UTC), QueryName: "three.example."},
		},
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/queries?limit=2&offset=4&sort=action&order=asc", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	body := decodeResponse[queriesResponse](t, res)
	if len(body.Queries) != 2 {
		t.Fatalf("queries length = %d, want 2", len(body.Queries))
	}
	if body.Limit != 2 || body.Offset != 4 || !body.HasNext || !body.HasPrevious {
		t.Fatalf("pagination metadata = %#v", body)
	}
	if body.NextOffset == nil || *body.NextOffset != 6 {
		t.Fatalf("next_offset = %v, want 6", body.NextOffset)
	}
	if body.PreviousOffset == nil || *body.PreviousOffset != 2 {
		t.Fatalf("previous_offset = %v, want 2", body.PreviousOffset)
	}
	if body.Sort != "action" || body.Order != "asc" {
		t.Fatalf("sort metadata = sort %q order %q, want action asc", body.Sort, body.Order)
	}
	if bytes.Contains(res.Body.Bytes(), []byte("total_count")) {
		t.Fatalf("query pagination response includes total_count: %s", res.Body.String())
	}
	if reader.queryOpts.Limit != 3 || reader.queryOpts.Offset != 4 {
		t.Fatalf("query opts = %#v, want sentinel limit and requested offset", reader.queryOpts)
	}
}

func TestQueriesRejectsInvalidSort(t *testing.T) {
	server := newTestServer(WithAuditReader(&fakeAuditReader{}))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/queries?sort=reason", cookie)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusBadRequest)
	}
	if !bytes.Contains(res.Body.Bytes(), []byte("invalid_query_options")) {
		t.Fatalf("body = %s, want invalid_query_options", res.Body.String())
	}
}

func TestQueriesRejectsInvalidOffset(t *testing.T) {
	server := newTestServer(WithAuditReader(&fakeAuditReader{}))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/queries?offset=-1", cookie)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusBadRequest)
	}
	if !bytes.Contains(res.Body.Bytes(), []byte("invalid_offset")) {
		t.Fatalf("body = %s, want invalid_offset", res.Body.String())
	}
}

func TestQueriesAppliesPrivacyProjectionAfterFiltering(t *testing.T) {
	reader := &fakeAnalyticsReader{
		settings: audit.Settings{PrivacyLevel: audit.PrivacyLevelHideClientAndDomain},
		events: []audit.Event{{
			Timestamp: time.Date(2026, 8, 9, 12, 30, 0, 0, time.UTC),
			ClientIP:  netip.MustParseAddr("192.0.2.10"),
			QueryName: "private.example.",
			QueryType: 1,
			Action:    coreholedns.ActionAllow,
		}},
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/queries?client_ip=192.0.2.10&domain=private.example.", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	body := decodeResponse[queriesResponse](t, res)
	if len(body.Queries) != 1 {
		t.Fatalf("queries length = %d, want 1", len(body.Queries))
	}
	if body.Queries[0].ClientIP != "" || body.Queries[0].QueryName != "" {
		t.Fatalf("projected query = %#v, want hidden client and domain", body.Queries[0])
	}
	if !reader.queryCalled || reader.queryOpts.ClientIP != "192.0.2.10" || reader.queryOpts.QueryName != "private.example." {
		t.Fatalf("query options = %#v called=%v", reader.queryOpts, reader.queryCalled)
	}
}

func TestConfigPayload(t *testing.T) {
	server := newTestServer(WithConfigSnapshot(ConfigSnapshot{
		DNSListen:   ":5353",
		AdminListen: "127.0.0.1:8080",
		CacheTTL:    300,
		DNSSEC:      DNSSECSnapshot{Enabled: true, Mode: "upstream"},
		ConditionalForwarding: ConditionalForwardingSnapshot{
			Enabled:  true,
			Domain:   "lan",
			Resolver: "192.168.1.1:53",
		},
		BlockingResponse: "null-ip",
		StoragePath:      "/var/lib/corehole/corehole.db",
		Upstreams: []UpstreamSnapshot{
			{Name: "cloudflare", Address: "1.1.1.1:53", Protocol: "udp", TLSServerName: "cloudflare-dns.com"},
			{Name: "quad9", Address: "9.9.9.9:53", Protocol: "udp"},
		},
		Blocklists:      []string{"/etc/corehole/ads.txt"},
		BlockingBundled: true,
	}))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/config", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusOK)
	}
	body := decodeResponse[configResponse](t, res)

	if body.DNSListen != ":5353" ||
		body.AdminListen != "127.0.0.1:8080" ||
		body.CacheTTL != 300 ||
		!body.DNSSEC.Enabled ||
		body.DNSSEC.Mode != "upstream" ||
		!body.ConditionalForwarding.Enabled ||
		body.ConditionalForwarding.Domain != "lan" ||
		body.ConditionalForwarding.Resolver != "192.168.1.1:53" ||
		body.BlockingResponse != "null-ip" ||
		!body.BlockingBundled ||
		body.StoragePath != "/var/lib/corehole/corehole.db" {
		t.Fatalf("config payload = %#v", body)
	}
	if len(body.Upstreams) != 2 {
		t.Fatalf("upstreams length = %d, want 2", len(body.Upstreams))
	}
	if body.Upstreams[0].TLSServerName != "cloudflare-dns.com" {
		t.Fatalf("upstream tls_server_name = %q, want cloudflare-dns.com", body.Upstreams[0].TLSServerName)
	}
	if body.BlocklistCount != 1 || len(body.Blocklists) != 1 || body.Blocklists[0] != "/etc/corehole/ads.txt" {
		t.Fatalf("blocklists = %#v count=%d, want path/count", body.Blocklists, body.BlocklistCount)
	}
}

func TestBlockingStatusAPI(t *testing.T) {
	controller := &fakeBlockingController{
		status: BlockingStatus{
			Paused:           true,
			Indefinite:       true,
			RemainingSeconds: 0,
		},
	}
	server := newTestServer(WithBlockingController(controller))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/blocking/status", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	body := decodeResponse[BlockingStatus](t, res)
	if !body.Paused || !body.Indefinite {
		t.Fatalf("blocking status = %#v, want indefinite pause", body)
	}
	if controller.statusCalls != 1 {
		t.Fatalf("statusCalls = %d, want 1", controller.statusCalls)
	}
}

func TestBlockingStatusAPIPauseForDuration(t *testing.T) {
	controller := &fakeBlockingController{}
	server := newTestServer(WithBlockingController(controller))
	cookie := setupSession(t, server)

	started := time.Now()
	res := putJSON(t, server, "/api/blocking/status", map[string]any{
		"paused":           true,
		"duration_seconds": 300,
	}, cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	if controller.pauseCount != 1 {
		t.Fatalf("pauseCount = %d, want 1", controller.pauseCount)
	}
	if controller.until.Before(started.Add(295*time.Second)) || controller.until.After(started.Add(305*time.Second)) {
		t.Fatalf("pause until = %s, want about 5 minutes from now", controller.until)
	}
	body := decodeResponse[BlockingStatus](t, res)
	if !body.Paused || body.Indefinite {
		t.Fatalf("blocking status = %#v, want timed pause", body)
	}
}

func TestBlockingStatusAPIPauseIndefinitely(t *testing.T) {
	controller := &fakeBlockingController{}
	server := newTestServer(WithBlockingController(controller))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/blocking/status", map[string]any{
		"paused": true,
	}, cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	if controller.pauseCount != 1 {
		t.Fatalf("pauseCount = %d, want 1", controller.pauseCount)
	}
	if !controller.until.IsZero() {
		t.Fatalf("pause until = %s, want zero time for indefinite", controller.until)
	}
	body := decodeResponse[BlockingStatus](t, res)
	if !body.Paused || !body.Indefinite {
		t.Fatalf("blocking status = %#v, want indefinite pause", body)
	}
}

func TestBlockingStatusAPIResume(t *testing.T) {
	controller := &fakeBlockingController{status: BlockingStatus{Paused: true, Indefinite: true}}
	server := newTestServer(WithBlockingController(controller))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/blocking/status", map[string]any{
		"paused": false,
	}, cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	if controller.resumeCount != 1 {
		t.Fatalf("resumeCount = %d, want 1", controller.resumeCount)
	}
	body := decodeResponse[BlockingStatus](t, res)
	if body.Paused {
		t.Fatalf("blocking status = %#v, want resumed", body)
	}
}

func TestBlockingStatusAPIRejectsInvalidDuration(t *testing.T) {
	server := newTestServer(WithBlockingController(&fakeBlockingController{}))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/blocking/status", map[string]any{
		"paused":           true,
		"duration_seconds": 0,
	}, cookie)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusBadRequest, res.Body.String())
	}
}

func TestConfigUpdateRejectsInvalidConfig(t *testing.T) {
	store := &fakeConfigStore{cfg: config.Default()}
	server := newTestServer(WithConfigStore(store))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/config", map[string]any{
		"blocking": map[string]any{
			"response": "bogus",
		},
	}, cookie)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusBadRequest)
	}
	if store.saveCount != 0 {
		t.Fatalf("saveCount = %d, want 0", store.saveCount)
	}
}

func TestConfigUpdateSavesSafeFields(t *testing.T) {
	initial := config.Default()
	store := &fakeConfigStore{cfg: initial}
	server := newTestServer(WithConfigStore(store))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/config", map[string]any{
		"dns": map[string]any{
			"listen":    ":5353",
			"cache_ttl": 300,
			"dnssec": map[string]any{
				"enabled": true,
				"mode":    "upstream",
			},
			"conditional_forwarding": map[string]any{
				"enabled":  true,
				"domain":   "lan",
				"resolver": "192.168.1.1:53",
			},
			"resolvers": []map[string]any{{
				"name":            "quad9",
				"address":         "9.9.9.9:853",
				"protocol":        "tls",
				"tls_server_name": "dns.quad9.net",
			}},
		},
		"admin": map[string]any{
			"listen": "127.0.0.1:9090",
		},
		"blocking": map[string]any{
			"response":   "refused",
			"bundled":    false,
			"blocklists": []string{"ads.txt", "tracking.txt"},
		},
	}, cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}

	body := decodeResponse[configUpdateResponse](t, res)
	if !body.RestartRequired {
		t.Fatal("restart_required = false, want true")
	}
	if body.Config.DNSListen != ":5353" ||
		body.Config.AdminListen != "127.0.0.1:9090" ||
		body.Config.CacheTTL != 300 ||
		!body.Config.DNSSEC.Enabled ||
		body.Config.DNSSEC.Mode != "upstream" ||
		!body.Config.ConditionalForwarding.Enabled ||
		body.Config.ConditionalForwarding.Domain != "lan" ||
		body.Config.BlockingResponse != "refused" ||
		body.Config.BlockingBundled {
		t.Fatalf("config update response = %#v", body.Config)
	}
	if len(body.Config.Upstreams) != 1 || body.Config.Upstreams[0].Name != "quad9" {
		t.Fatalf("upstreams = %#v, want quad9", body.Config.Upstreams)
	}
	if body.Config.Upstreams[0].TLSServerName != "dns.quad9.net" {
		t.Fatalf("upstream tls_server_name = %q, want dns.quad9.net", body.Config.Upstreams[0].TLSServerName)
	}
	if body.Config.BlocklistCount != 2 {
		t.Fatalf("blocklist_count = %d, want 2", body.Config.BlocklistCount)
	}
	if store.saveCount != 1 {
		t.Fatalf("saveCount = %d, want 1", store.saveCount)
	}
	if store.cfg.Storage.Path != initial.Storage.Path {
		t.Fatalf("storage.path = %q, want preserved %q", store.cfg.Storage.Path, initial.Storage.Path)
	}
	if !store.cfg.DNS.Resolvers[0].Enabled {
		t.Fatal("resolver enabled = false, want default true")
	}
	if store.cfg.DNS.CacheTTL != 300 || !store.cfg.DNS.ConditionalForwarding.Enabled {
		t.Fatalf("stored dns config = %#v, want cache TTL and conditional forwarding", store.cfg.DNS)
	}
	if !store.cfg.DNS.DNSSEC.Enabled || store.cfg.DNS.DNSSEC.Mode != config.DNSSECModeUpstream {
		t.Fatalf("stored dnssec config = %#v, want upstream enabled", store.cfg.DNS.DNSSEC)
	}
}

func TestConfigUpdateDNSSECReloadsImmediately(t *testing.T) {
	initial := config.Default()
	store := &fakeConfigStore{cfg: initial}
	reloader := &fakeDNSReloader{}
	server := newTestServer(WithConfigStoreAndDNSReloader(store, reloader))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/config", map[string]any{
		"dns": map[string]any{
			"dnssec": map[string]any{
				"enabled": true,
				"mode":    "upstream",
			},
		},
	}, cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}

	body := decodeResponse[configUpdateResponse](t, res)
	if body.RestartRequired {
		t.Fatal("restart_required = true, want false")
	}
	if !body.Config.DNSSEC.Enabled || body.Config.DNSSEC.Mode != "upstream" {
		t.Fatalf("dnssec response = %#v, want upstream enabled", body.Config.DNSSEC)
	}
	if reloader.reloadCount != 1 {
		t.Fatalf("reloadCount = %d, want 1", reloader.reloadCount)
	}
	if !reloader.last.DNS.DNSSEC.Enabled || reloader.last.DNS.DNSSEC.Mode != config.DNSSECModeUpstream {
		t.Fatalf("reloaded dnssec = %#v, want upstream enabled", reloader.last.DNS.DNSSEC)
	}
	if store.saveCount != 1 {
		t.Fatalf("saveCount = %d, want 1", store.saveCount)
	}
}

func TestConfigUpdateRejectsLocalDNSSECMode(t *testing.T) {
	store := &fakeConfigStore{cfg: config.Default()}
	server := newTestServer(WithConfigStore(store))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/config", map[string]any{
		"dns": map[string]any{
			"dnssec": map[string]any{
				"enabled": true,
				"mode":    "local",
			},
		},
	}, cookie)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusBadRequest)
	}
	if store.saveCount != 0 {
		t.Fatalf("saveCount = %d, want 0", store.saveCount)
	}
}

func TestConfigUpdateDNSSECModeOnlyUpdatesEnabledState(t *testing.T) {
	initial := config.Default()
	initial.DNS.DNSSEC.Enabled = true
	initial.DNS.DNSSEC.Mode = config.DNSSECModeUpstream
	store := &fakeConfigStore{cfg: initial}
	server := newTestServer(WithConfigStore(store))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/config", map[string]any{
		"dns": map[string]any{
			"dnssec": map[string]any{
				"mode": "off",
			},
		},
	}, cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}

	body := decodeResponse[configUpdateResponse](t, res)
	if body.Config.DNSSEC.Enabled || body.Config.DNSSEC.Mode != "off" {
		t.Fatalf("dnssec response = %#v, want off disabled", body.Config.DNSSEC)
	}
	if store.cfg.DNS.DNSSEC.Enabled || store.cfg.DNS.DNSSEC.Mode != config.DNSSECModeOff {
		t.Fatalf("stored dnssec = %#v, want off disabled", store.cfg.DNS.DNSSEC)
	}
}

func TestConfigUpdateReloadsUpstreamResolversImmediately(t *testing.T) {
	initial := config.Default()
	store := &fakeConfigStore{cfg: initial}
	reloader := &fakeDNSReloader{}
	server := newTestServer(WithConfigStoreAndDNSReloader(store, reloader))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/config", map[string]any{
		"dns": map[string]any{
			"resolvers": []map[string]any{{
				"name":            "quad9",
				"address":         "9.9.9.9:853",
				"protocol":        "tls",
				"tls_server_name": "dns.quad9.net",
				"enabled":         true,
			}},
		},
	}, cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}

	body := decodeResponse[configUpdateResponse](t, res)
	if body.RestartRequired {
		t.Fatal("restart_required = true, want false")
	}
	if reloader.reloadCount != 1 {
		t.Fatalf("reloadCount = %d, want 1", reloader.reloadCount)
	}
	if len(reloader.last.DNS.Resolvers) != 1 || reloader.last.DNS.Resolvers[0].Name != "quad9" {
		t.Fatalf("reloaded resolvers = %#v, want quad9", reloader.last.DNS.Resolvers)
	}
	if store.saveCount != 1 {
		t.Fatalf("saveCount = %d, want 1", store.saveCount)
	}
	if len(body.Config.Upstreams) != 1 || !body.Config.Upstreams[0].Enabled {
		t.Fatalf("upstreams = %#v, want enabled quad9", body.Config.Upstreams)
	}
}

func TestConfigUpdateDNSListenChangeStillRequiresRestart(t *testing.T) {
	store := &fakeConfigStore{cfg: config.Default()}
	reloader := &fakeDNSReloader{}
	server := newTestServer(WithConfigStoreAndDNSReloader(store, reloader))
	cookie := setupSession(t, server)

	res := putJSON(t, server, "/api/config", map[string]any{
		"dns": map[string]any{
			"listen": ":5353",
		},
	}, cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}

	body := decodeResponse[configUpdateResponse](t, res)
	if !body.RestartRequired {
		t.Fatal("restart_required = false, want true")
	}
	if reloader.reloadCount != 0 {
		t.Fatalf("reloadCount = %d, want 0", reloader.reloadCount)
	}
	if store.saveCount != 1 {
		t.Fatalf("saveCount = %d, want 1", store.saveCount)
	}
}

func newTestServer(opts ...Option) *Server {
	return newTestServerWithUserStore(NewMemoryUserStore(), opts...)
}

func newTestServerWithUserStore(userStore UserStore, opts ...Option) *Server {
	hasher := NewArgon2idHasher(Argon2idParams{
		Memory:      64,
		Time:        1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	opts = append([]Option{WithPasswordHasher(hasher)}, opts...)
	return NewServer(userStore, opts...)
}

func postJSON(t *testing.T, server http.Handler, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodPost, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}

	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	return res
}

func putJSON(t *testing.T, server http.Handler, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodPut, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}

	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	return res
}

func get(t *testing.T, server http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}

	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	return res
}

func getWithBearer(t *testing.T, server http.Handler, path string, key string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+key)

	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	return res
}

func createTestAPIKey(t *testing.T, server http.Handler, cookie *http.Cookie, name string) apiKeyCreateResponse {
	t.Helper()

	res := postJSON(t, server, "/api/api-keys", map[string]string{"name": name}, cookie)
	if res.Code != http.StatusCreated {
		t.Fatalf("create api key status code = %d, want %d: %s", res.Code, http.StatusCreated, res.Body.String())
	}
	return decodeResponse[apiKeyCreateResponse](t, res)
}

func setupSession(t *testing.T, server http.Handler) *http.Cookie {
	t.Helper()

	res := postJSON(t, server, "/api/setup", map[string]string{"password": "correct password"}, nil)
	if res.Code != http.StatusCreated {
		t.Fatalf("setup status code = %d, want %d", res.Code, http.StatusCreated)
	}
	return sessionCookie(t, res)
}

func loginSession(t *testing.T, server http.Handler, password string) *http.Cookie {
	t.Helper()

	res := postJSON(t, server, "/api/login", map[string]string{"password": password}, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("login status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	return sessionCookie(t, res)
}

func openTestStoragePath(t *testing.T, ctx context.Context, path string) *storage.SQLiteStore {
	t.Helper()

	store, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return store
}

func assertStoredAPIKeyMetadataOnly(t *testing.T, ctx context.Context, store *storage.SQLiteStore, created apiKeyCreateResponse) {
	t.Helper()

	var keyHash string
	var prefix string
	var last4 string
	if err := store.DB().QueryRowContext(ctx, `
SELECT key_hash, prefix, last4
FROM api_keys
WHERE id = ?`, created.APIKey.ID).Scan(&keyHash, &prefix, &last4); err != nil {
		t.Fatalf("query stored api key metadata: %v", err)
	}
	if keyHash != hashAPIKey(created.Key) {
		t.Fatalf("stored key_hash = %q, want digest of raw key", keyHash)
	}
	if keyHash == created.Key {
		t.Fatal("stored key_hash contains raw api key")
	}
	if prefix != apiKeyPrefix(created.Key) || last4 != apiKeyLast4(created.Key) {
		t.Fatalf("stored metadata prefix/last4 = %q/%q, want %q/%q", prefix, last4, apiKeyPrefix(created.Key), apiKeyLast4(created.Key))
	}

	var rawMatches int
	if err := store.DB().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM api_keys
WHERE name = ? OR key_hash = ? OR prefix = ? OR last4 = ?`,
		created.Key,
		created.Key,
		created.Key,
		created.Key,
	).Scan(&rawMatches); err != nil {
		t.Fatalf("query raw api key matches: %v", err)
	}
	if rawMatches != 0 {
		t.Fatalf("raw api key stored in api_keys metadata columns %d times, want 0", rawMatches)
	}
}

func statusWithCookie(t *testing.T, server http.Handler, cookie *http.Cookie) statusResponse {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(cookie)
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", res.Code, http.StatusOK)
	}
	return decodeResponse[statusResponse](t, res)
}

func waitForDashboardTotals(t *testing.T, ctx context.Context, sink *audit.SQLiteSink, want audit.Totals) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := sink.Totals(ctx)
		if err != nil {
			t.Fatalf("Totals() error = %v", err)
		}
		if got.TotalQueries == want.TotalQueries &&
			got.AllowedQueries == want.AllowedQueries &&
			got.BlockedQueries == want.BlockedQueries {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	got, err := sink.Totals(ctx)
	if err != nil {
		t.Fatalf("Totals() final error = %v", err)
	}
	t.Fatalf("totals = %#v, want %#v", got, want)
}

func sessionCookie(t *testing.T, res *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()

	for _, cookie := range res.Result().Cookies() {
		if cookie.Name == defaultSessionCookieName {
			return cookie
		}
	}
	t.Fatalf("response did not set %s cookie", defaultSessionCookieName)
	return nil
}

func decodeResponse[T any](t *testing.T, res *httptest.ResponseRecorder) T {
	t.Helper()

	var body T
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

type statusResponse struct {
	SetupRequired bool `json:"setup_required"`
	Authenticated bool `json:"authenticated"`
}

type apiKeyListResponse struct {
	APIKeys []APIKey `json:"api_keys"`
}

type fakeAuditReader struct {
	events      []audit.Event
	dropped     uint64
	totals      audit.Totals
	limit       int
	queryOpts   audit.QueryOptions
	queryCalled bool
}

func (r *fakeAuditReader) Recent(_ context.Context, limit int) ([]audit.Event, error) {
	r.limit = limit
	return r.events, nil
}

func (r *fakeAuditReader) Query(_ context.Context, opts audit.QueryOptions) ([]audit.Event, error) {
	r.queryCalled = true
	r.queryOpts = opts
	r.limit = opts.Limit
	return r.events, nil
}

func (r *fakeAuditReader) Dropped() uint64 {
	return r.dropped
}

func (r *fakeAuditReader) Totals(context.Context) (audit.Totals, error) {
	return r.totals, nil
}

type fakeConfigStore struct {
	cfg       config.Config
	saveCount int
}

func (s *fakeConfigStore) Load(context.Context) (config.Config, error) {
	return s.cfg, nil
}

func (s *fakeConfigStore) Save(_ context.Context, cfg config.Config) error {
	s.saveCount++
	s.cfg = cfg
	return nil
}

type fakeDNSReloader struct {
	reloadCount int
	last        config.Config
}

func (r *fakeDNSReloader) ReloadDNS(_ context.Context, cfg config.Config) error {
	r.reloadCount++
	r.last = cfg
	return nil
}

type fakeBlockingController struct {
	status      BlockingStatus
	statusCalls int
	pauseCount  int
	resumeCount int
	until       time.Time
}

func (c *fakeBlockingController) Status(time.Time) BlockingStatus {
	c.statusCalls++
	return c.status
}

func (c *fakeBlockingController) Pause(_ context.Context, until time.Time) (BlockingStatus, error) {
	c.pauseCount++
	c.until = until
	c.status = BlockingStatusFromPause(true, until, time.Now())
	return c.status, nil
}

func (c *fakeBlockingController) Resume(context.Context) (BlockingStatus, error) {
	c.resumeCount++
	c.status = BlockingStatus{}
	return c.status, nil
}

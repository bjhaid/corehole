package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/audit"
	"github.com/bjhaid/corehole/internal/blocklist"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/bjhaid/corehole/internal/filter"
	"github.com/bjhaid/corehole/internal/storage"
)

func TestFilterAPIRequiresSession(t *testing.T) {
	server, closeStore := newFilterAPITestServer(t)
	defer closeStore()

	res := get(t, server, "/api/filter/lists", nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/filter/lists status code = %d, want %d", res.Code, http.StatusUnauthorized)
	}

	res = postJSON(t, server, "/api/filter/rules", map[string]any{
		"pattern":    "ads.example",
		"kind":       "deny",
		"match_type": "exact",
	}, nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("POST /api/filter/rules status code = %d, want %d", res.Code, http.StatusUnauthorized)
	}

	res = get(t, server, "/api/filter/clients/1/groups", nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/filter/clients/1/groups status code = %d, want %d", res.Code, http.StatusUnauthorized)
	}

	res = get(t, server, "/api/filter/clients/suggestions", nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/filter/clients/suggestions status code = %d, want %d", res.Code, http.StatusUnauthorized)
	}
}

func TestFilterAPICRUDSuccess(t *testing.T) {
	server, closeStore := newFilterAPITestServer(t)
	defer closeStore()
	cookie := setupSession(t, server)

	createList := postJSON(t, server, "/api/filter/lists", map[string]any{
		"url":  "https://example.test/allow.txt",
		"kind": "allow",
	}, cookie)
	if createList.Code != http.StatusCreated {
		t.Fatalf("create list status code = %d, want %d: %s", createList.Code, http.StatusCreated, createList.Body.String())
	}
	list := decodeResponse[filter.List](t, createList)
	if list.ID == 0 || list.Kind != filter.KindAllow || !list.Enabled {
		t.Fatalf("created list = %#v", list)
	}

	createEntry := postJSON(t, server, "/api/filter/lists/"+strconv.FormatInt(list.ID, 10)+"/entries", map[string]any{
		"pattern":    "Example.test.",
		"match_type": "suffix",
	}, cookie)
	if createEntry.Code != http.StatusCreated {
		t.Fatalf("create entry status code = %d, want %d: %s", createEntry.Code, http.StatusCreated, createEntry.Body.String())
	}
	entry := decodeResponse[filter.ListEntry](t, createEntry)
	if entry.ListID != list.ID || entry.Pattern != "example.test" || !entry.Enabled {
		t.Fatalf("created entry = %#v", entry)
	}

	createRule := postJSON(t, server, "/api/filter/rules", map[string]any{
		"pattern":    "ads.example",
		"kind":       "deny",
		"match_type": "exact",
		"comment":    "manual",
	}, cookie)
	if createRule.Code != http.StatusCreated {
		t.Fatalf("create rule status code = %d, want %d: %s", createRule.Code, http.StatusCreated, createRule.Body.String())
	}
	rule := decodeResponse[filter.Rule](t, createRule)
	if rule.ID == 0 || rule.Pattern != "ads.example" || rule.Kind != filter.KindDeny || rule.Comment != "manual" {
		t.Fatalf("created rule = %#v", rule)
	}

	createClient := postJSON(t, server, "/api/filter/clients", map[string]any{
		"name":    "laptop",
		"address": "192.0.2.10",
	}, cookie)
	if createClient.Code != http.StatusCreated {
		t.Fatalf("create client status code = %d, want %d: %s", createClient.Code, http.StatusCreated, createClient.Body.String())
	}
	client := decodeResponse[filter.Client](t, createClient)

	createGroup := postJSON(t, server, "/api/filter/groups", map[string]any{
		"name": "default",
	}, cookie)
	if createGroup.Code != http.StatusCreated {
		t.Fatalf("create group status code = %d, want %d: %s", createGroup.Code, http.StatusCreated, createGroup.Body.String())
	}
	group := decodeResponse[filter.Group](t, createGroup)

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "list", path: "/api/filter/lists/" + strconv.FormatInt(list.ID, 10) + "/groups"},
		{name: "rule", path: "/api/filter/rules/" + strconv.FormatInt(rule.ID, 10) + "/groups"},
		{name: "client", path: "/api/filter/clients/" + strconv.FormatInt(client.ID, 10) + "/groups"},
	} {
		assign := postJSON(t, server, tc.path, map[string]any{"group_id": group.ID}, cookie)
		if assign.Code != http.StatusNoContent {
			t.Fatalf("assign %s group status code = %d, want %d: %s", tc.name, assign.Code, http.StatusNoContent, assign.Body.String())
		}
		listGroups := get(t, server, tc.path, cookie)
		if listGroups.Code != http.StatusOK {
			t.Fatalf("list %s groups status code = %d, want %d: %s", tc.name, listGroups.Code, http.StatusOK, listGroups.Body.String())
		}
		assertFilterAPIGroupAssignment(t, listGroups, group.ID)
		remove := deleteReq(t, server, tc.path+"/"+strconv.FormatInt(group.ID, 10), cookie)
		if remove.Code != http.StatusNoContent {
			t.Fatalf("remove %s group status code = %d, want %d: %s", tc.name, remove.Code, http.StatusNoContent, remove.Body.String())
		}
		afterRemove := get(t, server, tc.path, cookie)
		if afterRemove.Code != http.StatusOK {
			t.Fatalf("list %s groups after remove status code = %d, want %d", tc.name, afterRemove.Code, http.StatusOK)
		}
		groups := decodeResponse[struct {
			Groups []filter.Group `json:"groups"`
		}](t, afterRemove)
		if len(groups.Groups) != 0 {
			t.Fatalf("%s groups after remove = %#v, want none", tc.name, groups.Groups)
		}
	}

	listRules := get(t, server, "/api/filter/rules", cookie)
	if listRules.Code != http.StatusOK {
		t.Fatalf("list rules status code = %d, want %d", listRules.Code, http.StatusOK)
	}
	rules := decodeResponse[struct {
		Rules []filter.Rule `json:"rules"`
	}](t, listRules)
	if len(rules.Rules) != 1 || rules.Rules[0].ID != rule.ID {
		t.Fatalf("rules response = %#v", rules)
	}

	deleteRule := deleteReq(t, server, "/api/filter/rules/"+strconv.FormatInt(rule.ID, 10), cookie)
	if deleteRule.Code != http.StatusNoContent {
		t.Fatalf("delete rule status code = %d, want %d", deleteRule.Code, http.StatusNoContent)
	}
}

func TestFilterAPIRefreshListImportsAndReloadsRuntime(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()
	repo := filter.NewRepository(store.DB())
	service := filter.NewService(repo)
	manager := blocklist.NewManagerWithBundledAndSources(nil, false, filter.NewBlocklistSource(repo))
	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("initial Reload() error = %v", err)
	}
	server := newTestServer(WithFilterService(service), WithFilterReloader(manager))
	cookie := setupSession(t, server)
	path := filepath.Join(t.TempDir(), "adlist.txt")
	if err := os.WriteFile(path, []byte("0.0.0.0 adzerk.com\n"), 0o600); err != nil {
		t.Fatalf("write adlist: %v", err)
	}

	createList := postJSON(t, server, "/api/filter/lists", map[string]any{
		"path": path,
		"kind": "deny",
	}, cookie)
	if createList.Code != http.StatusCreated {
		t.Fatalf("create list status code = %d, want %d: %s", createList.Code, http.StatusCreated, createList.Body.String())
	}
	list := decodeResponse[filter.List](t, createList)

	refresh := postJSON(t, server, "/api/filter/lists/"+strconv.FormatInt(list.ID, 10)+"/refresh", nil, cookie)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh list status code = %d, want %d: %s", refresh.Code, http.StatusOK, refresh.Body.String())
	}
	refreshed := decodeResponse[filter.List](t, refresh)
	if refreshed.LastUpdatedAt == nil || refreshed.LastError != "" {
		t.Fatalf("refreshed list = %#v, want last_updated_at and no error", refreshed)
	}
	decision := manager.Decide(ctx, coreholedns.Query{Name: "adzerk.com"})
	if decision.Action != coreholedns.ActionBlock {
		t.Fatalf("decision for adzerk.com = %q (%s), want block after API refresh", decision.Action, decision.Reason)
	}

	update := putJSON(t, server, "/api/filter/lists/"+strconv.FormatInt(list.ID, 10), map[string]any{
		"path":            path,
		"kind":            "deny",
		"enabled":         false,
		"last_updated_at": refreshed.LastUpdatedAt.Format(time.RFC3339Nano),
	}, cookie)
	if update.Code != http.StatusOK {
		t.Fatalf("disable list status code = %d, want %d: %s", update.Code, http.StatusOK, update.Body.String())
	}
	decision = manager.Decide(ctx, coreholedns.Query{Name: "adzerk.com"})
	if decision.Action != coreholedns.ActionAllow {
		t.Fatalf("decision for disabled adzerk.com = %q (%s), want allow after API disable", decision.Action, decision.Reason)
	}
}

func TestFilterAPIClientSuggestions(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	reader := &fakeClientSuggestionReader{
		suggestions: []audit.ClientSuggestion{
			{Address: "192.0.2.10", LastSeen: now, Count: 3},
			{Address: "2001:db8::10", LastSeen: now.Add(-time.Minute), Count: 1},
		},
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/filter/clients/suggestions?limit=2", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("suggestions status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	body := decodeResponse[filterClientSuggestionsResponse](t, res)
	if reader.limit != 2 {
		t.Fatalf("RecentClients limit = %d, want 2", reader.limit)
	}
	if body.PrivacyLevel != 0 {
		t.Fatalf("privacy level = %d, want 0", body.PrivacyLevel)
	}
	if len(body.Suggestions) != 2 || body.Suggestions[0].Address != "192.0.2.10" || body.Suggestions[0].ClientIP != "192.0.2.10" || body.Suggestions[0].Count != 3 {
		t.Fatalf("suggestions response = %#v", body.Suggestions)
	}
}

func TestFilterAPIClientSuggestionsHideWhenClientPrivacyEnabled(t *testing.T) {
	reader := &fakeClientSuggestionReader{
		settings: audit.Settings{PrivacyLevel: audit.PrivacyLevelHideClient},
		suggestions: []audit.ClientSuggestion{
			{Address: "192.0.2.10", LastSeen: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC), Count: 3},
		},
	}
	server := newTestServer(WithAuditReader(reader))
	cookie := setupSession(t, server)

	res := get(t, server, "/api/filter/clients/suggestions", cookie)
	if res.Code != http.StatusOK {
		t.Fatalf("suggestions status code = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	body := decodeResponse[filterClientSuggestionsResponse](t, res)
	if body.PrivacyLevel != int(audit.PrivacyLevelHideClient) {
		t.Fatalf("privacy level = %d, want %d", body.PrivacyLevel, audit.PrivacyLevelHideClient)
	}
	if len(body.Suggestions) != 0 {
		t.Fatalf("suggestions = %#v, want none", body.Suggestions)
	}
	if reader.called {
		t.Fatal("RecentClients called despite client privacy")
	}
}

func newFilterAPITestServer(t *testing.T) (*Server, func()) {
	t.Helper()

	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	service := filter.NewService(filter.NewRepository(store.DB()))
	server := newTestServer(WithFilterService(service))
	return server, func() {
		t.Helper()
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}

type fakeClientSuggestionReader struct {
	settings    audit.Settings
	suggestions []audit.ClientSuggestion
	limit       int
	called      bool
}

func (r *fakeClientSuggestionReader) Recent(context.Context, int) ([]audit.Event, error) {
	return nil, nil
}

func (r *fakeClientSuggestionReader) RecentClients(_ context.Context, limit int) ([]audit.ClientSuggestion, error) {
	r.called = true
	r.limit = limit
	return r.suggestions, nil
}

func (r *fakeClientSuggestionReader) Settings(context.Context) (audit.Settings, error) {
	return r.settings, nil
}

func (r *fakeClientSuggestionReader) Dropped() uint64 {
	return 0
}

func assertFilterAPIGroupAssignment(t *testing.T, res *httptest.ResponseRecorder, wantID int64) {
	t.Helper()

	groups := decodeResponse[struct {
		Groups []filter.Group `json:"groups"`
	}](t, res)
	if len(groups.Groups) != 1 || groups.Groups[0].ID != wantID {
		t.Fatalf("groups response = %#v, want group id %d", groups, wantID)
	}
}

func deleteReq(t *testing.T, server http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodDelete, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	return res
}

package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bjhaid/corehole/internal/blocklist"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
)

func TestRefreshURLListImportsEntriesAndRuntimeBlocks(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()
	service := NewService(repo)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("0.0.0.0 adzerk.com\nplain.example\n*.suffix.example\n")); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}))
	defer server.Close()

	list, err := service.CreateList(ctx, List{URL: server.URL + "/hosts", Kind: KindDeny, Enabled: true})
	if err != nil {
		t.Fatalf("CreateList() error = %v", err)
	}

	manager := blocklist.NewManagerWithBundledAndSources(nil, false, NewBlocklistSource(repo))
	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("initial Reload() error = %v", err)
	}
	assertFilterDecision(t, manager, "adzerk.com", coreholedns.ActionAllow)

	refreshed, err := service.RefreshList(ctx, list.ID)
	if err != nil {
		t.Fatalf("RefreshList() error = %v", err)
	}
	if refreshed.LastUpdatedAt == nil || refreshed.LastError != "" {
		t.Fatalf("refreshed list metadata = %#v, want last_updated_at and empty last_error", refreshed)
	}
	entries, err := service.ListListEntries(ctx, list.ID)
	if err != nil {
		t.Fatalf("ListListEntries() error = %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entry count = %d, want 3: %#v", len(entries), entries)
	}

	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("Reload() after refresh error = %v", err)
	}
	assertFilterDecision(t, manager, "adzerk.com", coreholedns.ActionBlock)
	assertFilterDecision(t, manager, "child.suffix.example", coreholedns.ActionBlock)
}

func TestDisabledRefreshedListDoesNotBlockRuntime(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()
	service := NewService(repo)
	path := writeFilterListFile(t, "disabled.txt", "adzerk.com\n")

	list, err := service.CreateList(ctx, List{Path: path, Kind: KindDeny, Enabled: false})
	if err != nil {
		t.Fatalf("CreateList() error = %v", err)
	}
	if _, err := service.RefreshList(ctx, list.ID); err != nil {
		t.Fatalf("RefreshList() error = %v", err)
	}

	manager := blocklist.NewManagerWithBundledAndSources(nil, false, NewBlocklistSource(repo))
	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	assertFilterDecision(t, manager, "adzerk.com", coreholedns.ActionAllow)
}

func TestServiceGroupAssignments(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()
	service := NewService(repo)

	list, err := service.CreateList(ctx, List{URL: "https://example.test/deny.txt", Kind: KindDeny, Enabled: true})
	if err != nil {
		t.Fatalf("CreateList() error = %v", err)
	}
	rule, err := service.CreateRule(ctx, Rule{Pattern: "ads.example", Kind: KindDeny, MatchType: MatchExact, Enabled: true})
	if err != nil {
		t.Fatalf("CreateRule() error = %v", err)
	}
	client, err := service.CreateClient(ctx, Client{Name: "laptop", Address: "192.0.2.10", Enabled: true})
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	group, err := service.CreateGroup(ctx, Group{Name: "kids", Enabled: true})
	if err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}

	if err := service.AddClientGroup(ctx, client.ID, group.ID); err != nil {
		t.Fatalf("AddClientGroup() error = %v", err)
	}
	if err := service.AddListGroup(ctx, list.ID, group.ID); err != nil {
		t.Fatalf("AddListGroup() error = %v", err)
	}
	if err := service.AddRuleGroup(ctx, rule.ID, group.ID); err != nil {
		t.Fatalf("AddRuleGroup() error = %v", err)
	}

	clientGroups, err := service.ListClientGroups(ctx, client.ID)
	assertAssignedGroup(t, clientGroups, err, group.ID)
	listGroups, err := service.ListListGroups(ctx, list.ID)
	assertAssignedGroup(t, listGroups, err, group.ID)
	ruleGroups, err := service.ListRuleGroups(ctx, rule.ID)
	assertAssignedGroup(t, ruleGroups, err, group.ID)

	if err := service.RemoveClientGroup(ctx, client.ID, group.ID); err != nil {
		t.Fatalf("RemoveClientGroup() error = %v", err)
	}
	if err := service.RemoveListGroup(ctx, list.ID, group.ID); err != nil {
		t.Fatalf("RemoveListGroup() error = %v", err)
	}
	if err := service.RemoveRuleGroup(ctx, rule.ID, group.ID); err != nil {
		t.Fatalf("RemoveRuleGroup() error = %v", err)
	}

	clientGroups, err = service.ListClientGroups(ctx, client.ID)
	assertNoAssignedGroups(t, clientGroups, err)
	listGroups, err = service.ListListGroups(ctx, list.ID)
	assertNoAssignedGroups(t, listGroups, err)
	ruleGroups, err = service.ListRuleGroups(ctx, rule.ID)
	assertNoAssignedGroups(t, ruleGroups, err)
}

func TestRefreshBadPathSetsLastErrorAndPreservesPreviousRuntimeEntries(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()
	service := NewService(repo)
	path := writeFilterListFile(t, "good.txt", "adzerk.com\n")

	list, err := service.CreateList(ctx, List{Path: path, Kind: KindDeny, Enabled: true})
	if err != nil {
		t.Fatalf("CreateList() error = %v", err)
	}
	if _, err := service.RefreshList(ctx, list.ID); err != nil {
		t.Fatalf("initial RefreshList() error = %v", err)
	}
	manager := blocklist.NewManagerWithBundledAndSources(nil, false, NewBlocklistSource(repo))
	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("initial Reload() error = %v", err)
	}
	assertFilterDecision(t, manager, "adzerk.com", coreholedns.ActionBlock)

	list.Path = filepath.Join(t.TempDir(), "missing.txt")
	list, err = service.UpdateList(ctx, list)
	if err != nil {
		t.Fatalf("UpdateList() error = %v", err)
	}
	_, err = service.RefreshList(ctx, list.ID)
	if err == nil {
		t.Fatal("RefreshList() returned nil error for missing path")
	}
	after, err := service.GetList(ctx, list.ID)
	if err != nil {
		t.Fatalf("GetList() error = %v", err)
	}
	if after.LastError == "" || !strings.Contains(after.LastError, "missing.txt") {
		t.Fatalf("last_error = %q, want missing path error", after.LastError)
	}

	entries, err := service.ListListEntries(ctx, list.ID)
	if err != nil {
		t.Fatalf("ListListEntries() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Pattern != "adzerk.com" {
		t.Fatalf("entries after failed refresh = %#v, want prior adzerk.com entry", entries)
	}
	assertFilterDecision(t, manager, "adzerk.com", coreholedns.ActionBlock)
	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("Reload() after failed refresh error = %v", err)
	}
	assertFilterDecision(t, manager, "adzerk.com", coreholedns.ActionBlock)
}

func assertAssignedGroup(t *testing.T, groups []Group, err error, wantID int64) {
	t.Helper()
	if err != nil {
		t.Fatalf("ListGroups() error = %v", err)
	}
	if len(groups) != 1 || groups[0].ID != wantID {
		t.Fatalf("groups = %#v, want group id %d", groups, wantID)
	}
}

func assertNoAssignedGroups(t *testing.T, groups []Group, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("ListGroups() error = %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("groups = %#v, want none", groups)
	}
}

func writeFilterListFile(t *testing.T, name string, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write filter list: %v", err)
	}
	return path
}

func assertFilterDecision(t *testing.T, decider coreholedns.Decider, query string, want coreholedns.Action) {
	t.Helper()

	got := decider.Decide(context.Background(), coreholedns.Query{Name: query})
	if got.Action != want {
		t.Fatalf("decision for %q = %q (%s), want %q", query, got.Action, got.Reason, want)
	}
}

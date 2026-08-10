package filter

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/bjhaid/corehole/internal/storage"
)

func TestRepositoryCRUDAndMappings(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()

	list, err := repo.CreateList(ctx, List{
		URL:     "https://example.test/allow.txt",
		Kind:    KindAllow,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateList() error = %v", err)
	}
	if list.ID == 0 || list.Kind != KindAllow || !list.Enabled {
		t.Fatalf("created list = %#v", list)
	}

	list.Path = "/var/lib/corehole/allow.txt"
	list.URL = ""
	list.Enabled = false
	list, err = repo.UpdateList(ctx, list)
	if err != nil {
		t.Fatalf("UpdateList() error = %v", err)
	}
	if list.Path != "/var/lib/corehole/allow.txt" || list.URL != "" || list.Enabled {
		t.Fatalf("updated list = %#v", list)
	}

	entry, err := repo.CreateListEntry(ctx, ListEntry{
		ListID:    list.ID,
		Pattern:   "Example.COM.",
		MatchType: MatchSuffix,
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("CreateListEntry() error = %v", err)
	}
	if entry.Pattern != "example.com" {
		t.Fatalf("entry pattern = %q, want normalized example.com", entry.Pattern)
	}

	rule, err := repo.CreateRule(ctx, Rule{
		Pattern:   `(^|\.)ads\.example\.com$`,
		Kind:      KindDeny,
		MatchType: MatchRegex,
		Enabled:   true,
		Comment:   "ads",
	})
	if err != nil {
		t.Fatalf("CreateRule() error = %v", err)
	}
	rule.Comment = "updated"
	rule, err = repo.UpdateRule(ctx, rule)
	if err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}
	if rule.Comment != "updated" {
		t.Fatalf("rule comment = %q, want updated", rule.Comment)
	}

	client, err := repo.CreateClient(ctx, Client{
		Name:    "laptop",
		Address: "192.0.2.10",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	group, err := repo.CreateGroup(ctx, Group{
		Name:    "default",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}

	if err := repo.AddClientGroup(ctx, client.ID, group.ID); err != nil {
		t.Fatalf("AddClientGroup() error = %v", err)
	}
	if err := repo.AddListGroup(ctx, list.ID, group.ID); err != nil {
		t.Fatalf("AddListGroup() error = %v", err)
	}
	if err := repo.AddRuleGroup(ctx, rule.ID, group.ID); err != nil {
		t.Fatalf("AddRuleGroup() error = %v", err)
	}

	clientGroups, err := repo.ListClientGroups(ctx, client.ID)
	if err != nil {
		t.Fatalf("ListClientGroups() error = %v", err)
	}
	if len(clientGroups) != 1 || clientGroups[0].Name != "default" {
		t.Fatalf("client groups = %#v, want default", clientGroups)
	}

	if err := repo.RemoveRuleGroup(ctx, rule.ID, group.ID); err != nil {
		t.Fatalf("RemoveRuleGroup() error = %v", err)
	}
	ruleGroups, err := repo.ListRuleGroups(ctx, rule.ID)
	if err != nil {
		t.Fatalf("ListRuleGroups() error = %v", err)
	}
	if len(ruleGroups) != 0 {
		t.Fatalf("rule groups length = %d, want 0", len(ruleGroups))
	}

	if err := repo.DeleteClient(ctx, client.ID); err != nil {
		t.Fatalf("DeleteClient() error = %v", err)
	}
	if _, err := repo.GetClient(ctx, client.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetClient() after delete error = %v, want ErrNotFound", err)
	}
}

func TestDecisionPriorityOrdering(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()
	service := NewService(repo)

	denyList, err := repo.CreateList(ctx, List{URL: "https://example.test/deny.txt", Kind: KindDeny, Enabled: true})
	if err != nil {
		t.Fatalf("CreateList(deny) error = %v", err)
	}
	allowList, err := repo.CreateList(ctx, List{URL: "https://example.test/allow.txt", Kind: KindAllow, Enabled: true})
	if err != nil {
		t.Fatalf("CreateList(allow) error = %v", err)
	}
	if _, err := repo.CreateListEntry(ctx, ListEntry{ListID: denyList.ID, Pattern: "priority.test", MatchType: MatchExact, Enabled: true}); err != nil {
		t.Fatalf("CreateListEntry(deny) error = %v", err)
	}
	if _, err := repo.CreateListEntry(ctx, ListEntry{ListID: allowList.ID, Pattern: "priority.test", MatchType: MatchExact, Enabled: true}); err != nil {
		t.Fatalf("CreateListEntry(allow) error = %v", err)
	}
	if _, err := repo.CreateRule(ctx, Rule{Pattern: `^priority\.test$`, Kind: KindDeny, MatchType: MatchRegex, Enabled: true}); err != nil {
		t.Fatalf("CreateRule(regex deny) error = %v", err)
	}

	decision, err := service.Decide(ctx, DecisionRequest{Domain: "priority.test."})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Action != ActionAllow || decision.Reason != "subscribed allow list" {
		t.Fatalf("decision = %#v, want subscribed allow before subscribed deny/regex deny", decision)
	}

	if _, err := repo.CreateRule(ctx, Rule{Pattern: "priority.test", Kind: KindDeny, MatchType: MatchExact, Enabled: true}); err != nil {
		t.Fatalf("CreateRule(exact deny) error = %v", err)
	}
	decision, err = service.Decide(ctx, DecisionRequest{Domain: "priority.test"})
	if err != nil {
		t.Fatalf("Decide() with exact deny error = %v", err)
	}
	if decision.Action != ActionDeny || decision.Reason != "exact deny rule" {
		t.Fatalf("decision = %#v, want exact deny before subscribed allow", decision)
	}

	if _, err := repo.CreateRule(ctx, Rule{Pattern: `^priority\.test$`, Kind: KindAllow, MatchType: MatchRegex, Enabled: true}); err != nil {
		t.Fatalf("CreateRule(regex allow) error = %v", err)
	}
	decision, err = service.Decide(ctx, DecisionRequest{Domain: "priority.test"})
	if err != nil {
		t.Fatalf("Decide() with regex allow error = %v", err)
	}
	if decision.Action != ActionAllow || decision.Reason != "regex allow rule" {
		t.Fatalf("decision = %#v, want regex allow before exact deny", decision)
	}

	if _, err := repo.CreateRule(ctx, Rule{Pattern: "priority.test", Kind: KindAllow, MatchType: MatchExact, Enabled: true}); err != nil {
		t.Fatalf("CreateRule(exact allow) error = %v", err)
	}
	decision, err = service.Decide(ctx, DecisionRequest{Domain: "priority.test"})
	if err != nil {
		t.Fatalf("Decide() with exact allow error = %v", err)
	}
	if decision.Action != ActionAllow || decision.Reason != "exact allow rule" {
		t.Fatalf("decision = %#v, want exact allow first", decision)
	}
}

func TestDecisionHonorsGroupScope(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()
	service := NewService(repo)

	rule, err := repo.CreateRule(ctx, Rule{
		Pattern:   "grouped.test",
		Kind:      KindDeny,
		MatchType: MatchExact,
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("CreateRule() error = %v", err)
	}
	group, err := repo.CreateGroup(ctx, Group{Name: "kids", Enabled: true})
	if err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}
	if err := repo.AddRuleGroup(ctx, rule.ID, group.ID); err != nil {
		t.Fatalf("AddRuleGroup() error = %v", err)
	}

	decision, err := service.Decide(ctx, DecisionRequest{Domain: "grouped.test", ClientAddress: "192.0.2.55"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Action != ActionNone {
		t.Fatalf("decision for ungrouped client = %#v, want none", decision)
	}

	client, err := repo.CreateClient(ctx, Client{Name: "tablet", Address: "192.0.2.55", Enabled: true})
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if err := repo.AddClientGroup(ctx, client.ID, group.ID); err != nil {
		t.Fatalf("AddClientGroup() error = %v", err)
	}
	decision, err = service.Decide(ctx, DecisionRequest{Domain: "grouped.test", ClientAddress: "192.0.2.55"})
	if err != nil {
		t.Fatalf("Decide() grouped error = %v", err)
	}
	if decision.Action != ActionDeny || decision.RuleID != rule.ID {
		t.Fatalf("decision for grouped client = %#v, want grouped deny", decision)
	}
}

func TestBlocklistRuntimeStatsCountsEnabledImportedLists(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()

	enabledImported, err := repo.CreateList(ctx, List{URL: "https://example.test/enabled.txt", Kind: KindDeny, Enabled: true})
	if err != nil {
		t.Fatalf("CreateList(enabled imported) error = %v", err)
	}
	enabledEmpty, err := repo.CreateList(ctx, List{URL: "https://example.test/empty.txt", Kind: KindDeny, Enabled: true})
	if err != nil {
		t.Fatalf("CreateList(enabled empty) error = %v", err)
	}
	disabledImported, err := repo.CreateList(ctx, List{URL: "https://example.test/disabled.txt", Kind: KindDeny, Enabled: false})
	if err != nil {
		t.Fatalf("CreateList(disabled imported) error = %v", err)
	}
	if _, err := repo.CreateListEntry(ctx, ListEntry{ListID: enabledImported.ID, Pattern: "adzerk.com", MatchType: MatchExact, Enabled: true}); err != nil {
		t.Fatalf("CreateListEntry(enabled) error = %v", err)
	}
	if _, err := repo.CreateListEntry(ctx, ListEntry{ListID: enabledImported.ID, Pattern: "disabled-entry.example", MatchType: MatchExact, Enabled: false}); err != nil {
		t.Fatalf("CreateListEntry(disabled entry) error = %v", err)
	}
	if _, err := repo.CreateListEntry(ctx, ListEntry{ListID: disabledImported.ID, Pattern: "ignored.example", MatchType: MatchExact, Enabled: true}); err != nil {
		t.Fatalf("CreateListEntry(disabled list) error = %v", err)
	}

	stats, err := repo.BlocklistRuntimeStats(ctx)
	if err != nil {
		t.Fatalf("BlocklistRuntimeStats() error = %v", err)
	}
	if stats.EnabledLists != 2 || stats.ImportedEnabledLists != 1 || stats.EnabledEntries != 1 {
		t.Fatalf("stats = %#v, want enabled lists=2 imported enabled lists=1 enabled entries=1", stats)
	}

	enabledEmpty.Enabled = false
	if _, err := repo.UpdateList(ctx, enabledEmpty); err != nil {
		t.Fatalf("UpdateList(enabled empty disabled) error = %v", err)
	}
	stats, err = repo.BlocklistRuntimeStats(ctx)
	if err != nil {
		t.Fatalf("BlocklistRuntimeStats() after disable error = %v", err)
	}
	if stats.EnabledLists != 1 || stats.ImportedEnabledLists != 1 || stats.EnabledEntries != 1 {
		t.Fatalf("stats after disable = %#v, want enabled lists=1 imported enabled lists=1 enabled entries=1", stats)
	}
}

func newTestRepository(t *testing.T, ctx context.Context) (*Repository, func()) {
	t.Helper()

	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return NewRepository(store.DB()), func() {
		t.Helper()
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}

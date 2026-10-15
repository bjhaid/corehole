package filter

import (
	"context"
	"net/netip"
	"testing"

	"github.com/bjhaid/corehole/internal/blocklist"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
)

func TestRuleDeciderReloadAndPrecedence(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()
	service := NewService(repo)
	fallback := blocklist.NewMatcherWithBundled([]blocklist.Entry{
		{Domain: "listed.example", Kind: blocklist.EntryExact},
		{Domain: "trusted.example", Kind: blocklist.EntryExact, Allow: true},
	}, false)
	decider := NewRuleDecider(repo, fallback)
	for _, rule := range []Rule{
		{Pattern: "blocked.example.org", Kind: KindDeny, MatchType: MatchSuffix, Enabled: true},
		{Pattern: "listed.example", Kind: KindAllow, MatchType: MatchExact, Enabled: true},
		{Pattern: `(^|\.)regex\.example$`, Kind: KindDeny, MatchType: MatchRegex, Enabled: true},
		{Pattern: "trusted.example", Kind: KindDeny, MatchType: MatchSuffix, Enabled: true},
		{Pattern: "disabled.example", Kind: KindDeny, MatchType: MatchExact},
	} {
		if _, err := service.CreateRule(ctx, rule); err != nil {
			t.Fatal(err)
		}
	}
	if err := decider.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want coreholedns.Action
	}{
		{"BlOcKeD.Example.Org.", coreholedns.ActionBlock},
		{"www.blocked.example.org.", coreholedns.ActionBlock},
		{"notblocked.example.org.", coreholedns.ActionAllow},
		{"listed.example.", coreholedns.ActionAllow},
		{"regex.example.", coreholedns.ActionBlock},
		{"sub.regex.example.", coreholedns.ActionBlock},
		{"trusted.example.", coreholedns.ActionAllow},
		{"disabled.example.", coreholedns.ActionAllow},
	} {
		if got := decider.Decide(ctx, coreholedns.Query{Name: tc.name}); got.Action != tc.want {
			t.Errorf("%s = %+v, want %s", tc.name, got, tc.want)
		}
	}
	rule, err := service.GetRule(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	rule.Enabled = false
	if _, err := service.UpdateRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := decider.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got := decider.Decide(ctx, coreholedns.Query{Name: "blocked.example.org."}); got.Action != coreholedns.ActionAllow {
		t.Fatalf("disabled rule still blocks: %+v", got)
	}
}

func TestRuleDeciderClientScope(t *testing.T) {
	ctx := context.Background()
	repo, closeStore := newTestRepository(t, ctx)
	defer closeStore()
	s := NewService(repo)
	rule, err := s.CreateRule(ctx, Rule{Pattern: "scoped.example", Kind: KindDeny, MatchType: MatchExact, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, Group{Name: "kids", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := s.CreateClient(ctx, Client{Name: "laptop", Address: "192.0.2.10", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddClientGroup(ctx, client.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRuleGroup(ctx, rule.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	d := NewRuleDecider(repo, blocklist.NewMatcherWithBundled(nil, false))
	if err := d.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		address string
		want    coreholedns.Action
	}{
		{"192.0.2.10", coreholedns.ActionBlock},
		{"192.0.2.11", coreholedns.ActionAllow},
	} {
		got := d.Decide(ctx, coreholedns.Query{Name: "scoped.example.", ClientIP: netip.MustParseAddr(tc.address)})
		if got.Action != tc.want {
			t.Fatalf("%s = %+v, want %s", tc.address, got, tc.want)
		}
	}
}

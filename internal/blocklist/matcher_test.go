package blocklist

import (
	"context"
	"testing"

	coredns "github.com/bjhaid/corehole/internal/dns"
)

func TestMemoryMatcherExactAndSuffix(t *testing.T) {
	matcher := NewMatcherWithBundled([]Entry{
		{Domain: "example.com", Kind: EntryExact},
		{Domain: "example.org", Kind: EntrySuffix},
	}, false)

	tests := []struct {
		name       string
		query      string
		wantAction coredns.Action
	}{
		{name: "exact matches exact name", query: "example.com", wantAction: coredns.ActionBlock},
		{name: "exact ignores subdomain", query: "www.example.com", wantAction: coredns.ActionAllow},
		{name: "suffix ignores bare domain", query: "example.org", wantAction: coredns.ActionAllow},
		{name: "suffix matches subdomain", query: "www.example.org", wantAction: coredns.ActionBlock},
		{name: "suffix matches deep subdomain", query: "a.b.example.org.", wantAction: coredns.ActionBlock},
		{name: "query names normalize", query: "ExAmPlE.CoM.", wantAction: coredns.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := matcher.Decide(context.Background(), coredns.Query{Name: tt.query})
			if decision.Action != tt.wantAction {
				t.Fatalf("action = %q, want %q", decision.Action, tt.wantAction)
			}
		})
	}
}

func TestMemoryMatcherAllowPrecedence(t *testing.T) {
	matcher := NewMatcher([]Entry{
		{Domain: "bad.example", Kind: EntryExact},
		{Domain: "bad.example", Kind: EntryExact, Allow: true},
		{Domain: "blocked.example", Kind: EntryExact, Allow: true},
		{Domain: "example.com", Kind: EntrySuffix},
		{Domain: "safe.example.com", Kind: EntryExact, Allow: true},
		{Domain: "trusted.example.com", Kind: EntrySuffix, Allow: true},
	})

	tests := []struct {
		name       string
		query      string
		wantAction coredns.Action
	}{
		{name: "allow exact overrides deny exact", query: "bad.example", wantAction: coredns.ActionAllow},
		{name: "allow exact overrides bundled deny exact", query: "blocked.example", wantAction: coredns.ActionAllow},
		{name: "allow exact overrides deny suffix", query: "safe.example.com", wantAction: coredns.ActionAllow},
		{name: "allow suffix overrides deny suffix", query: "api.trusted.example.com", wantAction: coredns.ActionAllow},
		{name: "deny suffix still applies elsewhere", query: "ads.example.com", wantAction: coredns.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := matcher.Decide(context.Background(), coredns.Query{Name: tt.query})
			if decision.Action != tt.wantAction {
				t.Fatalf("action = %q, want %q", decision.Action, tt.wantAction)
			}
		})
	}
}

func TestMemoryMatcherIgnoresLocalHostsAliases(t *testing.T) {
	matcher := NewMatcherWithBundled([]Entry{
		{Domain: "localhost", Kind: EntryExact},
		{Domain: "localhost.localdomain", Kind: EntryExact},
		{Domain: "broadcasthost", Kind: EntryExact},
		{Domain: "ip6-localhost", Kind: EntryExact},
		{Domain: "blocked-from-test.example", Kind: EntryExact},
	}, false)

	tests := []struct {
		query      string
		wantAction coredns.Action
	}{
		{query: "localhost", wantAction: coredns.ActionAllow},
		{query: "localhost.localdomain", wantAction: coredns.ActionAllow},
		{query: "broadcasthost", wantAction: coredns.ActionAllow},
		{query: "ip6-localhost", wantAction: coredns.ActionAllow},
		{query: "blocked-from-test.example", wantAction: coredns.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			decision := matcher.Decide(context.Background(), coredns.Query{Name: tt.query})
			if decision.Action != tt.wantAction {
				t.Fatalf("action = %q, want %q", decision.Action, tt.wantAction)
			}
		})
	}
}

func TestMemoryMatcherIncludesBundledEntriesByDefault(t *testing.T) {
	matcher := NewMatcher(nil)

	decision := matcher.Decide(context.Background(), coredns.Query{Name: "blocked.example"})
	if decision.Action != coredns.ActionBlock {
		t.Fatalf("action = %q (%s), want %q", decision.Action, decision.Reason, coredns.ActionBlock)
	}
}

func TestMemoryMatcherCanDisableBundledEntries(t *testing.T) {
	matcher := NewMatcherWithBundled(nil, false)

	decision := matcher.Decide(context.Background(), coredns.Query{Name: "blocked.example"})
	if decision.Action != coredns.ActionAllow {
		t.Fatalf("action = %q (%s), want %q", decision.Action, decision.Reason, coredns.ActionAllow)
	}
}

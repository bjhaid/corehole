package blocklist

import (
	"context"
	"strings"

	coredns "github.com/bjhaid/corehole/internal/dns"
)

type MemoryMatcher struct {
	allowExact  map[string]struct{}
	allowSuffix map[string]struct{}
	denyExact   map[string]struct{}
	denySuffix  map[string]struct{}
}

func NewMatcher(entries []Entry) *MemoryMatcher {
	return NewMatcherWithBundled(entries, BundledDefaultEnabled())
}

func NewMatcherWithBundled(entries []Entry, bundled bool) *MemoryMatcher {
	if bundled {
		entries = EntriesWithBundled(entries)
	}

	m := &MemoryMatcher{
		allowExact:  make(map[string]struct{}),
		allowSuffix: make(map[string]struct{}),
		denyExact:   make(map[string]struct{}),
		denySuffix:  make(map[string]struct{}),
	}
	for _, entry := range entries {
		domain, kind, ok := normalizeStoredEntry(entry)
		if !ok {
			continue
		}

		target := m.denyExact
		if entry.Allow {
			target = m.allowExact
		}
		if kind == EntrySuffix {
			target = m.denySuffix
			if entry.Allow {
				target = m.allowSuffix
			}
		}
		target[domain] = struct{}{}
	}
	return m
}

func (m *MemoryMatcher) Decide(ctx context.Context, q coredns.Query) coredns.Decision {
	_ = ctx

	name, ok := normalizeDomain(q.Name)
	if !ok {
		return coredns.Decision{Action: coredns.ActionAllow, Reason: "invalid query name"}
	}

	if m.matches(m.allowExact, m.allowSuffix, name) {
		return coredns.Decision{Action: coredns.ActionAllow, Reason: "blocklist allow match"}
	}
	if m.matches(m.denyExact, m.denySuffix, name) {
		return coredns.Decision{Action: coredns.ActionBlock, Reason: "blocklist deny match"}
	}
	return coredns.Decision{Action: coredns.ActionAllow, Reason: "no blocklist match"}
}

func (m *MemoryMatcher) matches(exact map[string]struct{}, suffix map[string]struct{}, name string) bool {
	if _, ok := exact[name]; ok {
		return true
	}
	for i, r := range name {
		if r != '.' {
			continue
		}
		if _, ok := suffix[name[i+1:]]; ok {
			return true
		}
	}
	return false
}

func normalizeStoredEntry(entry Entry) (string, EntryKind, bool) {
	switch entry.Kind {
	case EntryExact:
		domain, ok := normalizeDomain(entry.Domain)
		if !ok || strings.HasPrefix(domain, "*.") || isLocalHostsAlias(domain) {
			return "", "", false
		}
		return domain, EntryExact, true
	case EntrySuffix:
		domain := normalizeDomainText(entry.Domain)
		domain = strings.TrimPrefix(domain, "*.")
		if !validBlocklistDomain(domain) {
			return "", "", false
		}
		return domain, EntrySuffix, true
	default:
		return "", "", false
	}
}

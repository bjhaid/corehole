package filter

import (
	"context"
	"regexp"
	"sync/atomic"

	coreholedns "github.com/bjhaid/corehole/internal/dns"
)

// RuleDecider overlays custom rules on the in-memory blocklist matcher. Rules
// and client memberships are read only on reload, never on the DNS hot path.
type RuleDecider struct {
	repo     *Repository
	fallback coreholedns.Decider
	current  atomic.Pointer[ruleSnapshot]
}

type ruleSnapshot struct {
	rules   []scopedRule
	clients map[string]map[int64]struct{}
	regexps map[string]*regexp.Regexp
}

func NewRuleDecider(repo *Repository, fallback coreholedns.Decider) *RuleDecider {
	return &RuleDecider{repo: repo, fallback: fallback}
}

func (d *RuleDecider) Reload(ctx context.Context) error {
	rules, err := d.repo.decisionRules(ctx)
	if err != nil {
		return err
	}
	clients, err := d.repo.ListClients(ctx)
	if err != nil {
		return err
	}
	snapshot := &ruleSnapshot{
		rules: rules, clients: make(map[string]map[int64]struct{}),
		regexps: make(map[string]*regexp.Regexp),
	}
	for _, client := range clients {
		if !client.Enabled {
			continue
		}
		groups, err := d.repo.clientGroupIDs(ctx, client.Address)
		if err != nil {
			return err
		}
		snapshot.clients[client.Address] = groups
	}
	for _, rule := range rules {
		if rule.Enabled && rule.MatchType == MatchRegex {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return err
			}
			snapshot.regexps[rule.Pattern] = re
		}
	}
	d.current.Store(snapshot)
	return nil
}

func (d *RuleDecider) Decide(ctx context.Context, q coreholedns.Query) coreholedns.Decision {
	snapshot := d.current.Load()
	if snapshot == nil {
		return d.fallback.Decide(ctx, q)
	}
	domain := normalizeDomain(q.Name)
	groups := snapshot.clients[q.ClientIP.Unmap().String()]
	match := func(kind Kind, matchType MatchType, reason string) (coreholedns.Decision, bool) {
		for _, rule := range snapshot.rules {
			if !rule.Enabled || rule.Kind != kind || rule.MatchType != matchType || !inScope(rule.GroupID, groups) {
				continue
			}
			matched := false
			if matchType == MatchRegex {
				matched = snapshot.regexps[rule.Pattern].MatchString(domain)
			} else {
				matched = matchesPattern(domain, rule.Pattern, matchType)
			}
			if matched {
				action := coreholedns.ActionAllow
				if kind == KindDeny {
					action = coreholedns.ActionBlock
				}
				return coreholedns.Decision{Action: action, Reason: reason, RuleID: rule.ID}, true
			}
		}
		return coreholedns.Decision{}, false
	}
	for _, candidate := range []struct {
		kind      Kind
		matchType MatchType
		reason    string
	}{
		{KindAllow, MatchExact, "exact allow rule"},
		{KindAllow, MatchRegex, "regex allow rule"},
		{KindAllow, MatchSuffix, "suffix allow rule"},
		{KindDeny, MatchExact, "exact deny rule"},
	} {
		if decision, ok := match(candidate.kind, candidate.matchType, candidate.reason); ok {
			return decision
		}
	}
	decision := d.fallback.Decide(ctx, q)
	if decision.Action == coreholedns.ActionBlock || decision.Reason == "blocklist allow match" {
		return decision
	}
	if decision, ok := match(KindDeny, MatchRegex, "regex deny rule"); ok {
		return decision
	}
	if decision, ok := match(KindDeny, MatchSuffix, "suffix deny rule"); ok {
		return decision
	}
	return decision
}

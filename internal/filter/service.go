package filter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/bjhaid/corehole/internal/blocklist"
)

const defaultRefreshTimeout = 30 * time.Second

type Service struct {
	repo       *Repository
	parser     blocklist.Parser
	httpClient *http.Client
}

func NewService(repo *Repository) *Service {
	return &Service{
		repo:       repo,
		parser:     blocklist.NewParser(),
		httpClient: &http.Client{Timeout: defaultRefreshTimeout},
	}
}

type BlocklistSource struct {
	repo *Repository
}

func NewBlocklistSource(repo *Repository) *BlocklistSource {
	return &BlocklistSource{repo: repo}
}

func (s *BlocklistSource) Entries(ctx context.Context) ([]blocklist.Entry, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.BlocklistEntries(ctx)
}

func (s *Service) CreateList(ctx context.Context, list List) (List, error) {
	return s.repo.CreateList(ctx, list)
}

func (s *Service) ListLists(ctx context.Context) ([]List, error) {
	return s.repo.ListLists(ctx)
}

func (s *Service) GetList(ctx context.Context, id int64) (List, error) {
	return s.repo.GetList(ctx, id)
}

func (s *Service) UpdateList(ctx context.Context, list List) (List, error) {
	return s.repo.UpdateList(ctx, list)
}

func (s *Service) DeleteList(ctx context.Context, id int64) error {
	return s.repo.DeleteList(ctx, id)
}

func (s *Service) RefreshList(ctx context.Context, id int64) (List, error) {
	list, err := s.repo.GetList(ctx, id)
	if err != nil {
		return List{}, err
	}

	entries, err := s.importListEntries(ctx, list)
	if err != nil {
		marked, markErr := s.repo.MarkListRefreshError(ctx, id, err)
		if markErr != nil {
			return List{}, markErr
		}
		return marked, err
	}
	return s.repo.ReplaceListEntries(ctx, id, entries, time.Now())
}

func (s *Service) CreateListEntry(ctx context.Context, entry ListEntry) (ListEntry, error) {
	return s.repo.CreateListEntry(ctx, entry)
}

func (s *Service) ListListEntries(ctx context.Context, listID int64) ([]ListEntry, error) {
	return s.repo.ListListEntries(ctx, listID)
}

func (s *Service) UpdateListEntry(ctx context.Context, entry ListEntry) (ListEntry, error) {
	return s.repo.UpdateListEntry(ctx, entry)
}

func (s *Service) DeleteListEntry(ctx context.Context, id int64) error {
	return s.repo.DeleteListEntry(ctx, id)
}

func (s *Service) CreateRule(ctx context.Context, rule Rule) (Rule, error) {
	return s.repo.CreateRule(ctx, rule)
}

func (s *Service) ListRules(ctx context.Context) ([]Rule, error) {
	return s.repo.ListRules(ctx)
}

func (s *Service) GetRule(ctx context.Context, id int64) (Rule, error) {
	return s.repo.GetRule(ctx, id)
}

func (s *Service) UpdateRule(ctx context.Context, rule Rule) (Rule, error) {
	return s.repo.UpdateRule(ctx, rule)
}

func (s *Service) DeleteRule(ctx context.Context, id int64) error {
	return s.repo.DeleteRule(ctx, id)
}

func (s *Service) CreateClient(ctx context.Context, client Client) (Client, error) {
	return s.repo.CreateClient(ctx, client)
}

func (s *Service) ListClients(ctx context.Context) ([]Client, error) {
	return s.repo.ListClients(ctx)
}

func (s *Service) GetClient(ctx context.Context, id int64) (Client, error) {
	return s.repo.GetClient(ctx, id)
}

func (s *Service) UpdateClient(ctx context.Context, client Client) (Client, error) {
	return s.repo.UpdateClient(ctx, client)
}

func (s *Service) DeleteClient(ctx context.Context, id int64) error {
	return s.repo.DeleteClient(ctx, id)
}

func (s *Service) CreateGroup(ctx context.Context, group Group) (Group, error) {
	return s.repo.CreateGroup(ctx, group)
}

func (s *Service) ListGroups(ctx context.Context) ([]Group, error) {
	return s.repo.ListGroups(ctx)
}

func (s *Service) GetGroup(ctx context.Context, id int64) (Group, error) {
	return s.repo.GetGroup(ctx, id)
}

func (s *Service) UpdateGroup(ctx context.Context, group Group) (Group, error) {
	return s.repo.UpdateGroup(ctx, group)
}

func (s *Service) DeleteGroup(ctx context.Context, id int64) error {
	return s.repo.DeleteGroup(ctx, id)
}

func (s *Service) AddClientGroup(ctx context.Context, clientID int64, groupID int64) error {
	if _, err := s.repo.GetClient(ctx, clientID); err != nil {
		return err
	}
	if _, err := s.repo.GetGroup(ctx, groupID); err != nil {
		return err
	}
	return s.repo.AddClientGroup(ctx, clientID, groupID)
}

func (s *Service) RemoveClientGroup(ctx context.Context, clientID int64, groupID int64) error {
	if _, err := s.repo.GetClient(ctx, clientID); err != nil {
		return err
	}
	if _, err := s.repo.GetGroup(ctx, groupID); err != nil {
		return err
	}
	return s.repo.RemoveClientGroup(ctx, clientID, groupID)
}

func (s *Service) ListClientGroups(ctx context.Context, clientID int64) ([]Group, error) {
	return s.repo.ListClientGroups(ctx, clientID)
}

func (s *Service) AddListGroup(ctx context.Context, listID int64, groupID int64) error {
	if _, err := s.repo.GetList(ctx, listID); err != nil {
		return err
	}
	if _, err := s.repo.GetGroup(ctx, groupID); err != nil {
		return err
	}
	return s.repo.AddListGroup(ctx, listID, groupID)
}

func (s *Service) RemoveListGroup(ctx context.Context, listID int64, groupID int64) error {
	if _, err := s.repo.GetList(ctx, listID); err != nil {
		return err
	}
	if _, err := s.repo.GetGroup(ctx, groupID); err != nil {
		return err
	}
	return s.repo.RemoveListGroup(ctx, listID, groupID)
}

func (s *Service) ListListGroups(ctx context.Context, listID int64) ([]Group, error) {
	return s.repo.ListListGroups(ctx, listID)
}

func (s *Service) AddRuleGroup(ctx context.Context, ruleID int64, groupID int64) error {
	if _, err := s.repo.GetRule(ctx, ruleID); err != nil {
		return err
	}
	if _, err := s.repo.GetGroup(ctx, groupID); err != nil {
		return err
	}
	return s.repo.AddRuleGroup(ctx, ruleID, groupID)
}

func (s *Service) RemoveRuleGroup(ctx context.Context, ruleID int64, groupID int64) error {
	if _, err := s.repo.GetRule(ctx, ruleID); err != nil {
		return err
	}
	if _, err := s.repo.GetGroup(ctx, groupID); err != nil {
		return err
	}
	return s.repo.RemoveRuleGroup(ctx, ruleID, groupID)
}

func (s *Service) ListRuleGroups(ctx context.Context, ruleID int64) ([]Group, error) {
	return s.repo.ListRuleGroups(ctx, ruleID)
}

func (s *Service) importListEntries(ctx context.Context, list List) ([]ListEntry, error) {
	reader, source, err := s.openListSource(ctx, list)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	parser := s.parser
	if parser == nil {
		parser = blocklist.NewParser()
	}
	parsed, err := parser.Parse(ctx, reader, source)
	if err != nil {
		return nil, fmt.Errorf("parse filter list %s: %w", source, err)
	}

	entries := make([]ListEntry, 0, len(parsed))
	seen := make(map[string]struct{}, len(parsed))
	for _, entry := range parsed {
		matchType, ok := matchTypeForBlocklistEntry(entry.Kind)
		if !ok {
			continue
		}
		listEntry := ListEntry{
			ListID:    list.ID,
			Pattern:   entry.Domain,
			MatchType: matchType,
			Enabled:   true,
		}
		if err := validateListEntry(&listEntry); err != nil {
			continue
		}
		key := string(listEntry.MatchType) + "\x00" + listEntry.Pattern
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, listEntry)
	}
	return entries, nil
}

func (s *Service) openListSource(ctx context.Context, list List) (io.ReadCloser, string, error) {
	if list.URL != "" {
		parsed, err := url.Parse(list.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return nil, "", fmt.Errorf("invalid filter list url %q", list.URL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, list.URL, nil)
		if err != nil {
			return nil, "", fmt.Errorf("create filter list request: %w", err)
		}
		client := s.httpClient
		if client == nil {
			client = &http.Client{Timeout: defaultRefreshTimeout}
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("fetch filter list %s: %w", list.URL, err)
		}
		if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
			res.Body.Close()
			return nil, "", fmt.Errorf("fetch filter list %s: status %d", list.URL, res.StatusCode)
		}
		return res.Body, list.URL, nil
	}

	if list.Path == "" {
		return nil, "", fmt.Errorf("%w: url or path is required", ErrInvalidInput)
	}
	f, err := os.Open(list.Path)
	if err != nil {
		return nil, "", fmt.Errorf("open filter list %s: %w", list.Path, err)
	}
	return f, list.Path, nil
}

func matchTypeForBlocklistEntry(kind blocklist.EntryKind) (MatchType, bool) {
	switch kind {
	case blocklist.EntryExact:
		return MatchExact, true
	case blocklist.EntrySuffix:
		return MatchSuffix, true
	default:
		return "", false
	}
}

func (s *Service) Decide(ctx context.Context, req DecisionRequest) (Decision, error) {
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return Decision{}, fmt.Errorf("%w: domain is required", ErrInvalidInput)
	}

	groupIDs := map[int64]struct{}{}
	if req.ClientAddress != "" {
		address, err := netip.ParseAddr(req.ClientAddress)
		if err != nil {
			return Decision{}, fmt.Errorf("%w: invalid client address", ErrInvalidInput)
		}
		groupIDs, err = s.repo.clientGroupIDs(ctx, address.String())
		if err != nil {
			return Decision{}, err
		}
	}

	rules, err := s.repo.decisionRules(ctx)
	if err != nil {
		return Decision{}, err
	}
	entries, err := s.repo.decisionEntries(ctx)
	if err != nil {
		return Decision{}, err
	}

	if decision, ok := firstMatchingRule(domain, groupIDs, rules, KindAllow, MatchExact, "exact allow rule"); ok {
		return decision, nil
	}
	if decision, ok := firstMatchingRule(domain, groupIDs, rules, KindAllow, MatchRegex, "regex allow rule"); ok {
		return decision, nil
	}
	if decision, ok := firstMatchingRule(domain, groupIDs, rules, KindAllow, MatchSuffix, "suffix allow rule"); ok {
		return decision, nil
	}
	if decision, ok := firstMatchingRule(domain, groupIDs, rules, KindDeny, MatchExact, "exact deny rule"); ok {
		return decision, nil
	}
	if decision, ok := firstMatchingEntry(domain, groupIDs, entries, KindAllow, "subscribed allow list"); ok {
		return decision, nil
	}
	if decision, ok := firstMatchingEntry(domain, groupIDs, entries, KindDeny, "subscribed deny list"); ok {
		return decision, nil
	}
	if decision, ok := firstMatchingRule(domain, groupIDs, rules, KindDeny, MatchRegex, "regex deny rule"); ok {
		return decision, nil
	}
	if decision, ok := firstMatchingRule(domain, groupIDs, rules, KindDeny, MatchSuffix, "suffix deny rule"); ok {
		return decision, nil
	}

	return Decision{Action: ActionNone, Reason: "no filter match"}, nil
}

func firstMatchingRule(domain string, groupIDs map[int64]struct{}, rules []scopedRule, kind Kind, matchType MatchType, reason string) (Decision, bool) {
	seen := make(map[int64]struct{})
	for _, rule := range rules {
		if _, ok := seen[rule.ID]; ok && rule.GroupID == 0 {
			continue
		}
		if !rule.Enabled || rule.Kind != kind || rule.MatchType != matchType || !inScope(rule.GroupID, groupIDs) {
			continue
		}
		if !matchesPattern(domain, rule.Pattern, rule.MatchType) {
			continue
		}
		seen[rule.ID] = struct{}{}
		return Decision{
			Action:    actionForKind(kind),
			Reason:    reason,
			RuleID:    rule.ID,
			Pattern:   rule.Pattern,
			MatchType: string(rule.MatchType),
		}, true
	}
	return Decision{}, false
}

func firstMatchingEntry(domain string, groupIDs map[int64]struct{}, entries []scopedListEntry, kind Kind, reason string) (Decision, bool) {
	seen := make(map[int64]struct{})
	for _, entry := range entries {
		if _, ok := seen[entry.ID]; ok && entry.GroupID == 0 {
			continue
		}
		if !entry.Enabled || entry.Kind != kind || !inScope(entry.GroupID, groupIDs) {
			continue
		}
		if !matchesPattern(domain, entry.Pattern, entry.MatchType) {
			continue
		}
		seen[entry.ID] = struct{}{}
		return Decision{
			Action:    actionForKind(kind),
			Reason:    reason,
			ListID:    entry.ListID,
			EntryID:   entry.ID,
			Pattern:   entry.Pattern,
			MatchType: string(entry.MatchType),
		}, true
	}
	return Decision{}, false
}

func inScope(groupID int64, clientGroups map[int64]struct{}) bool {
	if groupID == 0 {
		return true
	}
	_, ok := clientGroups[groupID]
	return ok
}

func actionForKind(kind Kind) Action {
	if kind == KindAllow {
		return ActionAllow
	}
	return ActionDeny
}

type scopedRule struct {
	Rule
	GroupID int64
}

type scopedListEntry struct {
	ListEntry
	Kind    Kind
	GroupID int64
}

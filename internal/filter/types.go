package filter

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

type Kind string

const (
	KindAllow Kind = "allow"
	KindDeny  Kind = "deny"
)

type MatchType string

const (
	MatchExact  MatchType = "exact"
	MatchSuffix MatchType = "suffix"
	MatchRegex  MatchType = "regex"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionNone  Action = "none"
)

var (
	ErrInvalidInput = errors.New("invalid filter input")
	ErrNotFound     = errors.New("filter record not found")
)

type List struct {
	ID            int64      `json:"id"`
	URL           string     `json:"url,omitempty"`
	Path          string     `json:"path,omitempty"`
	Kind          Kind       `json:"kind"`
	Enabled       bool       `json:"enabled"`
	LastUpdatedAt *time.Time `json:"last_updated_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

type ListEntry struct {
	ID        int64     `json:"id"`
	ListID    int64     `json:"list_id"`
	Pattern   string    `json:"pattern"`
	MatchType MatchType `json:"match_type"`
	Enabled   bool      `json:"enabled"`
}

type Rule struct {
	ID        int64     `json:"id"`
	Pattern   string    `json:"pattern"`
	Kind      Kind      `json:"kind"`
	MatchType MatchType `json:"match_type"`
	Enabled   bool      `json:"enabled"`
	Comment   string    `json:"comment,omitempty"`
}

type Client struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Comment string `json:"comment,omitempty"`
	Enabled bool   `json:"enabled"`
}

type Group struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
	Enabled bool   `json:"enabled"`
}

type DecisionRequest struct {
	Domain        string
	ClientAddress string
}

type Decision struct {
	Action    Action `json:"action"`
	Reason    string `json:"reason"`
	RuleID    int64  `json:"rule_id,omitempty"`
	ListID    int64  `json:"list_id,omitempty"`
	EntryID   int64  `json:"entry_id,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	MatchType string `json:"match_type,omitempty"`
}

type BlocklistRuntimeStats struct {
	EnabledLists         int
	ImportedEnabledLists int
	EnabledEntries       int
}

func normalizeKind(kind Kind) (Kind, error) {
	switch Kind(strings.ToLower(strings.TrimSpace(string(kind)))) {
	case KindAllow:
		return KindAllow, nil
	case KindDeny:
		return KindDeny, nil
	default:
		return "", fmt.Errorf("%w: kind must be allow or deny", ErrInvalidInput)
	}
}

func normalizeMatchType(matchType MatchType) (MatchType, error) {
	switch MatchType(strings.ToLower(strings.TrimSpace(string(matchType)))) {
	case MatchExact:
		return MatchExact, nil
	case MatchSuffix:
		return MatchSuffix, nil
	case MatchRegex:
		return MatchRegex, nil
	default:
		return "", fmt.Errorf("%w: match_type must be exact, suffix, or regex", ErrInvalidInput)
	}
}

func normalizePattern(pattern string, matchType MatchType) (string, error) {
	pattern = strings.TrimSpace(strings.TrimSuffix(pattern, "."))
	if pattern == "" {
		return "", fmt.Errorf("%w: pattern is required", ErrInvalidInput)
	}
	if matchType == MatchRegex {
		if _, err := regexp.Compile(pattern); err != nil {
			return "", fmt.Errorf("%w: invalid regex pattern", ErrInvalidInput)
		}
		return pattern, nil
	}
	return strings.ToLower(pattern), nil
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
}

func validateList(list *List) error {
	if list == nil {
		return fmt.Errorf("%w: list is required", ErrInvalidInput)
	}
	kind, err := normalizeKind(list.Kind)
	if err != nil {
		return err
	}
	list.Kind = kind
	list.URL = strings.TrimSpace(list.URL)
	list.Path = strings.TrimSpace(list.Path)
	list.LastError = strings.TrimSpace(list.LastError)
	if list.URL == "" && list.Path == "" {
		return fmt.Errorf("%w: url or path is required", ErrInvalidInput)
	}
	return nil
}

func validateRule(rule *Rule) error {
	if rule == nil {
		return fmt.Errorf("%w: rule is required", ErrInvalidInput)
	}
	kind, err := normalizeKind(rule.Kind)
	if err != nil {
		return err
	}
	matchType, err := normalizeMatchType(rule.MatchType)
	if err != nil {
		return err
	}
	pattern, err := normalizePattern(rule.Pattern, matchType)
	if err != nil {
		return err
	}
	rule.Kind = kind
	rule.MatchType = matchType
	rule.Pattern = pattern
	rule.Comment = strings.TrimSpace(rule.Comment)
	return nil
}

func validateListEntry(entry *ListEntry) error {
	if entry == nil {
		return fmt.Errorf("%w: list entry is required", ErrInvalidInput)
	}
	if entry.ListID <= 0 {
		return fmt.Errorf("%w: list_id is required", ErrInvalidInput)
	}
	matchType, err := normalizeMatchType(entry.MatchType)
	if err != nil {
		return err
	}
	pattern, err := normalizePattern(entry.Pattern, matchType)
	if err != nil {
		return err
	}
	entry.MatchType = matchType
	entry.Pattern = pattern
	return nil
}

func validateClient(client *Client) error {
	if client == nil {
		return fmt.Errorf("%w: client is required", ErrInvalidInput)
	}
	client.Name = strings.TrimSpace(client.Name)
	client.Address = strings.TrimSpace(client.Address)
	client.Comment = strings.TrimSpace(client.Comment)
	if client.Name == "" {
		return fmt.Errorf("%w: client name is required", ErrInvalidInput)
	}
	if client.Address == "" {
		return fmt.Errorf("%w: client address is required", ErrInvalidInput)
	}
	if _, err := netip.ParseAddr(client.Address); err != nil {
		return fmt.Errorf("%w: invalid client address", ErrInvalidInput)
	}
	return nil
}

func validateGroup(group *Group) error {
	if group == nil {
		return fmt.Errorf("%w: group is required", ErrInvalidInput)
	}
	group.Name = strings.TrimSpace(group.Name)
	group.Comment = strings.TrimSpace(group.Comment)
	if group.Name == "" {
		return fmt.Errorf("%w: group name is required", ErrInvalidInput)
	}
	return nil
}

func matchesPattern(domain string, pattern string, matchType MatchType) bool {
	switch matchType {
	case MatchExact:
		return domain == normalizeDomain(pattern)
	case MatchSuffix:
		pattern = normalizeDomain(strings.TrimPrefix(pattern, "*."))
		return domain == pattern || strings.HasSuffix(domain, "."+pattern)
	case MatchRegex:
		ok, err := regexp.MatchString(pattern, domain)
		return err == nil && ok
	default:
		return false
	}
}

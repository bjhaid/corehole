package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bjhaid/corehole/internal/audit"
	"github.com/bjhaid/corehole/internal/filter"
)

const (
	defaultClientSuggestionLimit = 20
	maxClientSuggestionLimit     = 100
)

type FilterService interface {
	CreateList(context.Context, filter.List) (filter.List, error)
	ListLists(context.Context) ([]filter.List, error)
	GetList(context.Context, int64) (filter.List, error)
	UpdateList(context.Context, filter.List) (filter.List, error)
	DeleteList(context.Context, int64) error
	RefreshList(context.Context, int64) (filter.List, error)
	CreateListEntry(context.Context, filter.ListEntry) (filter.ListEntry, error)
	ListListEntries(context.Context, int64) ([]filter.ListEntry, error)
	UpdateListEntry(context.Context, filter.ListEntry) (filter.ListEntry, error)
	DeleteListEntry(context.Context, int64) error
	CreateRule(context.Context, filter.Rule) (filter.Rule, error)
	ListRules(context.Context) ([]filter.Rule, error)
	GetRule(context.Context, int64) (filter.Rule, error)
	UpdateRule(context.Context, filter.Rule) (filter.Rule, error)
	DeleteRule(context.Context, int64) error
	CreateClient(context.Context, filter.Client) (filter.Client, error)
	ListClients(context.Context) ([]filter.Client, error)
	GetClient(context.Context, int64) (filter.Client, error)
	UpdateClient(context.Context, filter.Client) (filter.Client, error)
	DeleteClient(context.Context, int64) error
	CreateGroup(context.Context, filter.Group) (filter.Group, error)
	ListGroups(context.Context) ([]filter.Group, error)
	GetGroup(context.Context, int64) (filter.Group, error)
	UpdateGroup(context.Context, filter.Group) (filter.Group, error)
	DeleteGroup(context.Context, int64) error
	AddClientGroup(context.Context, int64, int64) error
	RemoveClientGroup(context.Context, int64, int64) error
	ListClientGroups(context.Context, int64) ([]filter.Group, error)
	AddListGroup(context.Context, int64, int64) error
	RemoveListGroup(context.Context, int64, int64) error
	ListListGroups(context.Context, int64) ([]filter.Group, error)
	AddRuleGroup(context.Context, int64, int64) error
	RemoveRuleGroup(context.Context, int64, int64) error
	ListRuleGroups(context.Context, int64) ([]filter.Group, error)
}

type FilterReloader interface {
	Reload(context.Context) error
}

type auditClientSuggestionReader interface {
	RecentClients(context.Context, int) ([]audit.ClientSuggestion, error)
}

func WithFilterService(service FilterService) Option {
	return func(s *Server) {
		if service != nil {
			s.filterService = service
		}
	}
}

func WithFilterReloader(reloader FilterReloader) Option {
	return func(s *Server) {
		if reloader != nil {
			s.filterReloader = reloader
		}
	}
}

type filterListRequest struct {
	URL           string  `json:"url,omitempty"`
	Path          string  `json:"path,omitempty"`
	Kind          string  `json:"kind"`
	Enabled       *bool   `json:"enabled,omitempty"`
	LastUpdatedAt *string `json:"last_updated_at,omitempty"`
	LastError     string  `json:"last_error,omitempty"`
}

type filterListEntryRequest struct {
	Pattern   string `json:"pattern"`
	MatchType string `json:"match_type"`
	Enabled   *bool  `json:"enabled,omitempty"`
}

type filterRuleRequest struct {
	Pattern   string `json:"pattern"`
	Kind      string `json:"kind"`
	MatchType string `json:"match_type"`
	Enabled   *bool  `json:"enabled,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

type filterClientRequest struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Comment string `json:"comment,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type filterClientSuggestionsResponse struct {
	Suggestions  []filterClientSuggestionResponse `json:"suggestions"`
	PrivacyLevel int                              `json:"privacy_level"`
}

type filterClientSuggestionResponse struct {
	Address  string    `json:"address"`
	ClientIP string    `json:"client_ip"`
	LastSeen time.Time `json:"last_seen"`
	Count    int       `json:"count"`
}

type filterGroupRequest struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type filterGroupAssignmentRequest struct {
	GroupID int64 `json:"group_id"`
}

func (s *Server) handleFilterLists(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		lists, err := s.filterService.ListLists(r.Context())
		if err != nil {
			writeFilterError(w, err, "filter_lists_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string][]filter.List{"lists": lists})
	case http.MethodPost:
		var req filterListRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		lastUpdatedAt, ok := parseOptionalFilterTime(w, req.LastUpdatedAt)
		if !ok {
			return
		}
		list, err := s.filterService.CreateList(r.Context(), filter.List{
			URL:           req.URL,
			Path:          req.Path,
			Kind:          filter.Kind(req.Kind),
			Enabled:       boolDefault(req.Enabled, true),
			LastUpdatedAt: lastUpdatedAt,
			LastError:     req.LastError,
		})
		if err != nil {
			writeFilterError(w, err, "filter_list_create_failed")
			return
		}
		writeJSON(w, http.StatusCreated, list)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterList(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	id, tail, ok := parseFilterIDPath(w, r.URL.Path, "/api/filter/lists/")
	if !ok {
		return
	}
	if tail == "entries" {
		s.handleFilterListEntries(w, r, id)
		return
	}
	if tail == "refresh" {
		s.handleFilterListRefresh(w, r, id)
		return
	}
	if tail == "groups" || strings.HasPrefix(tail, "groups/") {
		s.handleFilterListGroups(w, r, id, tail)
		return
	}
	if tail != "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.filterService.GetList(r.Context(), id)
		if err != nil {
			writeFilterError(w, err, "filter_list_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, list)
	case http.MethodPut:
		current, err := s.filterService.GetList(r.Context(), id)
		if err != nil {
			writeFilterError(w, err, "filter_list_unavailable")
			return
		}
		var req filterListRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		lastUpdatedAt, ok := parseOptionalFilterTime(w, req.LastUpdatedAt)
		if !ok {
			return
		}
		current.URL = req.URL
		current.Path = req.Path
		current.Kind = filter.Kind(req.Kind)
		current.Enabled = boolDefault(req.Enabled, current.Enabled)
		current.LastUpdatedAt = lastUpdatedAt
		current.LastError = req.LastError
		list, err := s.filterService.UpdateList(r.Context(), current)
		if err != nil {
			writeFilterError(w, err, "filter_list_update_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, list)
	case http.MethodDelete:
		if err := s.filterService.DeleteList(r.Context(), id); err != nil {
			writeFilterError(w, err, "filter_list_delete_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterListRefresh(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	list, err := s.filterService.RefreshList(r.Context(), id)
	if err != nil {
		writeFilterError(w, err, "filter_list_refresh_failed")
		return
	}
	if !s.reloadFilterRuntime(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleFilterListGroups(w http.ResponseWriter, r *http.Request, listID int64, tail string) {
	groupID, ok := parseFilterGroupAssignmentTail(w, tail)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if groupID != 0 {
			http.NotFound(w, r)
			return
		}
		groups, err := s.filterService.ListListGroups(r.Context(), listID)
		if err != nil {
			writeFilterError(w, err, "filter_list_groups_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string][]filter.Group{"groups": groups})
	case http.MethodPost:
		if groupID != 0 {
			http.NotFound(w, r)
			return
		}
		groupID, ok = decodeFilterGroupAssignment(w, r)
		if !ok {
			return
		}
		if err := s.filterService.AddListGroup(r.Context(), listID, groupID); err != nil {
			writeFilterError(w, err, "filter_list_group_add_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if groupID == 0 {
			http.NotFound(w, r)
			return
		}
		if err := s.filterService.RemoveListGroup(r.Context(), listID, groupID); err != nil {
			writeFilterError(w, err, "filter_list_group_remove_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterListEntries(w http.ResponseWriter, r *http.Request, listID int64) {
	switch r.Method {
	case http.MethodGet:
		entries, err := s.filterService.ListListEntries(r.Context(), listID)
		if err != nil {
			writeFilterError(w, err, "filter_list_entries_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string][]filter.ListEntry{"entries": entries})
	case http.MethodPost:
		var req filterListEntryRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		entry, err := s.filterService.CreateListEntry(r.Context(), filter.ListEntry{
			ListID:    listID,
			Pattern:   req.Pattern,
			MatchType: filter.MatchType(req.MatchType),
			Enabled:   boolDefault(req.Enabled, true),
		})
		if err != nil {
			writeFilterError(w, err, "filter_list_entry_create_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		writeJSON(w, http.StatusCreated, entry)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterListEntry(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	id, tail, ok := parseFilterIDPath(w, r.URL.Path, "/api/filter/list-entries/")
	if !ok {
		return
	}
	if tail != "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			ListID int64 `json:"list_id"`
			filterListEntryRequest
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		entry, err := s.filterService.UpdateListEntry(r.Context(), filter.ListEntry{
			ID:        id,
			ListID:    req.ListID,
			Pattern:   req.Pattern,
			MatchType: filter.MatchType(req.MatchType),
			Enabled:   boolDefault(req.Enabled, true),
		})
		if err != nil {
			writeFilterError(w, err, "filter_list_entry_update_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, entry)
	case http.MethodDelete:
		if err := s.filterService.DeleteListEntry(r.Context(), id); err != nil {
			writeFilterError(w, err, "filter_list_entry_delete_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterRules(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rules, err := s.filterService.ListRules(r.Context())
		if err != nil {
			writeFilterError(w, err, "filter_rules_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string][]filter.Rule{"rules": rules})
	case http.MethodPost:
		var req filterRuleRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		rule, err := s.filterService.CreateRule(r.Context(), filter.Rule{
			Pattern:   req.Pattern,
			Kind:      filter.Kind(req.Kind),
			MatchType: filter.MatchType(req.MatchType),
			Enabled:   boolDefault(req.Enabled, true),
			Comment:   req.Comment,
		})
		if err != nil {
			writeFilterError(w, err, "filter_rule_create_failed")
			return
		}
		writeJSON(w, http.StatusCreated, rule)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterRule(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	id, tail, ok := parseFilterIDPath(w, r.URL.Path, "/api/filter/rules/")
	if !ok {
		return
	}
	if tail == "groups" || strings.HasPrefix(tail, "groups/") {
		s.handleFilterRuleGroups(w, r, id, tail)
		return
	}
	if tail != "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rule, err := s.filterService.GetRule(r.Context(), id)
		if err != nil {
			writeFilterError(w, err, "filter_rule_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, rule)
	case http.MethodPut:
		current, err := s.filterService.GetRule(r.Context(), id)
		if err != nil {
			writeFilterError(w, err, "filter_rule_unavailable")
			return
		}
		var req filterRuleRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		current.Pattern = req.Pattern
		current.Kind = filter.Kind(req.Kind)
		current.MatchType = filter.MatchType(req.MatchType)
		current.Enabled = boolDefault(req.Enabled, current.Enabled)
		current.Comment = req.Comment
		rule, err := s.filterService.UpdateRule(r.Context(), current)
		if err != nil {
			writeFilterError(w, err, "filter_rule_update_failed")
			return
		}
		writeJSON(w, http.StatusOK, rule)
	case http.MethodDelete:
		if err := s.filterService.DeleteRule(r.Context(), id); err != nil {
			writeFilterError(w, err, "filter_rule_delete_failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterRuleGroups(w http.ResponseWriter, r *http.Request, ruleID int64, tail string) {
	groupID, ok := parseFilterGroupAssignmentTail(w, tail)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if groupID != 0 {
			http.NotFound(w, r)
			return
		}
		groups, err := s.filterService.ListRuleGroups(r.Context(), ruleID)
		if err != nil {
			writeFilterError(w, err, "filter_rule_groups_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string][]filter.Group{"groups": groups})
	case http.MethodPost:
		if groupID != 0 {
			http.NotFound(w, r)
			return
		}
		groupID, ok = decodeFilterGroupAssignment(w, r)
		if !ok {
			return
		}
		if err := s.filterService.AddRuleGroup(r.Context(), ruleID, groupID); err != nil {
			writeFilterError(w, err, "filter_rule_group_add_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if groupID == 0 {
			http.NotFound(w, r)
			return
		}
		if err := s.filterService.RemoveRuleGroup(r.Context(), ruleID, groupID); err != nil {
			writeFilterError(w, err, "filter_rule_group_remove_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterClients(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		clients, err := s.filterService.ListClients(r.Context())
		if err != nil {
			writeFilterError(w, err, "filter_clients_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string][]filter.Client{"clients": clients})
	case http.MethodPost:
		var req filterClientRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		client, err := s.filterService.CreateClient(r.Context(), filter.Client{
			Name:    req.Name,
			Address: req.Address,
			Comment: req.Comment,
			Enabled: boolDefault(req.Enabled, true),
		})
		if err != nil {
			writeFilterError(w, err, "filter_client_create_failed")
			return
		}
		writeJSON(w, http.StatusCreated, client)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterClientSuggestions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	settings, err := s.auditSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "client_suggestions_unavailable")
		return
	}
	if settings.PrivacyLevel >= audit.PrivacyLevelHideClient {
		writeJSON(w, http.StatusOK, filterClientSuggestionsResponse{
			Suggestions:  []filterClientSuggestionResponse{},
			PrivacyLevel: int(settings.PrivacyLevel),
		})
		return
	}
	reader, ok := s.auditReader.(auditClientSuggestionReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "client_suggestions_unavailable")
		return
	}
	limit, ok := parseClientSuggestionLimit(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_limit")
		return
	}
	suggestions, err := reader.RecentClients(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "client_suggestions_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, filterClientSuggestionsResponse{
		Suggestions:  filterClientSuggestionResponses(suggestions),
		PrivacyLevel: int(settings.PrivacyLevel),
	})
}

func (s *Server) handleFilterClient(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	id, tail, ok := parseFilterIDPath(w, r.URL.Path, "/api/filter/clients/")
	if !ok {
		return
	}
	if tail == "groups" || strings.HasPrefix(tail, "groups/") {
		s.handleFilterClientGroups(w, r, id, tail)
		return
	}
	if tail != "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		client, err := s.filterService.GetClient(r.Context(), id)
		if err != nil {
			writeFilterError(w, err, "filter_client_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, client)
	case http.MethodPut:
		current, err := s.filterService.GetClient(r.Context(), id)
		if err != nil {
			writeFilterError(w, err, "filter_client_unavailable")
			return
		}
		var req filterClientRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		current.Name = req.Name
		current.Address = req.Address
		current.Comment = req.Comment
		current.Enabled = boolDefault(req.Enabled, current.Enabled)
		client, err := s.filterService.UpdateClient(r.Context(), current)
		if err != nil {
			writeFilterError(w, err, "filter_client_update_failed")
			return
		}
		writeJSON(w, http.StatusOK, client)
	case http.MethodDelete:
		if err := s.filterService.DeleteClient(r.Context(), id); err != nil {
			writeFilterError(w, err, "filter_client_delete_failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterClientGroups(w http.ResponseWriter, r *http.Request, clientID int64, tail string) {
	groupID, ok := parseFilterGroupAssignmentTail(w, tail)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if groupID != 0 {
			http.NotFound(w, r)
			return
		}
		groups, err := s.filterService.ListClientGroups(r.Context(), clientID)
		if err != nil {
			writeFilterError(w, err, "filter_client_groups_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string][]filter.Group{"groups": groups})
	case http.MethodPost:
		if groupID != 0 {
			http.NotFound(w, r)
			return
		}
		groupID, ok = decodeFilterGroupAssignment(w, r)
		if !ok {
			return
		}
		if err := s.filterService.AddClientGroup(r.Context(), clientID, groupID); err != nil {
			writeFilterError(w, err, "filter_client_group_add_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if groupID == 0 {
			http.NotFound(w, r)
			return
		}
		if err := s.filterService.RemoveClientGroup(r.Context(), clientID, groupID); err != nil {
			writeFilterError(w, err, "filter_client_group_remove_failed")
			return
		}
		if !s.reloadFilterRuntime(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterGroups(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		groups, err := s.filterService.ListGroups(r.Context())
		if err != nil {
			writeFilterError(w, err, "filter_groups_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string][]filter.Group{"groups": groups})
	case http.MethodPost:
		var req filterGroupRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		group, err := s.filterService.CreateGroup(r.Context(), filter.Group{
			Name:    req.Name,
			Comment: req.Comment,
			Enabled: boolDefault(req.Enabled, true),
		})
		if err != nil {
			writeFilterError(w, err, "filter_group_create_failed")
			return
		}
		writeJSON(w, http.StatusCreated, group)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFilterGroup(w http.ResponseWriter, r *http.Request) {
	if s.filterService == nil {
		writeError(w, http.StatusServiceUnavailable, "filter_unavailable")
		return
	}
	id, tail, ok := parseFilterIDPath(w, r.URL.Path, "/api/filter/groups/")
	if !ok {
		return
	}
	if tail != "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		group, err := s.filterService.GetGroup(r.Context(), id)
		if err != nil {
			writeFilterError(w, err, "filter_group_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, group)
	case http.MethodPut:
		current, err := s.filterService.GetGroup(r.Context(), id)
		if err != nil {
			writeFilterError(w, err, "filter_group_unavailable")
			return
		}
		var req filterGroupRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		current.Name = req.Name
		current.Comment = req.Comment
		current.Enabled = boolDefault(req.Enabled, current.Enabled)
		group, err := s.filterService.UpdateGroup(r.Context(), current)
		if err != nil {
			writeFilterError(w, err, "filter_group_update_failed")
			return
		}
		writeJSON(w, http.StatusOK, group)
	case http.MethodDelete:
		if err := s.filterService.DeleteGroup(r.Context(), id); err != nil {
			writeFilterError(w, err, "filter_group_delete_failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func parseFilterIDPath(w http.ResponseWriter, path string, prefix string) (int64, string, bool) {
	rest := strings.TrimPrefix(path, prefix)
	if rest == path || rest == "" {
		http.NotFound(w, &http.Request{})
		return 0, "", false
	}
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_filter_id")
		return 0, "", false
	}
	var tail string
	if len(parts) == 2 {
		tail = strings.Trim(parts[1], "/")
	}
	return id, tail, true
}

func parseFilterGroupAssignmentTail(w http.ResponseWriter, tail string) (int64, bool) {
	if tail == "groups" {
		return 0, true
	}
	if !strings.HasPrefix(tail, "groups/") {
		http.NotFound(w, &http.Request{})
		return 0, false
	}
	rest := strings.TrimPrefix(tail, "groups/")
	if rest == "" || strings.Contains(rest, "/") {
		http.NotFound(w, &http.Request{})
		return 0, false
	}
	groupID, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || groupID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_filter_group_id")
		return 0, false
	}
	return groupID, true
}

func decodeFilterGroupAssignment(w http.ResponseWriter, r *http.Request) (int64, bool) {
	var req filterGroupAssignmentRequest
	if !decodeJSON(w, r, &req) {
		return 0, false
	}
	if req.GroupID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_filter_group_id")
		return 0, false
	}
	return req.GroupID, true
}

func writeFilterError(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, filter.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid_filter")
	case errors.Is(err, filter.ErrNotFound):
		writeError(w, http.StatusNotFound, "filter_not_found")
	default:
		writeError(w, http.StatusInternalServerError, fallback)
	}
}

func (s *Server) reloadFilterRuntime(w http.ResponseWriter, r *http.Request) bool {
	if s.filterReloader == nil {
		return true
	}
	if err := s.filterReloader.Reload(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "filter_reload_failed")
		return false
	}
	return true
}

func boolDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func parseClientSuggestionLimit(r *http.Request) (int, bool) {
	limit := defaultClientSuggestionLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return 0, false
		}
		limit = parsed
	}
	if limit > maxClientSuggestionLimit {
		limit = maxClientSuggestionLimit
	}
	return limit, true
}

func filterClientSuggestionResponses(suggestions []audit.ClientSuggestion) []filterClientSuggestionResponse {
	if len(suggestions) == 0 {
		return []filterClientSuggestionResponse{}
	}
	responses := make([]filterClientSuggestionResponse, 0, len(suggestions))
	for _, suggestion := range suggestions {
		responses = append(responses, filterClientSuggestionResponse{
			Address:  suggestion.Address,
			ClientIP: suggestion.Address,
			LastSeen: suggestion.LastSeen,
			Count:    suggestion.Count,
		})
	}
	return responses
}

func parseOptionalFilterTime(w http.ResponseWriter, value *string) (*time.Time, bool) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil, true
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*value))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter_time")
		return nil, false
	}
	return &parsed, true
}

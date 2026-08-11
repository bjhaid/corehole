package filter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bjhaid/corehole/internal/blocklist"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateList(ctx context.Context, list List) (List, error) {
	if err := validateList(&list); err != nil {
		return List{}, err
	}
	result, err := r.db.ExecContext(ctx, `
INSERT INTO filter_lists (url, path, kind, enabled, last_updated_at, last_error)
VALUES (?, ?, ?, ?, ?, ?)`,
		list.URL, list.Path, list.Kind, boolInt(list.Enabled), formatNullableTime(list.LastUpdatedAt), list.LastError)
	if err != nil {
		return List{}, fmt.Errorf("create filter list: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return List{}, fmt.Errorf("read created filter list id: %w", err)
	}
	return r.GetList(ctx, id)
}

func (r *Repository) ListLists(ctx context.Context) ([]List, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, url, path, kind, enabled, last_updated_at, last_error
FROM filter_lists
ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list filter lists: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var lists []List
	for rows.Next() {
		list, err := scanList(rows)
		if err != nil {
			return nil, err
		}
		lists = append(lists, list)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filter lists: %w", err)
	}
	return lists, nil
}

func (r *Repository) GetList(ctx context.Context, id int64) (List, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT id, url, path, kind, enabled, last_updated_at, last_error
FROM filter_lists
WHERE id = ?`, id)
	list, err := scanList(row)
	if errors.Is(err, sql.ErrNoRows) {
		return List{}, ErrNotFound
	}
	if err != nil {
		return List{}, err
	}
	return list, nil
}

func (r *Repository) UpdateList(ctx context.Context, list List) (List, error) {
	if list.ID <= 0 {
		return List{}, fmt.Errorf("%w: list id is required", ErrInvalidInput)
	}
	if err := validateList(&list); err != nil {
		return List{}, err
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE filter_lists
SET url = ?, path = ?, kind = ?, enabled = ?, last_updated_at = ?, last_error = ?
WHERE id = ?`,
		list.URL, list.Path, list.Kind, boolInt(list.Enabled), formatNullableTime(list.LastUpdatedAt), list.LastError, list.ID)
	if err != nil {
		return List{}, fmt.Errorf("update filter list: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return List{}, err
	}
	return r.GetList(ctx, list.ID)
}

func (r *Repository) DeleteList(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM filter_lists WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete filter list: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) CreateListEntry(ctx context.Context, entry ListEntry) (ListEntry, error) {
	if err := validateListEntry(&entry); err != nil {
		return ListEntry{}, err
	}
	result, err := r.db.ExecContext(ctx, `
INSERT INTO filter_list_entries (list_id, pattern, match_type, enabled)
VALUES (?, ?, ?, ?)`,
		entry.ListID, entry.Pattern, entry.MatchType, boolInt(entry.Enabled))
	if err != nil {
		return ListEntry{}, fmt.Errorf("create filter list entry: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return ListEntry{}, fmt.Errorf("read created filter list entry id: %w", err)
	}
	return r.GetListEntry(ctx, id)
}

func (r *Repository) ListListEntries(ctx context.Context, listID int64) ([]ListEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, list_id, pattern, match_type, enabled
FROM filter_list_entries
WHERE list_id = ?
ORDER BY id`, listID)
	if err != nil {
		return nil, fmt.Errorf("list filter list entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []ListEntry
	for rows.Next() {
		entry, err := scanListEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filter list entries: %w", err)
	}
	return entries, nil
}

func (r *Repository) GetListEntry(ctx context.Context, id int64) (ListEntry, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT id, list_id, pattern, match_type, enabled
FROM filter_list_entries
WHERE id = ?`, id)
	entry, err := scanListEntry(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ListEntry{}, ErrNotFound
	}
	if err != nil {
		return ListEntry{}, err
	}
	return entry, nil
}

func (r *Repository) UpdateListEntry(ctx context.Context, entry ListEntry) (ListEntry, error) {
	if entry.ID <= 0 {
		return ListEntry{}, fmt.Errorf("%w: list entry id is required", ErrInvalidInput)
	}
	if err := validateListEntry(&entry); err != nil {
		return ListEntry{}, err
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE filter_list_entries
SET list_id = ?, pattern = ?, match_type = ?, enabled = ?
WHERE id = ?`,
		entry.ListID, entry.Pattern, entry.MatchType, boolInt(entry.Enabled), entry.ID)
	if err != nil {
		return ListEntry{}, fmt.Errorf("update filter list entry: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return ListEntry{}, err
	}
	return r.GetListEntry(ctx, entry.ID)
}

func (r *Repository) DeleteListEntry(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM filter_list_entries WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete filter list entry: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) ReplaceListEntries(ctx context.Context, listID int64, entries []ListEntry, updatedAt time.Time) (List, error) {
	if listID <= 0 {
		return List{}, fmt.Errorf("%w: list id is required", ErrInvalidInput)
	}
	for i := range entries {
		entries[i].ListID = listID
		if err := validateListEntry(&entries[i]); err != nil {
			return List{}, err
		}
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return List{}, fmt.Errorf("begin filter list refresh: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "DELETE FROM filter_list_entries WHERE list_id = ?", listID); err != nil {
		return List{}, fmt.Errorf("clear filter list entries: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT OR IGNORE INTO filter_list_entries (list_id, pattern, match_type, enabled)
VALUES (?, ?, ?, ?)`)
	if err != nil {
		return List{}, fmt.Errorf("prepare filter list entry replace: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return List{}, err
		}
		if _, err := stmt.ExecContext(ctx, entry.ListID, entry.Pattern, entry.MatchType, boolInt(entry.Enabled)); err != nil {
			return List{}, fmt.Errorf("replace filter list entry: %w", err)
		}
	}
	result, err := tx.ExecContext(ctx, `
UPDATE filter_lists
SET last_updated_at = ?, last_error = ''
WHERE id = ?`, formatNullableTime(&updatedAt), listID)
	if err != nil {
		return List{}, fmt.Errorf("mark filter list refreshed: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return List{}, err
	}
	if err := tx.Commit(); err != nil {
		return List{}, fmt.Errorf("commit filter list refresh: %w", err)
	}
	return r.GetList(ctx, listID)
}

func (r *Repository) MarkListRefreshError(ctx context.Context, listID int64, refreshErr error) (List, error) {
	if listID <= 0 {
		return List{}, fmt.Errorf("%w: list id is required", ErrInvalidInput)
	}
	message := ""
	if refreshErr != nil {
		message = refreshErr.Error()
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE filter_lists
SET last_error = ?
WHERE id = ?`, message, listID)
	if err != nil {
		return List{}, fmt.Errorf("mark filter list refresh error: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return List{}, err
	}
	return r.GetList(ctx, listID)
}

func (r *Repository) BlocklistEntries(ctx context.Context) ([]blocklist.Entry, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT e.pattern, e.match_type, l.kind, l.id
FROM filter_list_entries e
JOIN filter_lists l ON l.id = e.list_id
WHERE e.enabled = 1 AND l.enabled = 1
ORDER BY l.id, e.id`)
	if err != nil {
		return nil, fmt.Errorf("list runtime filter blocklist entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []blocklist.Entry
	for rows.Next() {
		var pattern string
		var matchType MatchType
		var kind Kind
		var listID int64
		if err := rows.Scan(&pattern, &matchType, &kind, &listID); err != nil {
			return nil, fmt.Errorf("scan runtime filter blocklist entry: %w", err)
		}
		entryKind, ok := blocklistEntryKind(matchType)
		if !ok {
			continue
		}
		entries = append(entries, blocklist.Entry{
			Domain: pattern,
			Kind:   entryKind,
			Allow:  kind == KindAllow,
			Source: fmt.Sprintf("filter_list:%d", listID),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runtime filter blocklist entries: %w", err)
	}
	return entries, nil
}

func (r *Repository) BlocklistRuntimeStats(ctx context.Context) (BlocklistRuntimeStats, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT
	COUNT(DISTINCT l.id),
	COUNT(DISTINCT CASE WHEN e.id IS NOT NULL THEN l.id END),
	COUNT(e.id)
FROM filter_lists l
LEFT JOIN filter_list_entries e ON e.list_id = l.id AND e.enabled = 1
WHERE l.enabled = 1`)
	var stats BlocklistRuntimeStats
	if err := row.Scan(&stats.EnabledLists, &stats.ImportedEnabledLists, &stats.EnabledEntries); err != nil {
		return BlocklistRuntimeStats{}, fmt.Errorf("count runtime filter blocklist stats: %w", err)
	}
	return stats, nil
}

func (r *Repository) CreateRule(ctx context.Context, rule Rule) (Rule, error) {
	if err := validateRule(&rule); err != nil {
		return Rule{}, err
	}
	result, err := r.db.ExecContext(ctx, `
INSERT INTO filter_rules (pattern, kind, match_type, enabled, comment)
VALUES (?, ?, ?, ?, ?)`,
		rule.Pattern, rule.Kind, rule.MatchType, boolInt(rule.Enabled), rule.Comment)
	if err != nil {
		return Rule{}, fmt.Errorf("create filter rule: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Rule{}, fmt.Errorf("read created filter rule id: %w", err)
	}
	return r.GetRule(ctx, id)
}

func (r *Repository) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, pattern, kind, match_type, enabled, comment
FROM filter_rules
ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list filter rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []Rule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filter rules: %w", err)
	}
	return rules, nil
}

func (r *Repository) GetRule(ctx context.Context, id int64) (Rule, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT id, pattern, kind, match_type, enabled, comment
FROM filter_rules
WHERE id = ?`, id)
	rule, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, err
	}
	return rule, nil
}

func (r *Repository) UpdateRule(ctx context.Context, rule Rule) (Rule, error) {
	if rule.ID <= 0 {
		return Rule{}, fmt.Errorf("%w: rule id is required", ErrInvalidInput)
	}
	if err := validateRule(&rule); err != nil {
		return Rule{}, err
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE filter_rules
SET pattern = ?, kind = ?, match_type = ?, enabled = ?, comment = ?
WHERE id = ?`,
		rule.Pattern, rule.Kind, rule.MatchType, boolInt(rule.Enabled), rule.Comment, rule.ID)
	if err != nil {
		return Rule{}, fmt.Errorf("update filter rule: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return Rule{}, err
	}
	return r.GetRule(ctx, rule.ID)
}

func (r *Repository) DeleteRule(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM filter_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete filter rule: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) CreateClient(ctx context.Context, client Client) (Client, error) {
	if err := validateClient(&client); err != nil {
		return Client{}, err
	}
	result, err := r.db.ExecContext(ctx, `
INSERT INTO filter_clients (name, address, comment, enabled)
VALUES (?, ?, ?, ?)`,
		client.Name, client.Address, client.Comment, boolInt(client.Enabled))
	if err != nil {
		return Client{}, fmt.Errorf("create filter client: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Client{}, fmt.Errorf("read created filter client id: %w", err)
	}
	return r.GetClient(ctx, id)
}

func (r *Repository) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, name, address, comment, enabled
FROM filter_clients
ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list filter clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var clients []Client
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filter clients: %w", err)
	}
	return clients, nil
}

func (r *Repository) GetClient(ctx context.Context, id int64) (Client, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT id, name, address, comment, enabled
FROM filter_clients
WHERE id = ?`, id)
	client, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, err
	}
	return client, nil
}

func (r *Repository) UpdateClient(ctx context.Context, client Client) (Client, error) {
	if client.ID <= 0 {
		return Client{}, fmt.Errorf("%w: client id is required", ErrInvalidInput)
	}
	if err := validateClient(&client); err != nil {
		return Client{}, err
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE filter_clients
SET name = ?, address = ?, comment = ?, enabled = ?
WHERE id = ?`,
		client.Name, client.Address, client.Comment, boolInt(client.Enabled), client.ID)
	if err != nil {
		return Client{}, fmt.Errorf("update filter client: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return Client{}, err
	}
	return r.GetClient(ctx, client.ID)
}

func (r *Repository) DeleteClient(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM filter_clients WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete filter client: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) CreateGroup(ctx context.Context, group Group) (Group, error) {
	if err := validateGroup(&group); err != nil {
		return Group{}, err
	}
	result, err := r.db.ExecContext(ctx, `
INSERT INTO filter_groups (name, comment, enabled)
VALUES (?, ?, ?)`,
		group.Name, group.Comment, boolInt(group.Enabled))
	if err != nil {
		return Group{}, fmt.Errorf("create filter group: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Group{}, fmt.Errorf("read created filter group id: %w", err)
	}
	return r.GetGroup(ctx, id)
}

func (r *Repository) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, name, comment, enabled
FROM filter_groups
ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list filter groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groups []Group
	for rows.Next() {
		group, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filter groups: %w", err)
	}
	return groups, nil
}

func (r *Repository) GetGroup(ctx context.Context, id int64) (Group, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT id, name, comment, enabled
FROM filter_groups
WHERE id = ?`, id)
	group, err := scanGroup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	if err != nil {
		return Group{}, err
	}
	return group, nil
}

func (r *Repository) UpdateGroup(ctx context.Context, group Group) (Group, error) {
	if group.ID <= 0 {
		return Group{}, fmt.Errorf("%w: group id is required", ErrInvalidInput)
	}
	if err := validateGroup(&group); err != nil {
		return Group{}, err
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE filter_groups
SET name = ?, comment = ?, enabled = ?
WHERE id = ?`,
		group.Name, group.Comment, boolInt(group.Enabled), group.ID)
	if err != nil {
		return Group{}, fmt.Errorf("update filter group: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return Group{}, err
	}
	return r.GetGroup(ctx, group.ID)
}

func (r *Repository) DeleteGroup(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM filter_groups WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete filter group: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) AddClientGroup(ctx context.Context, clientID int64, groupID int64) error {
	return r.addMapping(ctx, "filter_client_groups", "client_id", clientID, "group_id", groupID)
}

func (r *Repository) RemoveClientGroup(ctx context.Context, clientID int64, groupID int64) error {
	return r.removeMapping(ctx, "filter_client_groups", "client_id", clientID, "group_id", groupID)
}

func (r *Repository) ListClientGroups(ctx context.Context, clientID int64) ([]Group, error) {
	return r.groupsForOwner(ctx, "filter_client_groups", "client_id", clientID)
}

func (r *Repository) AddListGroup(ctx context.Context, listID int64, groupID int64) error {
	return r.addMapping(ctx, "filter_list_groups", "list_id", listID, "group_id", groupID)
}

func (r *Repository) RemoveListGroup(ctx context.Context, listID int64, groupID int64) error {
	return r.removeMapping(ctx, "filter_list_groups", "list_id", listID, "group_id", groupID)
}

func (r *Repository) ListListGroups(ctx context.Context, listID int64) ([]Group, error) {
	return r.groupsForOwner(ctx, "filter_list_groups", "list_id", listID)
}

func (r *Repository) AddRuleGroup(ctx context.Context, ruleID int64, groupID int64) error {
	return r.addMapping(ctx, "filter_rule_groups", "rule_id", ruleID, "group_id", groupID)
}

func (r *Repository) RemoveRuleGroup(ctx context.Context, ruleID int64, groupID int64) error {
	return r.removeMapping(ctx, "filter_rule_groups", "rule_id", ruleID, "group_id", groupID)
}

func (r *Repository) ListRuleGroups(ctx context.Context, ruleID int64) ([]Group, error) {
	return r.groupsForOwner(ctx, "filter_rule_groups", "rule_id", ruleID)
}

func (r *Repository) addMapping(ctx context.Context, table string, ownerColumn string, ownerID int64, groupColumn string, groupID int64) error {
	if ownerID <= 0 || groupID <= 0 {
		return fmt.Errorf("%w: mapping ids are required", ErrInvalidInput)
	}
	_, err := r.db.ExecContext(ctx,
		fmt.Sprintf("INSERT OR IGNORE INTO %s (%s, %s) VALUES (?, ?)", table, ownerColumn, groupColumn),
		ownerID, groupID)
	if err != nil {
		return fmt.Errorf("add filter group mapping: %w", err)
	}
	return nil
}

func (r *Repository) removeMapping(ctx context.Context, table string, ownerColumn string, ownerID int64, groupColumn string, groupID int64) error {
	if ownerID <= 0 || groupID <= 0 {
		return fmt.Errorf("%w: mapping ids are required", ErrInvalidInput)
	}
	result, err := r.db.ExecContext(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE %s = ? AND %s = ?", table, ownerColumn, groupColumn),
		ownerID, groupID)
	if err != nil {
		return fmt.Errorf("remove filter group mapping: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) groupsForOwner(ctx context.Context, table string, ownerColumn string, ownerID int64) ([]Group, error) {
	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
SELECT g.id, g.name, g.comment, g.enabled
FROM filter_groups g
JOIN %s m ON m.group_id = g.id
WHERE m.%s = ?
ORDER BY g.id`, table, ownerColumn), ownerID)
	if err != nil {
		return nil, fmt.Errorf("list filter group mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groups []Group
	for rows.Next() {
		group, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filter group mappings: %w", err)
	}
	return groups, nil
}

func (r *Repository) clientGroupIDs(ctx context.Context, address string) (map[int64]struct{}, error) {
	groups := make(map[int64]struct{})
	rows, err := r.db.QueryContext(ctx, `
SELECT cg.group_id
FROM filter_clients c
JOIN filter_client_groups cg ON cg.client_id = c.id
JOIN filter_groups g ON g.id = cg.group_id
WHERE c.address = ? AND c.enabled = 1 AND g.enabled = 1`, address)
	if err != nil {
		return nil, fmt.Errorf("list client filter groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan client filter group: %w", err)
		}
		groups[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client filter groups: %w", err)
	}
	return groups, nil
}

func (r *Repository) decisionRules(ctx context.Context) ([]scopedRule, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT r.id, r.pattern, r.kind, r.match_type, r.enabled, r.comment, rg.group_id
FROM filter_rules r
LEFT JOIN filter_rule_groups rg ON rg.rule_id = r.id
ORDER BY r.id, rg.group_id`)
	if err != nil {
		return nil, fmt.Errorf("list decision filter rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []scopedRule
	for rows.Next() {
		var rule scopedRule
		var enabled int
		var groupID sql.NullInt64
		if err := rows.Scan(&rule.ID, &rule.Pattern, &rule.Kind, &rule.MatchType, &enabled, &rule.Comment, &groupID); err != nil {
			return nil, fmt.Errorf("scan decision filter rule: %w", err)
		}
		rule.Enabled = enabled == 1
		if groupID.Valid {
			rule.GroupID = groupID.Int64
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate decision filter rules: %w", err)
	}
	return rules, nil
}

func (r *Repository) decisionEntries(ctx context.Context) ([]scopedListEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT e.id, e.list_id, e.pattern, e.match_type, e.enabled, l.kind, l.enabled, lg.group_id
FROM filter_list_entries e
JOIN filter_lists l ON l.id = e.list_id
LEFT JOIN filter_list_groups lg ON lg.list_id = l.id
ORDER BY l.id, e.id, lg.group_id`)
	if err != nil {
		return nil, fmt.Errorf("list decision filter list entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []scopedListEntry
	for rows.Next() {
		var entry scopedListEntry
		var entryEnabled int
		var listEnabled int
		var groupID sql.NullInt64
		if err := rows.Scan(&entry.ID, &entry.ListID, &entry.Pattern, &entry.MatchType, &entryEnabled, &entry.Kind, &listEnabled, &groupID); err != nil {
			return nil, fmt.Errorf("scan decision filter list entry: %w", err)
		}
		entry.Enabled = entryEnabled == 1 && listEnabled == 1
		if groupID.Valid {
			entry.GroupID = groupID.Int64
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate decision filter list entries: %w", err)
	}
	return entries, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanList(row rowScanner) (List, error) {
	var list List
	var enabled int
	var lastUpdated string
	if err := row.Scan(&list.ID, &list.URL, &list.Path, &list.Kind, &enabled, &lastUpdated, &list.LastError); err != nil {
		return List{}, err
	}
	list.Enabled = enabled == 1
	if lastUpdated != "" {
		parsed, err := time.Parse(time.RFC3339Nano, lastUpdated)
		if err != nil {
			return List{}, fmt.Errorf("parse filter list last_updated_at: %w", err)
		}
		list.LastUpdatedAt = &parsed
	}
	return list, nil
}

func scanListEntry(row rowScanner) (ListEntry, error) {
	var entry ListEntry
	var enabled int
	if err := row.Scan(&entry.ID, &entry.ListID, &entry.Pattern, &entry.MatchType, &enabled); err != nil {
		return ListEntry{}, err
	}
	entry.Enabled = enabled == 1
	return entry, nil
}

func scanRule(row rowScanner) (Rule, error) {
	var rule Rule
	var enabled int
	if err := row.Scan(&rule.ID, &rule.Pattern, &rule.Kind, &rule.MatchType, &enabled, &rule.Comment); err != nil {
		return Rule{}, err
	}
	rule.Enabled = enabled == 1
	return rule, nil
}

func scanClient(row rowScanner) (Client, error) {
	var client Client
	var enabled int
	if err := row.Scan(&client.ID, &client.Name, &client.Address, &client.Comment, &enabled); err != nil {
		return Client{}, err
	}
	client.Enabled = enabled == 1
	return client, nil
}

func scanGroup(row rowScanner) (Group, error) {
	var group Group
	var enabled int
	if err := row.Scan(&group.ID, &group.Name, &group.Comment, &enabled); err != nil {
		return Group{}, err
	}
	group.Enabled = enabled == 1
	return group, nil
}

func requireAffected(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check affected filter rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func formatNullableTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func blocklistEntryKind(matchType MatchType) (blocklist.EntryKind, bool) {
	switch matchType {
	case MatchExact:
		return blocklist.EntryExact, true
	case MatchSuffix:
		return blocklist.EntrySuffix, true
	default:
		return "", false
	}
}

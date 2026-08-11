package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	PrivacyLevelFull PrivacyLevel = iota
	PrivacyLevelHideClient
	PrivacyLevelHideClientAndDomain

	defaultSummaryTopLimit       = 10
	defaultSummaryBucketCount    = 24
	defaultSummaryBucketInterval = time.Hour
)

type PrivacyLevel int

type Settings struct {
	RetentionDuration time.Duration
	PrivacyLevel      PrivacyLevel
}

type SummaryOptions struct {
	Since          time.Time
	TopLimit       int
	BucketCount    int
	BucketInterval time.Duration
	Now            time.Time
}

type Summary struct {
	TotalQueryCount   int64
	TotalsByAction    []ActionTotal
	TotalsByCache     []NamedTotal
	TopQueriedDomains []NamedTotal
	TopBlockedDomains []NamedTotal
	TopClients        []NamedTotal
	TopBlockedClients []NamedTotal
	RecentTimeBuckets []TimeBucket
	ClientTimeBuckets []ClientTimeBucket
}

type Totals struct {
	TotalQueries   int64
	BlockedQueries int64
	AllowedQueries int64
}

type Stats struct {
	Totals
	DroppedEvents uint64
}

type ActionTotal struct {
	Action string
	Count  int
}

type NamedTotal struct {
	Name  string
	Count int
}

type ClientSuggestion struct {
	Address  string
	LastSeen time.Time
	Count    int
}

type TimeBucket struct {
	Start   time.Time
	End     time.Time
	Total   int
	Allowed int
	Blocked int
}

type ClientTimeBucket struct {
	Start   time.Time
	End     time.Time
	Total   int
	Clients []NamedTotal
}

func DefaultSettings() Settings {
	return Settings{}
}

func (s *SQLiteSink) Settings(ctx context.Context) (Settings, error) {
	return SettingsFromDB(ctx, s.db)
}

func (s *SQLiteSink) SetSettings(ctx context.Context, settings Settings) error {
	return SetSettings(ctx, s.db, settings)
}

func (s *SQLiteSink) CleanupExpired(ctx context.Context, now time.Time) (int64, error) {
	return CleanupExpired(ctx, s.db, now)
}

func (s *SQLiteSink) Summary(ctx context.Context, opts SummaryOptions) (Summary, error) {
	return QuerySummary(ctx, s.db, opts)
}

func (s *SQLiteSink) Totals(ctx context.Context) (Totals, error) {
	return QueryTotals(ctx, s.db)
}

func (s *SQLiteSink) Stats(ctx context.Context) (Stats, error) {
	totals, err := s.Totals(ctx)
	if err != nil {
		return Stats{}, err
	}
	return Stats{
		Totals:        totals,
		DroppedEvents: s.Dropped(),
	}, nil
}

func (s *SQLiteSink) RecentClients(ctx context.Context, limit int) ([]ClientSuggestion, error) {
	return RecentClients(ctx, s.db, limit)
}

func SettingsFromDB(ctx context.Context, db *sql.DB) (Settings, error) {
	if db == nil {
		return Settings{}, errors.New("audit settings requires a database")
	}

	var (
		retentionNS int64
		level       int
	)
	err := db.QueryRowContext(ctx, `
SELECT retention_duration_ns, privacy_level
FROM audit_settings
WHERE id = 1`).Scan(&retentionNS, &level)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("query audit settings: %w", err)
	}

	settings := Settings{
		RetentionDuration: time.Duration(retentionNS),
		PrivacyLevel:      PrivacyLevel(level),
	}
	if err := validateSettings(settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func SetSettings(ctx context.Context, db *sql.DB, settings Settings) error {
	if db == nil {
		return errors.New("audit settings requires a database")
	}
	if err := validateSettings(settings); err != nil {
		return err
	}

	_, err := db.ExecContext(ctx, `
INSERT INTO audit_settings (id, retention_duration_ns, privacy_level, updated_at)
VALUES (1, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	retention_duration_ns = excluded.retention_duration_ns,
	privacy_level = excluded.privacy_level,
	updated_at = excluded.updated_at`,
		settings.RetentionDuration.Nanoseconds(),
		int(settings.PrivacyLevel),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save audit settings: %w", err)
	}
	return nil
}

func CleanupExpired(ctx context.Context, db *sql.DB, now time.Time) (int64, error) {
	settings, err := SettingsFromDB(ctx, db)
	if err != nil {
		return 0, err
	}
	return CleanupOlderThan(ctx, db, settings.RetentionDuration, now)
}

func CleanupOlderThan(ctx context.Context, db *sql.DB, maxAge time.Duration, now time.Time) (int64, error) {
	if db == nil {
		return 0, errors.New("audit cleanup requires a database")
	}
	if maxAge <= 0 {
		return 0, nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	cutoff := now.UTC().Add(-maxAge).Format(time.RFC3339Nano)
	result, err := db.ExecContext(ctx, "DELETE FROM audit_events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleanup audit events: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count cleaned audit events: %w", err)
	}
	return deleted, nil
}

func QueryTotals(ctx context.Context, db *sql.DB) (Totals, error) {
	if db == nil {
		return Totals{}, errors.New("audit totals requires a database")
	}

	rows, err := db.QueryContext(ctx, `
SELECT action, count
FROM audit_action_totals`)
	if err != nil {
		return Totals{}, fmt.Errorf("query audit totals: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var totals Totals
	for rows.Next() {
		var action string
		var count int64
		if err := rows.Scan(&action, &count); err != nil {
			return Totals{}, fmt.Errorf("scan audit total: %w", err)
		}
		totals.TotalQueries += count
		switch action {
		case "block":
			totals.BlockedQueries += count
		case "allow":
			totals.AllowedQueries += count
		}
	}
	if err := rows.Err(); err != nil {
		return Totals{}, fmt.Errorf("read audit totals: %w", err)
	}
	return totals, nil
}

func RebuildTotals(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("audit totals rebuild requires a database")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit totals rebuild: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, "DELETE FROM audit_action_totals"); err != nil {
		return fmt.Errorf("clear audit totals: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_action_totals (action, count, updated_at)
SELECT action, COUNT(*), ?
FROM audit_events
GROUP BY action`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("rebuild audit totals: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit totals rebuild: %w", err)
	}
	return nil
}

func QuerySummary(ctx context.Context, db *sql.DB, opts SummaryOptions) (Summary, error) {
	if db == nil {
		return Summary{}, errors.New("audit summary requires a database")
	}
	opts = normalizeSummaryOptions(opts)

	allTimeTotals, err := QueryTotals(ctx, db)
	if err != nil {
		return Summary{}, err
	}
	totals, err := actionTotals(ctx, db, opts.Since)
	if err != nil {
		return Summary{}, err
	}
	cacheTotals, err := cacheStatusTotals(ctx, db, opts.Since)
	if err != nil {
		return Summary{}, err
	}
	topQueries, err := namedTotals(ctx, db, `
SELECT query_name, COUNT(*)
FROM audit_events
WHERE timestamp >= ?
GROUP BY query_name
ORDER BY COUNT(*) DESC, query_name ASC
LIMIT ?`, opts.Since, opts.TopLimit)
	if err != nil {
		return Summary{}, err
	}
	topBlocked, err := namedTotals(ctx, db, `
SELECT query_name, COUNT(*)
FROM audit_events
WHERE timestamp >= ? AND action = 'block'
GROUP BY query_name
ORDER BY COUNT(*) DESC, query_name ASC
LIMIT ?`, opts.Since, opts.TopLimit)
	if err != nil {
		return Summary{}, err
	}
	topClients, err := namedTotals(ctx, db, `
SELECT client_ip, COUNT(*)
FROM audit_events
WHERE timestamp >= ? AND client_ip <> ''
GROUP BY client_ip
ORDER BY COUNT(*) DESC, client_ip ASC
LIMIT ?`, opts.Since, opts.TopLimit)
	if err != nil {
		return Summary{}, err
	}
	topBlockedClients, err := namedTotals(ctx, db, `
SELECT client_ip, COUNT(*)
FROM audit_events
WHERE timestamp >= ? AND action = 'block' AND client_ip <> ''
GROUP BY client_ip
ORDER BY COUNT(*) DESC, client_ip ASC
LIMIT ?`, opts.Since, opts.TopLimit)
	if err != nil {
		return Summary{}, err
	}
	buckets, err := timeBuckets(ctx, db, opts)
	if err != nil {
		return Summary{}, err
	}
	clientBuckets, err := clientTimeBuckets(ctx, db, opts, topClients)
	if err != nil {
		return Summary{}, err
	}

	return Summary{
		TotalQueryCount:   allTimeTotals.TotalQueries,
		TotalsByAction:    totals,
		TotalsByCache:     cacheTotals,
		TopQueriedDomains: topQueries,
		TopBlockedDomains: topBlocked,
		TopClients:        topClients,
		TopBlockedClients: topBlockedClients,
		RecentTimeBuckets: buckets,
		ClientTimeBuckets: clientBuckets,
	}, nil
}

func RecentClients(ctx context.Context, db *sql.DB, limit int) ([]ClientSuggestion, error) {
	if db == nil {
		return nil, errors.New("audit recent clients requires a database")
	}
	if limit <= 0 {
		return []ClientSuggestion{}, nil
	}
	scanLimit := limit * 10
	if scanLimit < 100 {
		scanLimit = 100
	}
	if scanLimit > 1000 {
		scanLimit = 1000
	}

	rows, err := db.QueryContext(ctx, `
SELECT client_ip, COUNT(*), MAX(timestamp) AS last_seen
FROM audit_events
WHERE client_ip <> ''
GROUP BY client_ip
ORDER BY last_seen DESC, client_ip ASC
LIMIT ?`, scanLimit)
	if err != nil {
		return nil, fmt.Errorf("query recent audit clients: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	suggestions := make([]ClientSuggestion, 0, limit)
	for rows.Next() {
		var (
			address string
			count   int
			lastRaw string
		)
		if err := rows.Scan(&address, &count, &lastRaw); err != nil {
			return nil, fmt.Errorf("scan recent audit client: %w", err)
		}
		parsedAddr, err := netip.ParseAddr(address)
		if err != nil || !parsedAddr.IsValid() {
			continue
		}
		lastSeen, err := time.Parse(time.RFC3339Nano, lastRaw)
		if err != nil {
			return nil, fmt.Errorf("parse recent audit client timestamp: %w", err)
		}
		suggestions = append(suggestions, ClientSuggestion{
			Address:  parsedAddr.String(),
			LastSeen: lastSeen,
			Count:    count,
		})
		if len(suggestions) >= limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read recent audit clients: %w", err)
	}
	return suggestions, nil
}

func ProjectEvents(events []Event, level PrivacyLevel) []Event {
	if len(events) == 0 {
		return []Event{}
	}
	projected := make([]Event, len(events))
	copy(projected, events)
	for i := range projected {
		if level >= PrivacyLevelHideClient {
			projected[i].ClientIP = netip.Addr{}
		}
		if level >= PrivacyLevelHideClientAndDomain {
			projected[i].QueryName = ""
		}
	}
	return projected
}

func ProjectSummary(summary Summary, level PrivacyLevel) Summary {
	projected := Summary{
		TotalQueryCount:   summary.TotalQueryCount,
		TotalsByAction:    cloneActionTotals(summary.TotalsByAction),
		TotalsByCache:     cloneNamedTotals(summary.TotalsByCache),
		TopQueriedDomains: cloneNamedTotals(summary.TopQueriedDomains),
		TopBlockedDomains: cloneNamedTotals(summary.TopBlockedDomains),
		TopClients:        cloneNamedTotals(summary.TopClients),
		TopBlockedClients: cloneNamedTotals(summary.TopBlockedClients),
		RecentTimeBuckets: cloneTimeBuckets(summary.RecentTimeBuckets),
		ClientTimeBuckets: cloneClientTimeBuckets(summary.ClientTimeBuckets),
	}
	if level >= PrivacyLevelHideClient {
		projected.TopClients = collapseNamedTotals(projected.TopClients)
		projected.TopBlockedClients = collapseNamedTotals(projected.TopBlockedClients)
		for i := range projected.ClientTimeBuckets {
			projected.ClientTimeBuckets[i].Clients = collapseNamedTotals(projected.ClientTimeBuckets[i].Clients)
		}
	}
	if level >= PrivacyLevelHideClientAndDomain {
		projected.TopQueriedDomains = collapseNamedTotals(projected.TopQueriedDomains)
		projected.TopBlockedDomains = collapseNamedTotals(projected.TopBlockedDomains)
	}
	return projected
}

func normalizeSummaryOptions(opts SummaryOptions) SummaryOptions {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	} else {
		opts.Now = opts.Now.UTC()
	}
	if opts.TopLimit <= 0 {
		opts.TopLimit = defaultSummaryTopLimit
	}
	if opts.TopLimit > 100 {
		opts.TopLimit = 100
	}
	if opts.BucketCount <= 0 {
		opts.BucketCount = defaultSummaryBucketCount
	}
	if opts.BucketCount > 168 {
		opts.BucketCount = 168
	}
	if opts.BucketInterval <= 0 {
		opts.BucketInterval = defaultSummaryBucketInterval
	}
	if opts.Since.IsZero() {
		opts.Since = opts.Now.Add(-time.Duration(opts.BucketCount) * opts.BucketInterval)
	}
	opts.Since = opts.Since.UTC()
	return opts
}

func actionTotals(ctx context.Context, db *sql.DB, since time.Time) ([]ActionTotal, error) {
	rows, err := db.QueryContext(ctx, `
SELECT action, COUNT(*)
FROM audit_events
WHERE timestamp >= ?
GROUP BY action
ORDER BY COUNT(*) DESC, action ASC`, since.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("query action totals: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var totals []ActionTotal
	for rows.Next() {
		var total ActionTotal
		if err := rows.Scan(&total.Action, &total.Count); err != nil {
			return nil, fmt.Errorf("scan action total: %w", err)
		}
		totals = append(totals, total)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read action totals: %w", err)
	}
	return totals, nil
}

func cacheStatusTotals(ctx context.Context, db *sql.DB, since time.Time) ([]NamedTotal, error) {
	rows, err := db.QueryContext(ctx, `
SELECT cache_status, COUNT(*)
FROM audit_events
WHERE timestamp >= ? AND cache_status <> ''
GROUP BY cache_status
ORDER BY COUNT(*) DESC, cache_status ASC`, since.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("query cache status totals: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var totals []NamedTotal
	for rows.Next() {
		var total NamedTotal
		if err := rows.Scan(&total.Name, &total.Count); err != nil {
			return nil, fmt.Errorf("scan cache status total: %w", err)
		}
		totals = append(totals, total)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read cache status totals: %w", err)
	}
	return totals, nil
}

func namedTotals(ctx context.Context, db *sql.DB, query string, since time.Time, limit int) ([]NamedTotal, error) {
	rows, err := db.QueryContext(ctx, query, since.Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, fmt.Errorf("query named totals: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var totals []NamedTotal
	for rows.Next() {
		var total NamedTotal
		if err := rows.Scan(&total.Name, &total.Count); err != nil {
			return nil, fmt.Errorf("scan named total: %w", err)
		}
		totals = append(totals, total)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read named totals: %w", err)
	}
	return totals, nil
}

func timeBuckets(ctx context.Context, db *sql.DB, opts SummaryOptions) ([]TimeBucket, error) {
	end := opts.Now.Truncate(opts.BucketInterval).Add(opts.BucketInterval)
	start := end.Add(-time.Duration(opts.BucketCount) * opts.BucketInterval)
	buckets := make([]TimeBucket, opts.BucketCount)
	for i := range buckets {
		bucketStart := start.Add(time.Duration(i) * opts.BucketInterval)
		buckets[i] = TimeBucket{
			Start: bucketStart,
			End:   bucketStart.Add(opts.BucketInterval),
		}
	}

	rows, err := db.QueryContext(ctx, `
SELECT timestamp, action
FROM audit_events
WHERE timestamp >= ? AND timestamp < ?`, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("query time buckets: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		var timestamp string
		var action string
		if err := rows.Scan(&timestamp, &action); err != nil {
			return nil, fmt.Errorf("scan time bucket event: %w", err)
		}
		eventTime, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse time bucket timestamp: %w", err)
		}
		index := int(eventTime.UTC().Sub(start) / opts.BucketInterval)
		if index < 0 || index >= len(buckets) {
			continue
		}
		buckets[index].Total++
		switch action {
		case "allow":
			buckets[index].Allowed++
		case "block":
			buckets[index].Blocked++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read time bucket events: %w", err)
	}
	return buckets, nil
}

func clientTimeBuckets(ctx context.Context, db *sql.DB, opts SummaryOptions, topClients []NamedTotal) ([]ClientTimeBucket, error) {
	end := opts.Now.Truncate(opts.BucketInterval).Add(opts.BucketInterval)
	start := end.Add(-time.Duration(opts.BucketCount) * opts.BucketInterval)
	buckets := make([]ClientTimeBucket, opts.BucketCount)
	for i := range buckets {
		bucketStart := start.Add(time.Duration(i) * opts.BucketInterval)
		buckets[i] = ClientTimeBucket{
			Start: bucketStart,
			End:   bucketStart.Add(opts.BucketInterval),
		}
	}
	if len(topClients) == 0 {
		return buckets, nil
	}

	clientIndexes := make(map[string]int, len(topClients))
	for i, client := range topClients {
		if client.Name != "" {
			clientIndexes[client.Name] = i
		}
	}
	if len(clientIndexes) == 0 {
		return buckets, nil
	}

	counts := make([][]int, len(buckets))
	for i := range counts {
		counts[i] = make([]int, len(topClients))
	}

	rows, err := db.QueryContext(ctx, `
SELECT timestamp, client_ip
FROM audit_events
WHERE timestamp >= ? AND timestamp < ? AND client_ip <> ''`, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("query client time buckets: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		var timestamp string
		var clientIP string
		if err := rows.Scan(&timestamp, &clientIP); err != nil {
			return nil, fmt.Errorf("scan client time bucket event: %w", err)
		}
		eventTime, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse client time bucket timestamp: %w", err)
		}
		bucketIndex := int(eventTime.UTC().Sub(start) / opts.BucketInterval)
		if bucketIndex < 0 || bucketIndex >= len(buckets) {
			continue
		}
		buckets[bucketIndex].Total++
		clientIndex, ok := clientIndexes[clientIP]
		if !ok {
			continue
		}
		counts[bucketIndex][clientIndex]++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read client time bucket events: %w", err)
	}

	for bucketIndex := range buckets {
		clients := make([]NamedTotal, 0, len(topClients))
		for clientIndex, count := range counts[bucketIndex] {
			if count == 0 {
				continue
			}
			clients = append(clients, NamedTotal{
				Name:  topClients[clientIndex].Name,
				Count: count,
			})
		}
		buckets[bucketIndex].Clients = clients
	}
	return buckets, nil
}

func validateSettings(settings Settings) error {
	if settings.RetentionDuration < 0 {
		return errors.New("audit retention duration cannot be negative")
	}
	if settings.PrivacyLevel < PrivacyLevelFull || settings.PrivacyLevel > PrivacyLevelHideClientAndDomain {
		return errors.New("invalid audit privacy level")
	}
	return nil
}

func cloneActionTotals(totals []ActionTotal) []ActionTotal {
	if len(totals) == 0 {
		return []ActionTotal{}
	}
	cloned := make([]ActionTotal, len(totals))
	copy(cloned, totals)
	return cloned
}

func cloneNamedTotals(totals []NamedTotal) []NamedTotal {
	if len(totals) == 0 {
		return []NamedTotal{}
	}
	cloned := make([]NamedTotal, len(totals))
	copy(cloned, totals)
	return cloned
}

func cloneTimeBuckets(buckets []TimeBucket) []TimeBucket {
	if len(buckets) == 0 {
		return []TimeBucket{}
	}
	cloned := make([]TimeBucket, len(buckets))
	copy(cloned, buckets)
	return cloned
}

func cloneClientTimeBuckets(buckets []ClientTimeBucket) []ClientTimeBucket {
	if len(buckets) == 0 {
		return []ClientTimeBucket{}
	}
	cloned := make([]ClientTimeBucket, len(buckets))
	for i, bucket := range buckets {
		cloned[i] = ClientTimeBucket{
			Start:   bucket.Start,
			End:     bucket.End,
			Total:   bucket.Total,
			Clients: cloneNamedTotals(bucket.Clients),
		}
	}
	return cloned
}

func collapseNamedTotals(totals []NamedTotal) []NamedTotal {
	if len(totals) == 0 {
		return []NamedTotal{}
	}
	var count int
	for _, total := range totals {
		count += total.Count
	}
	return []NamedTotal{{Count: count}}
}

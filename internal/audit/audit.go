package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coredns "github.com/bjhaid/corehole/internal/dns"
)

type Event struct {
	Timestamp       time.Time
	ClientIP        netip.Addr
	QueryName       string
	QueryType       uint16
	Action          coredns.Action
	Reason          string
	RuleID          int64
	BlocklistID     int64
	Response        string
	Duration        time.Duration
	Upstream        string
	CacheStatus     string
	ForwardDuration time.Duration
	RetryCount      int
	ForwardError    string
}

type QuerySortField string

const (
	QuerySortTimestamp   QuerySortField = "timestamp"
	QuerySortClientIP    QuerySortField = "client_ip"
	QuerySortQueryName   QuerySortField = "query_name"
	QuerySortQueryType   QuerySortField = "query_type"
	QuerySortAction      QuerySortField = "action"
	QuerySortResponse    QuerySortField = "response"
	QuerySortRuleID      QuerySortField = "rule_id"
	QuerySortBlocklistID QuerySortField = "blocklist_id"
	QuerySortDurationNS  QuerySortField = "duration_ns"
	QuerySortDurationMS  QuerySortField = "duration_ms"
	QuerySortUpstream    QuerySortField = "upstream_resolver"
	QuerySortCacheStatus QuerySortField = "cache_status"
	QuerySortForwardNS   QuerySortField = "forward_duration_ns"
	QuerySortForwardMS   QuerySortField = "forward_duration_ms"
	QuerySortRetryCount  QuerySortField = "retry_count"
	QuerySortForwardErr  QuerySortField = "forward_error"
)

type QuerySortOrder string

const (
	QuerySortASC  QuerySortOrder = "asc"
	QuerySortDESC QuerySortOrder = "desc"
)

type QueryOptions struct {
	Limit  int
	Offset int
	Sort   QuerySortField
	Order  QuerySortOrder

	From time.Time
	To   time.Time

	ClientIP       string
	QueryName      string
	QueryType      uint16
	HasQueryType   bool
	Action         string
	Response       string
	RuleID         int64
	HasRuleID      bool
	BlocklistID    int64
	HasBlocklistID bool
	DurationNS     int64
	HasDurationNS  bool
	DurationMinNS  int64
	HasDurationMin bool
	DurationMaxNS  int64
	HasDurationMax bool
	Upstream       string
	CacheStatus    string
	ForwardMinNS   int64
	HasForwardMin  bool
	ForwardMaxNS   int64
	HasForwardMax  bool
	RetryCount     int
	HasRetryCount  bool
	ForwardError   string
}

type Sink interface {
	Record(ctx context.Context, event Event)
	Close(ctx context.Context) error
}

type NoopSink struct{}

func (NoopSink) Record(context.Context, Event) {}

func (NoopSink) Close(context.Context) error { return nil }

type SQLiteSink struct {
	db            *sql.DB
	events        chan Event
	done          chan struct{}
	stopped       chan struct{}
	batchSize     int
	flushInterval time.Duration
	dropped       atomic.Uint64
	closed        atomic.Bool

	errMu sync.Mutex
	err   error
}

type SQLiteSinkOption func(*SQLiteSink)

func WithQueueSize(size int) SQLiteSinkOption {
	return func(s *SQLiteSink) {
		if size > 0 {
			s.events = make(chan Event, size)
		}
	}
}

func WithBatchSize(size int) SQLiteSinkOption {
	return func(s *SQLiteSink) {
		if size > 0 {
			s.batchSize = size
		}
	}
}

func WithFlushInterval(interval time.Duration) SQLiteSinkOption {
	return func(s *SQLiteSink) {
		if interval > 0 {
			s.flushInterval = interval
		}
	}
}

func NewSQLiteSink(db *sql.DB, opts ...SQLiteSinkOption) (*SQLiteSink, error) {
	if db == nil {
		return nil, errors.New("audit sqlite sink requires a database")
	}

	sink := &SQLiteSink{
		db:            db,
		events:        make(chan Event, 1024),
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
		batchSize:     100,
		flushInterval: time.Second,
	}
	for _, opt := range opts {
		opt(sink)
	}

	go sink.run()
	return sink, nil
}

func (s *SQLiteSink) Record(_ context.Context, event Event) {
	if s.closed.Load() {
		s.dropped.Add(1)
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	select {
	case s.events <- event:
	default:
		s.dropped.Add(1)
	}
}

func (s *SQLiteSink) Dropped() uint64 {
	return s.dropped.Load()
}

func (s *SQLiteSink) Recent(ctx context.Context, limit int) ([]Event, error) {
	return RecentEvents(ctx, s.db, limit)
}

func (s *SQLiteSink) Query(ctx context.Context, opts QueryOptions) ([]Event, error) {
	return QueryEvents(ctx, s.db, opts)
}

func (s *SQLiteSink) Close(ctx context.Context) error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.done)
	}

	select {
	case <-s.stopped:
		return s.lastError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SQLiteSink) run() {
	defer close(s.stopped)

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, s.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := insertBatch(context.Background(), s.db, batch); err != nil {
			s.setError(err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case event := <-s.events:
			batch = append(batch, event)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.done:
			for {
				select {
				case event := <-s.events:
					batch = append(batch, event)
					if len(batch) >= s.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func insertBatch(ctx context.Context, db *sql.DB, events []Event) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit insert: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO audit_events (
	timestamp,
	client_ip,
	query_name,
	query_type,
	action,
	reason,
	rule_id,
	blocklist_id,
	response,
	duration_ns,
	upstream_resolver,
	cache_status,
	forward_duration_ns,
	retry_count,
	forward_error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare audit insert: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	for _, event := range events {
		timestamp := event.Timestamp
		if timestamp.IsZero() {
			timestamp = time.Now()
		}
		if _, err := stmt.ExecContext(
			ctx,
			timestamp.UTC().Format(time.RFC3339Nano),
			addrString(event.ClientIP),
			event.QueryName,
			event.QueryType,
			string(event.Action),
			event.Reason,
			event.RuleID,
			event.BlocklistID,
			event.Response,
			event.Duration.Nanoseconds(),
			event.Upstream,
			event.CacheStatus,
			event.ForwardDuration.Nanoseconds(),
			event.RetryCount,
			event.ForwardError,
		); err != nil {
			return fmt.Errorf("insert audit event: %w", err)
		}
	}

	if err := incrementActionTotals(ctx, tx, events); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit insert: %w", err)
	}
	return nil
}

func incrementActionTotals(ctx context.Context, tx *sql.Tx, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	counts := make(map[string]int64)
	for _, event := range events {
		counts[string(event.Action)]++
	}

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO audit_action_totals (action, count, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(action) DO UPDATE SET
	count = audit_action_totals.count + excluded.count,
	updated_at = excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("prepare audit action total update: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for action, count := range counts {
		if _, err := stmt.ExecContext(ctx, action, count, now); err != nil {
			return fmt.Errorf("update audit action total: %w", err)
		}
	}
	return nil
}

func RecentEvents(ctx context.Context, db *sql.DB, limit int) ([]Event, error) {
	return QueryEvents(ctx, db, QueryOptions{Limit: limit})
}

func QueryEvents(ctx context.Context, db *sql.DB, opts QueryOptions) ([]Event, error) {
	if db == nil {
		return nil, errors.New("audit query events requires a database")
	}
	if opts.Limit <= 0 {
		return []Event{}, nil
	}
	if opts.Offset < 0 {
		return nil, errors.New("audit query events offset must be non-negative")
	}

	sortColumn, err := querySortColumn(opts.Sort)
	if err != nil {
		return nil, err
	}
	sortOrder, err := querySortOrder(opts.Order)
	if err != nil {
		return nil, err
	}

	var (
		where []string
		args  []any
	)
	if !opts.From.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, opts.From.UTC().Format(time.RFC3339Nano))
	}
	if !opts.To.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, opts.To.UTC().Format(time.RFC3339Nano))
	}
	if opts.ClientIP != "" {
		where = append(where, "client_ip = ?")
		args = append(args, opts.ClientIP)
	}
	if opts.QueryName != "" {
		where = append(where, "query_name = ?")
		args = append(args, opts.QueryName)
	}
	if opts.HasQueryType {
		where = append(where, "query_type = ?")
		args = append(args, opts.QueryType)
	}
	if opts.Action != "" {
		where = append(where, "action = ?")
		args = append(args, opts.Action)
	}
	if opts.Response != "" {
		where = append(where, "response = ?")
		args = append(args, opts.Response)
	}
	if opts.HasRuleID {
		where = append(where, "rule_id = ?")
		args = append(args, opts.RuleID)
	}
	if opts.HasBlocklistID {
		where = append(where, "blocklist_id = ?")
		args = append(args, opts.BlocklistID)
	}
	if opts.HasDurationNS {
		where = append(where, "duration_ns = ?")
		args = append(args, opts.DurationNS)
	}
	if opts.HasDurationMin {
		where = append(where, "duration_ns >= ?")
		args = append(args, opts.DurationMinNS)
	}
	if opts.HasDurationMax {
		where = append(where, "duration_ns <= ?")
		args = append(args, opts.DurationMaxNS)
	}
	if opts.Upstream != "" {
		where = append(where, "upstream_resolver = ?")
		args = append(args, opts.Upstream)
	}
	if opts.CacheStatus != "" {
		where = append(where, "cache_status = ?")
		args = append(args, opts.CacheStatus)
	}
	if opts.HasForwardMin {
		where = append(where, "forward_duration_ns >= ?")
		args = append(args, opts.ForwardMinNS)
	}
	if opts.HasForwardMax {
		where = append(where, "forward_duration_ns <= ?")
		args = append(args, opts.ForwardMaxNS)
	}
	if opts.HasRetryCount {
		where = append(where, "retry_count = ?")
		args = append(args, opts.RetryCount)
	}
	if opts.ForwardError != "" {
		where = append(where, "forward_error = ?")
		args = append(args, opts.ForwardError)
	}

	var query strings.Builder
	query.WriteString(`
SELECT
	timestamp,
	client_ip,
	query_name,
	query_type,
	action,
	reason,
	rule_id,
	blocklist_id,
	response,
	duration_ns,
	upstream_resolver,
	cache_status,
	forward_duration_ns,
	retry_count,
	forward_error
FROM audit_events`)
	if len(where) > 0 {
		query.WriteString("\nWHERE ")
		query.WriteString(strings.Join(where, " AND "))
	}
	query.WriteString("\nORDER BY ")
	query.WriteString(sortColumn)
	query.WriteByte(' ')
	query.WriteString(sortOrder)
	query.WriteString(", id ")
	query.WriteString(sortOrder)
	query.WriteString("\nLIMIT ?")
	args = append(args, opts.Limit)
	if opts.Offset > 0 {
		query.WriteString("\nOFFSET ?")
		args = append(args, opts.Offset)
	}

	rows, err := db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	return scanEventRows(rows)
}

func querySortColumn(sort QuerySortField) (string, error) {
	if sort == "" {
		sort = QuerySortTimestamp
	}
	columns := map[QuerySortField]string{
		QuerySortTimestamp:   "timestamp",
		QuerySortClientIP:    "client_ip",
		QuerySortQueryName:   "query_name",
		QuerySortQueryType:   "query_type",
		QuerySortAction:      "action",
		QuerySortResponse:    "response",
		QuerySortRuleID:      "rule_id",
		QuerySortBlocklistID: "blocklist_id",
		QuerySortDurationNS:  "duration_ns",
		QuerySortDurationMS:  "duration_ns",
		QuerySortUpstream:    "upstream_resolver",
		QuerySortCacheStatus: "cache_status",
		QuerySortForwardNS:   "forward_duration_ns",
		QuerySortForwardMS:   "forward_duration_ns",
		QuerySortRetryCount:  "retry_count",
		QuerySortForwardErr:  "forward_error",
	}
	column, ok := columns[sort]
	if !ok {
		return "", fmt.Errorf("unsupported audit query sort field %q", sort)
	}
	return column, nil
}

func querySortOrder(order QuerySortOrder) (string, error) {
	if order == "" {
		order = QuerySortDESC
	}
	switch order {
	case QuerySortASC:
		return "ASC", nil
	case QuerySortDESC:
		return "DESC", nil
	default:
		return "", fmt.Errorf("unsupported audit query sort order %q", order)
	}
}

func scanEventRows(rows *sql.Rows) ([]Event, error) {
	var events []Event
	for rows.Next() {
		var (
			event             Event
			timestamp         string
			clientIP          string
			action            string
			durationNS        int64
			forwardDurationNS int64
		)
		if err := rows.Scan(
			&timestamp,
			&clientIP,
			&event.QueryName,
			&event.QueryType,
			&action,
			&event.Reason,
			&event.RuleID,
			&event.BlocklistID,
			&event.Response,
			&durationNS,
			&event.Upstream,
			&event.CacheStatus,
			&forwardDurationNS,
			&event.RetryCount,
			&event.ForwardError,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}

		parsedTimestamp, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse audit timestamp: %w", err)
		}
		event.Timestamp = parsedTimestamp
		if clientIP != "" {
			parsedClientIP, err := netip.ParseAddr(clientIP)
			if err != nil {
				return nil, fmt.Errorf("parse audit client ip: %w", err)
			}
			event.ClientIP = parsedClientIP
		}
		event.Action = coredns.Action(action)
		event.Duration = time.Duration(durationNS)
		event.ForwardDuration = time.Duration(forwardDurationNS)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit events: %w", err)
	}

	return events, nil
}

func (s *SQLiteSink) setError(err error) {
	s.errMu.Lock()
	defer s.errMu.Unlock()

	if s.err == nil {
		s.err = err
	}
}

func (s *SQLiteSink) lastError() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()

	return s.err
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

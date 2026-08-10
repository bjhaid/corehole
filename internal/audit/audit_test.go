package audit

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	coredns "github.com/bjhaid/corehole/internal/dns"
	"github.com/bjhaid/corehole/internal/storage"
)

func TestSQLiteSinkFlushesFullBatchAndReturnsRecentEvents(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	sink, err := NewSQLiteSink(
		store.DB(),
		WithBatchSize(2),
		WithFlushInterval(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewSQLiteSink() error = %v", err)
	}
	defer closeSink(t, ctx, sink)

	first := testEvent(time.Date(2026, 8, 9, 17, 0, 0, 0, time.UTC), "alpha.example.")
	second := testEvent(first.Timestamp.Add(time.Second), "beta.example.")
	sink.Record(ctx, first)
	sink.Record(ctx, second)

	events := waitForRecentEvents(t, ctx, sink, 2)
	if got, want := len(events), 2; got != want {
		t.Fatalf("recent events len = %d, want %d", got, want)
	}
	if events[0].QueryName != second.QueryName || events[1].QueryName != first.QueryName {
		t.Fatalf("recent events order = [%q, %q], want [%q, %q]",
			events[0].QueryName,
			events[1].QueryName,
			second.QueryName,
			first.QueryName,
		)
	}
	if events[0].ClientIP != second.ClientIP {
		t.Fatalf("client ip = %s, want %s", events[0].ClientIP, second.ClientIP)
	}
	if events[0].Duration != second.Duration {
		t.Fatalf("duration = %s, want %s", events[0].Duration, second.Duration)
	}
}

func TestSQLiteSinkRecordDropsInsteadOfBlockingWhenQueueIsFull(t *testing.T) {
	sink := &SQLiteSink{
		events: make(chan Event, 1),
	}
	sink.events <- testEvent(time.Now(), "queued.example.")

	done := make(chan struct{})
	go func() {
		sink.Record(context.Background(), testEvent(time.Now(), "dropped.example."))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Record blocked on a full queue")
	}
	if dropped := sink.Dropped(); dropped != 1 {
		t.Fatalf("dropped events = %d, want 1", dropped)
	}
}

func TestSQLiteSinkCloseFlushesPartialBatch(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	sink, err := NewSQLiteSink(
		store.DB(),
		WithBatchSize(10),
		WithFlushInterval(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewSQLiteSink() error = %v", err)
	}

	event := testEvent(time.Date(2026, 8, 9, 17, 30, 0, 0, time.UTC), "close.example.")
	sink.Record(ctx, event)
	closeSink(t, ctx, sink)

	events, err := RecentEvents(ctx, store.DB(), 10)
	if err != nil {
		t.Fatalf("RecentEvents() error = %v", err)
	}
	if got, want := len(events), 1; got != want {
		t.Fatalf("recent events len = %d, want %d", got, want)
	}
	if events[0].QueryName != event.QueryName {
		t.Fatalf("query name = %q, want %q", events[0].QueryName, event.QueryName)
	}
}

func TestQueryEventsFiltersSupportedFields(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	match := testEvent(base, "match.example.")
	match.ClientIP = netip.MustParseAddr("192.0.2.10")
	match.QueryType = 28
	match.Action = coredns.ActionBlock
	match.Response = "NXDOMAIN"
	match.RuleID = 42
	match.BlocklistID = 7
	match.Duration = 25 * time.Millisecond
	match.Upstream = "1.1.1.1:53"
	match.CacheStatus = "miss"
	match.ForwardDuration = 24 * time.Millisecond
	match.RetryCount = -1
	match.ForwardError = "upstream timeout"

	other := testEvent(base.Add(time.Minute), "other.example.")
	other.ClientIP = netip.MustParseAddr("192.0.2.11")
	other.QueryType = 1
	other.Action = coredns.ActionAllow
	other.Response = "NOERROR"
	other.RuleID = 0
	other.BlocklistID = 0
	other.Duration = 5 * time.Millisecond
	other.Upstream = "8.8.8.8:53"
	other.CacheStatus = "hit"
	other.ForwardDuration = time.Millisecond
	other.RetryCount = 0

	if err := insertBatch(ctx, store.DB(), []Event{match, other}); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}

	tests := []struct {
		name string
		opts QueryOptions
	}{
		{name: "from", opts: QueryOptions{From: base.Add(-time.Second), To: base.Add(time.Second)}},
		{name: "client ip", opts: QueryOptions{ClientIP: "192.0.2.10"}},
		{name: "query name", opts: QueryOptions{QueryName: "match.example."}},
		{name: "query type", opts: QueryOptions{QueryType: 28, HasQueryType: true}},
		{name: "action", opts: QueryOptions{Action: "block"}},
		{name: "response", opts: QueryOptions{Response: "NXDOMAIN"}},
		{name: "rule id", opts: QueryOptions{RuleID: 42, HasRuleID: true}},
		{name: "blocklist id", opts: QueryOptions{BlocklistID: 7, HasBlocklistID: true}},
		{name: "duration exact", opts: QueryOptions{DurationNS: int64(25 * time.Millisecond), HasDurationNS: true}},
		{name: "duration range", opts: QueryOptions{DurationMinNS: int64(20 * time.Millisecond), HasDurationMin: true, DurationMaxNS: int64(30 * time.Millisecond), HasDurationMax: true}},
		{name: "upstream", opts: QueryOptions{Upstream: "1.1.1.1:53"}},
		{name: "cache status", opts: QueryOptions{CacheStatus: "miss"}},
		{name: "forward duration range", opts: QueryOptions{ForwardMinNS: int64(20 * time.Millisecond), HasForwardMin: true, ForwardMaxNS: int64(30 * time.Millisecond), HasForwardMax: true}},
		{name: "retry count", opts: QueryOptions{RetryCount: -1, HasRetryCount: true}},
		{name: "forward error", opts: QueryOptions{ForwardError: "upstream timeout"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.Limit = 10
			events, err := QueryEvents(ctx, store.DB(), tt.opts)
			if err != nil {
				t.Fatalf("QueryEvents() error = %v", err)
			}
			if len(events) != 1 || events[0].QueryName != match.QueryName {
				t.Fatalf("events = %#v, want match only", events)
			}
		})
	}
}

func TestQueryEventsAppliesFiltersBeforeLimit(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	events := []Event{
		testEvent(base.Add(3*time.Minute), "recent-one.example."),
		testEvent(base.Add(2*time.Minute), "recent-two.example."),
		testEvent(base.Add(time.Minute), "recent-three.example."),
		testEvent(base, "blocked.example."),
	}
	for i := range events[:3] {
		events[i].Action = coredns.ActionAllow
	}
	events[3].Action = coredns.ActionBlock
	if err := insertBatch(ctx, store.DB(), events); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}

	filtered, err := QueryEvents(ctx, store.DB(), QueryOptions{Limit: 1, Action: "block"})
	if err != nil {
		t.Fatalf("QueryEvents() error = %v", err)
	}
	if len(filtered) != 1 || filtered[0].QueryName != "blocked.example." {
		t.Fatalf("filtered events = %#v, want older blocked event", filtered)
	}
}

func TestInsertBatchUpdatesActionTotals(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	allowed := testEvent(base, "allowed.example.")
	allowed.Action = coredns.ActionAllow
	blocked := testEvent(base.Add(time.Second), "blocked.example.")
	blocked.Action = coredns.ActionBlock
	blockedAgain := testEvent(base.Add(2*time.Second), "blocked-again.example.")
	blockedAgain.Action = coredns.ActionBlock

	if err := insertBatch(ctx, store.DB(), []Event{allowed, blocked}); err != nil {
		t.Fatalf("insertBatch() first error = %v", err)
	}
	if err := insertBatch(ctx, store.DB(), []Event{blockedAgain}); err != nil {
		t.Fatalf("insertBatch() second error = %v", err)
	}

	totals, err := QueryTotals(ctx, store.DB())
	if err != nil {
		t.Fatalf("QueryTotals() error = %v", err)
	}
	if totals.TotalQueries != 3 || totals.AllowedQueries != 1 || totals.BlockedQueries != 2 {
		t.Fatalf("totals = %#v, want total 3 allowed 1 blocked 2", totals)
	}
}

func TestInsertBatchRollsBackEventsWhenActionTotalUpdateFails(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	if _, err := store.DB().ExecContext(ctx, "DROP TABLE audit_action_totals"); err != nil {
		t.Fatalf("drop audit_action_totals: %v", err)
	}

	err := insertBatch(ctx, store.DB(), []Event{
		testEvent(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC), "rollback.example."),
	})
	if err == nil {
		t.Fatal("insertBatch() error = nil, want counter update error")
	}

	var rows int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events").Scan(&rows); err != nil {
		t.Fatalf("query audit_events count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("audit_events rows = %d, want 0 after rollback", rows)
	}
}

func TestRebuildTotalsUsesAuditEvents(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	allowed := testEvent(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC), "allowed.example.")
	allowed.Action = coredns.ActionAllow
	blocked := testEvent(allowed.Timestamp.Add(time.Second), "blocked.example.")
	blocked.Action = coredns.ActionBlock
	if err := insertBatch(ctx, store.DB(), []Event{allowed, blocked}); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, "UPDATE audit_action_totals SET count = 99"); err != nil {
		t.Fatalf("drift audit_action_totals: %v", err)
	}

	if err := RebuildTotals(ctx, store.DB()); err != nil {
		t.Fatalf("RebuildTotals() error = %v", err)
	}

	totals, err := QueryTotals(ctx, store.DB())
	if err != nil {
		t.Fatalf("QueryTotals() error = %v", err)
	}
	if totals.TotalQueries != 2 || totals.AllowedQueries != 1 || totals.BlockedQueries != 1 {
		t.Fatalf("rebuilt totals = %#v, want total 2 allowed 1 blocked 1", totals)
	}
}

func TestRecentClientsReturnsUniqueValidClientsByLastSeen(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	first := testEvent(base, "first.example.")
	first.ClientIP = netip.MustParseAddr("192.0.2.10")
	second := testEvent(base.Add(time.Minute), "second.example.")
	second.ClientIP = netip.MustParseAddr("192.0.2.11")
	third := testEvent(base.Add(2*time.Minute), "third.example.")
	third.ClientIP = netip.MustParseAddr("192.0.2.10")
	blank := testEvent(base.Add(3*time.Minute), "blank.example.")
	blank.ClientIP = netip.Addr{}
	if err := insertBatch(ctx, store.DB(), []Event{first, second, third, blank}); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `
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
	duration_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		base.Add(4*time.Minute).Format(time.RFC3339Nano),
		"not-an-ip",
		"invalid.example.",
		1,
		"allow",
		"",
		0,
		0,
		"NOERROR",
		int64(time.Millisecond),
	); err != nil {
		t.Fatalf("insert invalid audit event: %v", err)
	}

	suggestions, err := RecentClients(ctx, store.DB(), 10)
	if err != nil {
		t.Fatalf("RecentClients() error = %v", err)
	}
	if got, want := len(suggestions), 2; got != want {
		t.Fatalf("suggestions len = %d, want %d: %#v", got, want, suggestions)
	}
	if suggestions[0].Address != "192.0.2.10" || !suggestions[0].LastSeen.Equal(third.Timestamp) || suggestions[0].Count != 2 {
		t.Fatalf("first suggestion = %#v, want 192.0.2.10 count 2", suggestions[0])
	}
	if suggestions[1].Address != "192.0.2.11" || !suggestions[1].LastSeen.Equal(second.Timestamp) || suggestions[1].Count != 1 {
		t.Fatalf("second suggestion = %#v, want 192.0.2.11 count 1", suggestions[1])
	}
}

func TestQueryEventsSortsAscendingAndDescending(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	fast := testEvent(now, "fast.example.")
	fast.Duration = 5 * time.Millisecond
	fast.ForwardDuration = 30 * time.Millisecond
	slow := testEvent(now.Add(time.Second), "slow.example.")
	slow.Duration = 25 * time.Millisecond
	slow.ForwardDuration = 10 * time.Millisecond
	if err := insertBatch(ctx, store.DB(), []Event{fast, slow}); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}

	ascending, err := QueryEvents(ctx, store.DB(), QueryOptions{Limit: 10, Sort: QuerySortDurationMS, Order: QuerySortASC})
	if err != nil {
		t.Fatalf("QueryEvents() ascending error = %v", err)
	}
	if len(ascending) != 2 || ascending[0].QueryName != "fast.example." || ascending[1].QueryName != "slow.example." {
		t.Fatalf("ascending events = %#v, want fast then slow", ascending)
	}

	descending, err := QueryEvents(ctx, store.DB(), QueryOptions{Limit: 10, Sort: QuerySortDurationNS, Order: QuerySortDESC})
	if err != nil {
		t.Fatalf("QueryEvents() descending error = %v", err)
	}
	if len(descending) != 2 || descending[0].QueryName != "slow.example." || descending[1].QueryName != "fast.example." {
		t.Fatalf("descending events = %#v, want slow then fast", descending)
	}

	forwardAscending, err := QueryEvents(ctx, store.DB(), QueryOptions{Limit: 10, Sort: QuerySortForwardMS, Order: QuerySortASC})
	if err != nil {
		t.Fatalf("QueryEvents() forward ascending error = %v", err)
	}
	if len(forwardAscending) != 2 || forwardAscending[0].QueryName != "slow.example." || forwardAscending[1].QueryName != "fast.example." {
		t.Fatalf("forward ascending events = %#v, want slow then fast by forward duration", forwardAscending)
	}
}

func TestQueryEventsOffsetPaginatesSortedEvents(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	var events []Event
	for i, name := range []string{"first.example.", "second.example.", "third.example."} {
		events = append(events, testEvent(base.Add(time.Duration(i)*time.Minute), name))
	}
	if err := insertBatch(ctx, store.DB(), events); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}

	page, err := QueryEvents(ctx, store.DB(), QueryOptions{Limit: 1, Offset: 1, Sort: QuerySortTimestamp, Order: QuerySortDESC})
	if err != nil {
		t.Fatalf("QueryEvents() error = %v", err)
	}
	if len(page) != 1 || page[0].QueryName != "second.example." {
		t.Fatalf("page events = %#v, want second event", page)
	}
}

func TestQueryEventsRejectsUnsupportedSort(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	if _, err := QueryEvents(ctx, store.DB(), QueryOptions{Limit: 10, Sort: QuerySortField("reason")}); err == nil {
		t.Fatal("QueryEvents() error = nil, want unsupported sort error")
	}
}

func TestSQLiteSinkRecordDropsWhenQueueFull(t *testing.T) {
	sink := &SQLiteSink{
		events: make(chan Event, 1),
	}

	sink.Record(context.Background(), Event{})
	sink.Record(context.Background(), Event{})

	if got, want := sink.Dropped(), uint64(1); got != want {
		t.Fatalf("Dropped() = %d, want %d", got, want)
	}
}

func TestCleanupExpiredUsesConfiguredRetention(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	oldEvent := testEvent(now.Add(-48*time.Hour), "old.example.")
	newEvent := testEvent(now.Add(-2*time.Hour), "new.example.")
	if err := insertBatch(ctx, store.DB(), []Event{oldEvent, newEvent}); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}

	deleted, err := CleanupExpired(ctx, store.DB(), now)
	if err != nil {
		t.Fatalf("CleanupExpired() with disabled retention error = %v", err)
	}
	if deleted != 0 {
		t.Fatalf("disabled cleanup deleted = %d, want 0", deleted)
	}

	if err := SetSettings(ctx, store.DB(), Settings{RetentionDuration: 24 * time.Hour}); err != nil {
		t.Fatalf("SetSettings() error = %v", err)
	}
	deleted, err = CleanupExpired(ctx, store.DB(), now)
	if err != nil {
		t.Fatalf("CleanupExpired() error = %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}

	events, err := RecentEvents(ctx, store.DB(), 10)
	if err != nil {
		t.Fatalf("RecentEvents() error = %v", err)
	}
	if len(events) != 1 || events[0].QueryName != "new.example." {
		t.Fatalf("remaining events = %#v, want new event only", events)
	}

	totals, err := QueryTotals(ctx, store.DB())
	if err != nil {
		t.Fatalf("QueryTotals() error = %v", err)
	}
	if totals.TotalQueries != 2 || totals.BlockedQueries != 2 {
		t.Fatalf("totals after cleanup = %#v, want all-time source total retained", totals)
	}
}

func TestPrivacyProjection(t *testing.T) {
	event := testEvent(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC), "private.example.")
	levelOne := ProjectEvents([]Event{event}, PrivacyLevelHideClient)
	if levelOne[0].ClientIP.IsValid() {
		t.Fatalf("level 1 client IP = %s, want hidden", levelOne[0].ClientIP)
	}
	if levelOne[0].QueryName != event.QueryName {
		t.Fatalf("level 1 query name = %q, want preserved", levelOne[0].QueryName)
	}

	levelTwo := ProjectEvents([]Event{event}, PrivacyLevelHideClientAndDomain)
	if levelTwo[0].ClientIP.IsValid() || levelTwo[0].QueryName != "" {
		t.Fatalf("level 2 event = %#v, want hidden client and query", levelTwo[0])
	}
	if event.ClientIP != netip.MustParseAddr("192.0.2.10") || event.QueryName == "" {
		t.Fatalf("source event was mutated: %#v", event)
	}

	summary := Summary{
		TopQueriedDomains: []NamedTotal{{Name: "one.example.", Count: 2}, {Name: "two.example.", Count: 1}},
		TopBlockedDomains: []NamedTotal{{Name: "ads.example.", Count: 3}},
		TopClients:        []NamedTotal{{Name: "192.0.2.10", Count: 4}},
		TopBlockedClients: []NamedTotal{{Name: "192.0.2.10", Count: 2}, {Name: "192.0.2.20", Count: 1}},
		ClientTimeBuckets: []ClientTimeBucket{{
			Start: time.Date(2026, 8, 10, 11, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
			Total: 2,
			Clients: []NamedTotal{
				{Name: "192.0.2.10", Count: 1},
				{Name: "192.0.2.20", Count: 1},
			},
		}},
	}
	projected := ProjectSummary(summary, PrivacyLevelHideClientAndDomain)
	if len(projected.TopClients) != 1 || projected.TopClients[0].Name != "" || projected.TopClients[0].Count != 4 {
		t.Fatalf("projected clients = %#v, want collapsed hidden client", projected.TopClients)
	}
	if len(projected.TopBlockedClients) != 1 || projected.TopBlockedClients[0].Name != "" || projected.TopBlockedClients[0].Count != 3 {
		t.Fatalf("projected blocked clients = %#v, want collapsed hidden client", projected.TopBlockedClients)
	}
	if len(projected.ClientTimeBuckets) != 1 ||
		len(projected.ClientTimeBuckets[0].Clients) != 1 ||
		projected.ClientTimeBuckets[0].Clients[0].Name != "" ||
		projected.ClientTimeBuckets[0].Clients[0].Count != 2 {
		t.Fatalf("projected client buckets = %#v, want collapsed hidden clients", projected.ClientTimeBuckets)
	}
	if len(projected.TopQueriedDomains) != 1 || projected.TopQueriedDomains[0].Name != "" || projected.TopQueriedDomains[0].Count != 3 {
		t.Fatalf("projected domains = %#v, want collapsed hidden domains", projected.TopQueriedDomains)
	}
	if summary.TopQueriedDomains[0].Name == "" || summary.ClientTimeBuckets[0].Clients[0].Name == "" {
		t.Fatalf("source summary was mutated: %#v", summary)
	}
}

func TestQuerySummaryAggregatesAuditEvents(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer closeStore(t, ctx, store)

	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	events := []Event{
		{
			Timestamp: time.Date(2026, 8, 10, 11, 10, 0, 0, time.UTC),
			ClientIP:  netip.MustParseAddr("192.0.2.10"),
			QueryName: "example.com.",
			QueryType: 1,
			Action:    coredns.ActionAllow,
			Duration:  5 * time.Millisecond,
		},
		{
			Timestamp: time.Date(2026, 8, 10, 11, 20, 0, 0, time.UTC),
			ClientIP:  netip.MustParseAddr("192.0.2.10"),
			QueryName: "ads.example.",
			QueryType: 1,
			Action:    coredns.ActionBlock,
			Reason:    "deny",
		},
		{
			Timestamp: time.Date(2026, 8, 10, 12, 10, 0, 0, time.UTC),
			ClientIP:  netip.MustParseAddr("192.0.2.20"),
			QueryName: "ads.example.",
			QueryType: 1,
			Action:    coredns.ActionBlock,
			Reason:    "deny",
		},
		{
			Timestamp: time.Date(2026, 8, 10, 12, 20, 0, 0, time.UTC),
			ClientIP:  netip.MustParseAddr("192.0.2.20"),
			QueryName: "bad.example.",
			QueryType: 1,
			Action:    coredns.ActionBlock,
			Reason:    "deny",
		},
	}
	if err := insertBatch(ctx, store.DB(), events); err != nil {
		t.Fatalf("insertBatch() error = %v", err)
	}

	summary, err := QuerySummary(ctx, store.DB(), SummaryOptions{
		Since:          now.Add(-2 * time.Hour),
		TopLimit:       2,
		BucketCount:    2,
		BucketInterval: time.Hour,
		Now:            now,
	})
	if err != nil {
		t.Fatalf("QuerySummary() error = %v", err)
	}

	if len(summary.TotalsByAction) != 2 ||
		summary.TotalsByAction[0] != (ActionTotal{Action: "block", Count: 3}) ||
		summary.TotalsByAction[1] != (ActionTotal{Action: "allow", Count: 1}) {
		t.Fatalf("totals by action = %#v", summary.TotalsByAction)
	}
	if summary.TotalQueryCount != 4 {
		t.Fatalf("total query count = %d, want 4", summary.TotalQueryCount)
	}
	if len(summary.TopQueriedDomains) != 2 ||
		summary.TopQueriedDomains[0] != (NamedTotal{Name: "ads.example.", Count: 2}) {
		t.Fatalf("top queried domains = %#v", summary.TopQueriedDomains)
	}
	if len(summary.TopBlockedDomains) != 2 ||
		summary.TopBlockedDomains[0] != (NamedTotal{Name: "ads.example.", Count: 2}) {
		t.Fatalf("top blocked domains = %#v", summary.TopBlockedDomains)
	}
	if len(summary.TopClients) != 2 ||
		summary.TopClients[0] != (NamedTotal{Name: "192.0.2.10", Count: 2}) {
		t.Fatalf("top clients = %#v", summary.TopClients)
	}
	if len(summary.TopBlockedClients) != 2 ||
		summary.TopBlockedClients[0] != (NamedTotal{Name: "192.0.2.20", Count: 2}) ||
		summary.TopBlockedClients[1] != (NamedTotal{Name: "192.0.2.10", Count: 1}) {
		t.Fatalf("top blocked clients = %#v", summary.TopBlockedClients)
	}
	if len(summary.RecentTimeBuckets) != 2 ||
		summary.RecentTimeBuckets[0].Total != 2 ||
		summary.RecentTimeBuckets[0].Allowed != 1 ||
		summary.RecentTimeBuckets[0].Blocked != 1 ||
		summary.RecentTimeBuckets[1].Total != 2 ||
		summary.RecentTimeBuckets[1].Blocked != 2 {
		t.Fatalf("recent time buckets = %#v", summary.RecentTimeBuckets)
	}
	if len(summary.ClientTimeBuckets) != 2 ||
		summary.ClientTimeBuckets[0].Total != 2 ||
		len(summary.ClientTimeBuckets[0].Clients) != 1 ||
		summary.ClientTimeBuckets[0].Clients[0] != (NamedTotal{Name: "192.0.2.10", Count: 2}) ||
		summary.ClientTimeBuckets[1].Total != 2 ||
		len(summary.ClientTimeBuckets[1].Clients) != 1 ||
		summary.ClientTimeBuckets[1].Clients[0] != (NamedTotal{Name: "192.0.2.20", Count: 2}) {
		t.Fatalf("client time buckets = %#v", summary.ClientTimeBuckets)
	}
}

func openTestStore(t *testing.T, ctx context.Context) *storage.SQLiteStore {
	t.Helper()

	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("storage.Open() error = %v", err)
	}
	return store
}

func closeStore(t *testing.T, ctx context.Context, store *storage.SQLiteStore) {
	t.Helper()

	if err := store.Close(ctx); err != nil {
		t.Fatalf("storage.Close() error = %v", err)
	}
}

func closeSink(t *testing.T, ctx context.Context, sink *SQLiteSink) {
	t.Helper()

	if err := sink.Close(ctx); err != nil {
		t.Fatalf("SQLiteSink.Close() error = %v", err)
	}
}

func waitForRecentEvents(t *testing.T, ctx context.Context, sink *SQLiteSink, want int) []Event {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	var events []Event
	for time.Now().Before(deadline) {
		var err error
		events, err = sink.Recent(ctx, want)
		if err != nil {
			t.Fatalf("Recent() error = %v", err)
		}
		if len(events) == want {
			return events
		}
		time.Sleep(10 * time.Millisecond)
	}
	return events
}

func testEvent(timestamp time.Time, queryName string) Event {
	return Event{
		Timestamp:   timestamp,
		ClientIP:    netip.MustParseAddr("192.0.2.10"),
		QueryName:   queryName,
		QueryType:   1,
		Action:      coredns.ActionBlock,
		Reason:      "test-rule",
		RuleID:      42,
		BlocklistID: 7,
		Response:    "0.0.0.0",
		Duration:    15 * time.Millisecond,
	}
}

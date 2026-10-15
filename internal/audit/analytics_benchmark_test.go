package audit

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/storage"
)

// COREHOLE_BENCH_EVENTS optionally supplies a private gzip JSON-lines sample:
// [timestamp, client_ip, query_name, action, cache_status]. No production data
// belongs in the repository. Without a sample, use deterministic synthetic data.
func BenchmarkAnalytics(b *testing.B) {
	ctx := context.Background()
	store, err := storage.OpenAudit(ctx, filepath.Join(b.TempDir(), "audit.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close(ctx) })
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO audit_events(timestamp,client_ip,query_name,query_type,action,cache_status) VALUES (?,?,?,1,?,?)`)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = stmt.Close() }()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	if path := os.Getenv("COREHOLE_BENCH_EVENTS"); path != "" {
		file, err := os.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		defer func() { _ = file.Close() }()
		reader, err := gzip.NewReader(file)
		if err != nil {
			b.Fatal(err)
		}
		defer func() { _ = reader.Close() }()
		decoder := json.NewDecoder(reader)
		now = time.Time{}
		for {
			var row [5]string
			if err := decoder.Decode(&row); err == io.EOF {
				break
			} else if err != nil {
				b.Fatal(err)
			}
			ts, err := time.Parse(time.RFC3339Nano, row[0])
			if err != nil {
				b.Fatal(err)
			}
			if ts.After(now) {
				now = ts
			}
			if _, err := stmt.ExecContext(ctx, row[0], row[1], row[2], row[3], row[4]); err != nil {
				b.Fatal(err)
			}
		}
	} else {
		for i := 0; i < 100000; i++ {
			action := "allow"
			if i%5 == 0 {
				action = "block"
			}
			if _, err := stmt.ExecContext(ctx, now.Add(-time.Duration(i%86400)*time.Second).Format(time.RFC3339Nano),
				fmt.Sprintf("192.0.2.%d", i%100+1), fmt.Sprintf("domain-%d.example.", i%10000), action, []string{"hit", "miss", "bypass"}[i%3]); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	if err := RebuildTotals(ctx, store.DB()); err != nil {
		b.Fatal(err)
	}
	opts := normalizeSummaryOptions(SummaryOptions{Now: now.Add(time.Second)})
	topClients, err := namedTotals(ctx, store.ReadDB(), `SELECT client_ip,COUNT(*) FROM audit_events WHERE timestamp >= ? AND client_ip <> '' GROUP BY client_ip ORDER BY COUNT(*) DESC,client_ip ASC LIMIT ?`, opts.Since, opts.TopLimit)
	if err != nil {
		b.Fatal(err)
	}
	buckets, err := timeBuckets(ctx, store.ReadDB(), opts)
	if err != nil {
		b.Fatal(err)
	}
	sink, err := NewSQLiteSink(store.DB(), WithReaderDB(store.ReadDB()), WithRetentionCleanupInterval(0))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = sink.Close(ctx) })
	if _, err := sink.Summary(ctx, SummaryOptions{}); err != nil {
		b.Fatal(err)
	}
	for _, bench := range []struct {
		name string
		run  func() error
	}{
		{"Summary", func() error { _, err := QuerySummary(ctx, store.ReadDB(), opts); return err }},
		{"CachedSummary", func() error { _, err := sink.Summary(ctx, SummaryOptions{}); return err }},
		{"TimeBuckets", func() error { _, err := timeBuckets(ctx, store.ReadDB(), opts); return err }},
		{"ClientBuckets", func() error { _, err := clientTimeBuckets(ctx, store.ReadDB(), opts, topClients, buckets); return err }},
		{"TopDomains", func() error {
			_, err := namedTotals(ctx, store.ReadDB(), `SELECT query_name,COUNT(*) FROM audit_events WHERE timestamp >= ? GROUP BY query_name ORDER BY COUNT(*) DESC,query_name ASC LIMIT ?`, opts.Since, opts.TopLimit)
			return err
		}},
	} {
		b.Run(bench.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := bench.run(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

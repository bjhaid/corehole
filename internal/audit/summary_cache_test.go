package audit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSummaryCacheCoalescesAndClones(t *testing.T) {
	var cache summaryCache
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	load := func(context.Context) (Summary, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return Summary{TopClients: []NamedTotal{{Name: "192.0.2.1", Count: 1}}, ClientTimeBuckets: []ClientTimeBucket{{Clients: []NamedTotal{{Name: "192.0.2.1", Count: 1}}}}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := cache.get(ctx, load)
			if err != nil {
				t.Error(err)
				return
			}
			value.TopClients[0].Name = "modified"
			value.ClientTimeBuckets[0].Clients[0].Name = "modified"
		}()
	}
	<-started
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("load calls = %d, want 1", calls.Load())
	}
	value, err := cache.get(ctx, load)
	if err != nil {
		t.Fatal(err)
	}
	if value.TopClients[0].Name != "192.0.2.1" || value.ClientTimeBuckets[0].Clients[0].Name != "192.0.2.1" {
		t.Fatal("caller mutated shared cache")
	}
	cache.mu.Lock()
	cache.expires = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	if _, err := cache.get(ctx, load); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("expired summary reused")
	}
}

func TestSummaryCacheInvalidationDuringLoad(t *testing.T) {
	var cache summaryCache
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		_, err := cache.get(context.Background(), func(context.Context) (Summary, error) {
			close(started)
			<-release
			return Summary{TotalQueryCount: 1}, nil
		})
		if err != nil {
			t.Error(err)
		}
	}()
	<-started
	cache.invalidate()
	// A canceled waiter must not wait for, or cancel, the active request.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.get(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter = %v", err)
	}
	close(release)
	<-finished
	value, err := cache.get(context.Background(), func(context.Context) (Summary, error) { return Summary{TotalQueryCount: 2}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if value.TotalQueryCount != 2 {
		t.Fatal("invalidated in-flight result was cached")
	}
}

func TestSummaryCacheDoesNotCacheErrors(t *testing.T) {
	var cache summaryCache
	_, err := cache.get(context.Background(), func(context.Context) (Summary, error) { return Summary{}, errors.New("unavailable") })
	if err == nil {
		t.Fatal("load error lost")
	}
	value, err := cache.get(context.Background(), func(context.Context) (Summary, error) { return Summary{TotalQueryCount: 1}, nil })
	if err != nil || value.TotalQueryCount != 1 {
		t.Fatal("failed load poisoned cache")
	}
}

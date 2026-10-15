package audit

import (
	"context"
	"sync"
	"time"
)

const summaryCacheTTL = 15 * time.Second

// Cache only the default rolling summary used by the console. A single entry
// bounds memory, and one in-flight computation prevents duplicate table scans.
// Custom summary windows bypass the cache.
type summaryCache struct {
	mu         sync.Mutex
	value      Summary
	expires    time.Time
	flight     chan struct{}
	generation uint64
}

func (c *summaryCache) get(ctx context.Context, load func(context.Context) (Summary, error)) (Summary, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Summary{}, err
		}
		c.mu.Lock()
		if time.Now().Before(c.expires) {
			value := c.value
			c.mu.Unlock()
			return ProjectSummary(value, PrivacyLevelFull), nil
		}
		if done := c.flight; done != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return Summary{}, ctx.Err()
			case <-done:
				continue
			}
		}
		done := make(chan struct{})
		c.flight = done
		generation := c.generation
		c.mu.Unlock()
		value, err := load(ctx)
		c.mu.Lock()
		if err == nil && generation == c.generation {
			c.value = ProjectSummary(value, PrivacyLevelFull)
			c.expires = time.Now().Add(summaryCacheTTL)
		}
		c.flight = nil
		close(done)
		c.mu.Unlock()
		return value, err
	}
}

func (c *summaryCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	c.expires = time.Time{}
	c.value = Summary{}
}

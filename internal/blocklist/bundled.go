package blocklist

import (
	"context"
	_ "embed"
	"strings"
	"sync/atomic"
)

const BundledSeedSource = "builtin:seed"

//go:embed seed.txt
var bundledSeed string

var bundledDefault atomic.Bool

func init() {
	bundledDefault.Store(true)
}

func BundledDefaultEnabled() bool {
	return bundledDefault.Load()
}

func SetBundledDefault(enabled bool) {
	bundledDefault.Store(enabled)
}

func BundledEntries() []Entry {
	return append([]Entry(nil), parsedBundledEntries...)
}

func EntriesWithBundled(entries []Entry) []Entry {
	combined := make([]Entry, 0, len(parsedBundledEntries)+len(entries))
	combined = append(combined, parsedBundledEntries...)
	combined = append(combined, entries...)
	return combined
}

func bundledEntryCount(enabled bool) int {
	if !enabled {
		return 0
	}
	return len(parsedBundledEntries)
}

var parsedBundledEntries = mustParseBundledEntries()

func mustParseBundledEntries() []Entry {
	entries, err := NewParser().Parse(context.Background(), strings.NewReader(bundledSeed), BundledSeedSource)
	if err != nil {
		panic(err)
	}
	return entries
}

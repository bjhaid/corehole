package blocklist

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	coredns "github.com/bjhaid/corehole/internal/dns"
)

type ReloadStatus string

const (
	ReloadStatusNeverLoaded ReloadStatus = "never_loaded"
	ReloadStatusOK          ReloadStatus = "ok"
	ReloadStatusError       ReloadStatus = "error"
)

type Snapshot struct {
	Paths      []string
	Bundled    bool
	EntryCount int
	LastReload time.Time
	LastError  string
	Status     ReloadStatus
}

type Manager struct {
	paths   []string
	parser  Parser
	bundled bool
	sources []EntrySource

	current atomic.Value

	reloadMu sync.Mutex
	metaMu   sync.RWMutex
	meta     Snapshot
}

func NewManager(paths []string) *Manager {
	return NewManagerWithParser(paths, nil)
}

func NewManagerWithBundled(paths []string, bundled bool) *Manager {
	return newManager(paths, nil, bundled, nil)
}

func NewManagerWithBundledAndSources(paths []string, bundled bool, sources ...EntrySource) *Manager {
	return newManager(paths, nil, bundled, sources)
}

func NewManagerWithParser(paths []string, parser Parser) *Manager {
	return newManager(paths, parser, BundledDefaultEnabled(), nil)
}

func newManager(paths []string, parser Parser, bundled bool, sources []EntrySource) *Manager {
	if parser == nil {
		parser = NewParser()
	}
	paths = append([]string(nil), paths...)
	sources = append([]EntrySource(nil), sources...)
	m := &Manager{
		paths:   paths,
		parser:  parser,
		bundled: bundled,
		sources: sources,
		meta: Snapshot{
			Paths:   append([]string(nil), paths...),
			Bundled: bundled,
			Status:  ReloadStatusNeverLoaded,
		},
	}
	m.current.Store(matcherHolder{matcher: NewMatcherWithBundled(nil, bundled)})
	return m
}

func (m *Manager) Decide(ctx context.Context, q coredns.Query) coredns.Decision {
	return m.current.Load().(matcherHolder).matcher.Decide(ctx, q)
}

func (m *Manager) Reload(ctx context.Context) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	entries, err := m.loadEntries(ctx)
	if err != nil {
		m.recordReloadError(err, time.Now())
		return err
	}

	m.current.Store(matcherHolder{matcher: NewMatcherWithBundled(entries, m.bundled)})
	m.recordReloadSuccess(len(entries)+bundledEntryCount(m.bundled), time.Now())
	return nil
}

func (m *Manager) Snapshot() Snapshot {
	m.metaMu.RLock()
	defer m.metaMu.RUnlock()

	snapshot := m.meta
	snapshot.Paths = append([]string(nil), m.meta.Paths...)
	return snapshot
}

func (m *Manager) loadEntries(ctx context.Context) ([]Entry, error) {
	var entries []Entry
	for _, path := range m.paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open blocklist %s: %w", path, err)
		}
		parsed, parseErr := m.parser.Parse(ctx, f, path)
		closeErr := f.Close()
		if parseErr != nil {
			return nil, fmt.Errorf("parse blocklist %s: %w", path, parseErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close blocklist %s: %w", path, closeErr)
		}
		entries = append(entries, parsed...)
	}
	for _, source := range m.sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parsed, err := source.Entries(ctx)
		if err != nil {
			return nil, err
		}
		entries = append(entries, parsed...)
	}
	return entries, nil
}

func (m *Manager) recordReloadSuccess(entryCount int, at time.Time) {
	m.metaMu.Lock()
	defer m.metaMu.Unlock()

	m.meta.EntryCount = entryCount
	m.meta.LastReload = at
	m.meta.LastError = ""
	m.meta.Status = ReloadStatusOK
}

func (m *Manager) recordReloadError(err error, at time.Time) {
	m.metaMu.Lock()
	defer m.metaMu.Unlock()

	m.meta.LastReload = at
	m.meta.LastError = err.Error()
	m.meta.Status = ReloadStatusError
}

type matcherHolder struct {
	matcher Matcher
}

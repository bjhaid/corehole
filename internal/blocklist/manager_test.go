package blocklist

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coredns "github.com/bjhaid/corehole/internal/dns"
)

func TestManagerReloadChangesDecisions(t *testing.T) {
	ctx := context.Background()
	path := writeBlocklist(t, "list.txt", "old.example\n")
	manager := NewManager([]string{path})

	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("initial Reload returned error: %v", err)
	}
	assertDecision(t, manager, "old.example", coredns.ActionBlock)
	assertDecision(t, manager, "new.example", coredns.ActionAllow)

	if err := os.WriteFile(path, []byte("new.example\n"), 0o600); err != nil {
		t.Fatalf("rewrite blocklist: %v", err)
	}
	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("second Reload returned error: %v", err)
	}

	assertDecision(t, manager, "old.example", coredns.ActionAllow)
	assertDecision(t, manager, "new.example", coredns.ActionBlock)
}

func TestManagerFailedReloadKeepsPreviousMatcher(t *testing.T) {
	ctx := context.Background()
	path := writeBlocklist(t, "list.txt", "kept.example\n")
	manager := NewManager([]string{path})

	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("initial Reload returned error: %v", err)
	}
	before := manager.Snapshot()
	assertDecision(t, manager, "kept.example", coredns.ActionBlock)

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove blocklist: %v", err)
	}
	if err := manager.Reload(ctx); err == nil {
		t.Fatal("Reload returned nil error after blocklist was removed")
	}

	assertDecision(t, manager, "kept.example", coredns.ActionBlock)
	after := manager.Snapshot()
	if after.Status != ReloadStatusError {
		t.Fatalf("status = %q, want %q", after.Status, ReloadStatusError)
	}
	if after.LastError == "" || !strings.Contains(after.LastError, path) {
		t.Fatalf("last error = %q, want path-specific error", after.LastError)
	}
	if after.EntryCount != before.EntryCount {
		t.Fatalf("entry count = %d, want previous count %d", after.EntryCount, before.EntryCount)
	}
	if !after.LastReload.After(before.LastReload) {
		t.Fatalf("last reload = %v, want after previous reload time %v", after.LastReload, before.LastReload)
	}
}

func TestManagerSnapshotReportsStatus(t *testing.T) {
	ctx := context.Background()
	path := writeBlocklist(t, "list.txt", "one.example\n*.suffix.example\n")
	manager := NewManager([]string{path})

	initial := manager.Snapshot()
	if initial.Status != ReloadStatusNeverLoaded {
		t.Fatalf("initial status = %q, want %q", initial.Status, ReloadStatusNeverLoaded)
	}
	if initial.LastError != "" {
		t.Fatalf("initial last error = %q, want empty", initial.LastError)
	}
	if len(initial.Paths) != 1 || initial.Paths[0] != path {
		t.Fatalf("initial paths = %#v, want [%q]", initial.Paths, path)
	}
	initial.Paths[0] = "mutated"
	if got := manager.Snapshot().Paths[0]; got != path {
		t.Fatalf("snapshot paths are mutable through caller: got %q, want %q", got, path)
	}

	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	snapshot := manager.Snapshot()
	if snapshot.Status != ReloadStatusOK {
		t.Fatalf("status = %q, want %q", snapshot.Status, ReloadStatusOK)
	}
	wantEntryCount := 2 + len(BundledEntries())
	if snapshot.EntryCount != wantEntryCount {
		t.Fatalf("entry count = %d, want %d", snapshot.EntryCount, wantEntryCount)
	}
	if snapshot.LastReload.IsZero() {
		t.Fatal("last reload is zero after successful reload")
	}
	if snapshot.LastError != "" {
		t.Fatalf("last error = %q, want empty", snapshot.LastError)
	}
}

func TestManagerReloadUsesBundledEntriesWithoutPaths(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil)

	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	assertDecision(t, manager, "blocked.example", coredns.ActionBlock)
	snapshot := manager.Snapshot()
	if snapshot.EntryCount != len(BundledEntries()) {
		t.Fatalf("entry count = %d, want bundled count %d", snapshot.EntryCount, len(BundledEntries()))
	}
}

func TestManagerCanDisableBundledEntries(t *testing.T) {
	ctx := context.Background()
	manager := NewManagerWithBundled(nil, false)

	if err := manager.Reload(ctx); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	assertDecision(t, manager, "blocked.example", coredns.ActionAllow)
	snapshot := manager.Snapshot()
	if snapshot.EntryCount != 0 {
		t.Fatalf("entry count = %d, want 0", snapshot.EntryCount)
	}
}

func writeBlocklist(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write blocklist: %v", err)
	}
	return path
}

func assertDecision(t *testing.T, decider coredns.Decider, query string, want coredns.Action) {
	t.Helper()

	got := decider.Decide(context.Background(), coredns.Query{Name: query})
	if got.Action != want {
		t.Fatalf("decision for %q = %q (%s), want %q", query, got.Action, got.Reason, want)
	}
}

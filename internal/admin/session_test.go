package admin

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/storage"
)

func TestLegacySessionsImportDoesNotResurrectDeletedSessions(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	main, err := storage.OpenMain(ctx, filepath.Join(dir, "main.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = main.Close(ctx) }()
	sessions, err := storage.OpenSessions(ctx, filepath.Join(dir, "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sessions.Close(ctx) }()
	now := time.Now().UTC()
	legacy := NewSQLiteSessionStore(main.DB())
	token, err := legacy.Create(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := CopyLegacySessions(ctx, main.ReadDB(), sessions.DB()); err != nil {
		t.Fatal(err)
	}
	current := NewSQLiteSessionStoreWithReader(sessions.DB(), sessions.ReadDB())
	if !current.Valid(token, now) {
		t.Fatal("legacy session not preserved")
	}
	current.Delete(token)
	if err := CopyLegacySessions(ctx, main.ReadDB(), sessions.DB()); err != nil {
		t.Fatal(err)
	}
	if NewSQLiteSessionStoreWithReader(sessions.DB(), sessions.ReadDB()).Valid(token, now) {
		t.Fatal("deleted session resurrected")
	}
}

func TestUnavailableSessionsFailClosed(t *testing.T) {
	s := NewUnavailableSessionStore()
	if _, err := s.Create(time.Now(), time.Hour); err == nil {
		t.Fatal("unavailable store created a session")
	}
	if s.Valid("anything", time.Now()) {
		t.Fatal("unavailable store accepted a session")
	}
}

func TestSQLiteSessionStorePersistsSessions(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("close storage: %v", err)
		}
	}()

	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	first := NewSQLiteSessionStore(store.DB())
	token, err := first.Create(now, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	restarted := NewSQLiteSessionStore(store.DB())
	if !restarted.Valid(token, now.Add(time.Minute)) {
		t.Fatal("persisted session is not valid after recreating session store")
	}
}

func TestSQLiteSessionStoreExpiresAndDeletesSessions(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("close storage: %v", err)
		}
	}()

	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	sessions := NewSQLiteSessionStore(store.DB())
	token, err := sessions.Create(now, time.Minute)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	if sessions.Valid(token, now.Add(2*time.Minute)) {
		t.Fatal("expired session is valid")
	}

	token, err = sessions.Create(now, time.Hour)
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}
	sessions.Delete(token)
	if sessions.Valid(token, now.Add(time.Minute)) {
		t.Fatal("deleted session is valid")
	}
}

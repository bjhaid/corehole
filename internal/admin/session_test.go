package admin

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bjhaid/corehole/internal/storage"
)

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

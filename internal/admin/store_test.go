package admin

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bjhaid/corehole/internal/storage"
)

func TestMemoryUserStoreBehavior(t *testing.T) {
	assertUserStoreBehavior(t, NewMemoryUserStore())
}

func TestSQLiteUserStoreBehavior(t *testing.T) {
	ctx := context.Background()
	store := openTestStorage(t, ctx)
	defer closeTestStorage(t, ctx, store)

	assertUserStoreBehavior(t, NewSQLiteUserStore(store.DB()))
}

func TestSQLiteUserStorePersistsSetup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corehole.db")

	store, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	users := NewSQLiteUserStore(store.DB())
	if err := users.CreateAdmin(ctx, "persisted-hash"); err != nil {
		t.Fatalf("CreateAdmin() error = %v", err)
	}
	closeTestStorage(t, ctx, store)

	store, err = storage.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen Open() error = %v", err)
	}
	defer closeTestStorage(t, ctx, store)

	users = NewSQLiteUserStore(store.DB())
	setup, err := users.IsSetup(ctx)
	if err != nil {
		t.Fatalf("IsSetup() error = %v", err)
	}
	if !setup {
		t.Fatal("IsSetup() = false, want true")
	}

	got, err := users.AdminPasswordHash(ctx)
	if err != nil {
		t.Fatalf("AdminPasswordHash() error = %v", err)
	}
	if got != "persisted-hash" {
		t.Fatalf("AdminPasswordHash() = %q, want persisted-hash", got)
	}
}

func TestSQLiteUserStoreCreateAdminConcurrent(t *testing.T) {
	ctx := context.Background()
	store := openTestStorage(t, ctx)
	defer closeTestStorage(t, ctx, store)

	users := NewSQLiteUserStore(store.DB())
	const attempts = 16
	errs := make(chan error, attempts)

	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- users.CreateAdmin(ctx, fmt.Sprintf("hash-%d", i))
		}(i)
	}
	wg.Wait()
	close(errs)

	var created int
	var alreadySetup int
	for err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrAlreadySetup):
			alreadySetup++
		default:
			t.Fatalf("CreateAdmin() unexpected error = %v", err)
		}
	}
	if created != 1 {
		t.Fatalf("successful CreateAdmin() calls = %d, want 1", created)
	}
	if alreadySetup != attempts-1 {
		t.Fatalf("ErrAlreadySetup calls = %d, want %d", alreadySetup, attempts-1)
	}

	var rowCount int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_users").Scan(&rowCount); err != nil {
		t.Fatalf("query admin_users count: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("admin_users rows = %d, want 1", rowCount)
	}
}

func assertUserStoreBehavior(t *testing.T, users UserStore) {
	t.Helper()
	ctx := context.Background()

	setup, err := users.IsSetup(ctx)
	if err != nil {
		t.Fatalf("initial IsSetup() error = %v", err)
	}
	if setup {
		t.Fatal("initial IsSetup() = true, want false")
	}

	if _, err := users.AdminPasswordHash(ctx); !errors.Is(err, ErrNotSetup) {
		t.Fatalf("initial AdminPasswordHash() error = %v, want ErrNotSetup", err)
	}

	if err := users.CreateAdmin(ctx, "first-hash"); err != nil {
		t.Fatalf("CreateAdmin() error = %v", err)
	}

	setup, err = users.IsSetup(ctx)
	if err != nil {
		t.Fatalf("IsSetup() after CreateAdmin() error = %v", err)
	}
	if !setup {
		t.Fatal("IsSetup() after CreateAdmin() = false, want true")
	}

	got, err := users.AdminPasswordHash(ctx)
	if err != nil {
		t.Fatalf("AdminPasswordHash() error = %v", err)
	}
	if got != "first-hash" {
		t.Fatalf("AdminPasswordHash() = %q, want first-hash", got)
	}

	if err := users.CreateAdmin(ctx, "second-hash"); !errors.Is(err, ErrAlreadySetup) {
		t.Fatalf("second CreateAdmin() error = %v, want ErrAlreadySetup", err)
	}

	got, err = users.AdminPasswordHash(ctx)
	if err != nil {
		t.Fatalf("AdminPasswordHash() after duplicate CreateAdmin() error = %v", err)
	}
	if got != "first-hash" {
		t.Fatalf("AdminPasswordHash() after duplicate CreateAdmin() = %q, want first-hash", got)
	}
}

func openTestStorage(t *testing.T, ctx context.Context) *storage.SQLiteStore {
	t.Helper()

	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return store
}

func closeTestStorage(t *testing.T, ctx context.Context, store *storage.SQLiteStore) {
	t.Helper()

	if err := store.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

package localdns

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/bjhaid/corehole/internal/storage"
)

func TestSQLiteRepositoryPersistsRecords(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	repo := NewSQLiteRepository(store.DB())
	disabled := false
	created, err := repo.Create(ctx, RecordInput{
		Name:    "Host.Example.",
		Type:    TypeA,
		Value:   "192.0.2.10",
		TTL:     120,
		Enabled: &disabled,
		Comment: " office host ",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == 0 {
		t.Fatal("created ID = 0, want nonzero")
	}
	if created.Name != "host.example" || created.Value != "192.0.2.10" || created.Enabled {
		t.Fatalf("created record = %#v", created)
	}
	if created.Comment != "office host" {
		t.Fatalf("comment = %q, want trimmed", created.Comment)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("timestamps were not populated: %#v", created)
	}

	loaded, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if loaded != created {
		t.Fatalf("loaded = %#v, want %#v", loaded, created)
	}

	enabled := true
	updated, err := repo.Update(ctx, created.ID, RecordInput{
		Name:    "Alias.Example",
		Type:    TypeCNAME,
		Value:   "host.example",
		TTL:     600,
		Enabled: &enabled,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if updated.Name != "alias.example" || updated.Type != TypeCNAME || updated.Value != "host.example" || !updated.Enabled {
		t.Fatalf("updated record = %#v", updated)
	}
	if !updated.UpdatedAt.After(updated.CreatedAt) && !updated.UpdatedAt.Equal(updated.CreatedAt) {
		t.Fatalf("updated_at = %s before created_at = %s", updated.UpdatedAt, updated.CreatedAt)
	}

	records, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != 1 || records[0].ID != created.ID {
		t.Fatalf("records = %#v, want updated record", records)
	}

	enabledRecords, err := repo.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled() error = %v", err)
	}
	if len(enabledRecords) != 1 || enabledRecords[0].ID != created.ID {
		t.Fatalf("enabled records = %#v, want updated record", enabledRecords)
	}

	if err := repo.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repo.Get(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after delete error = %v, want ErrNotFound", err)
	}
}

func TestSQLiteRepositoryListEnabledOmitsDisabledRecords(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "corehole.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := store.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	repo := NewSQLiteRepository(store.DB())
	disabled := false
	if _, err := repo.Create(ctx, RecordInput{Name: "disabled.example", Type: TypeA, Value: "192.0.2.20", Enabled: &disabled}); err != nil {
		t.Fatalf("Create(disabled) error = %v", err)
	}
	enabled := true
	if _, err := repo.Create(ctx, RecordInput{Name: "enabled.example", Type: TypeAAAA, Value: "2001:db8::1", Enabled: &enabled}); err != nil {
		t.Fatalf("Create(enabled) error = %v", err)
	}

	records, err := repo.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled() error = %v", err)
	}
	if len(records) != 1 || records[0].Name != "enabled.example" {
		t.Fatalf("enabled records = %#v, want only enabled.example", records)
	}
}

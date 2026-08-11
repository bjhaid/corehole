package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrNotFound = errors.New("persisted config not found")

type Store interface {
	Load(ctx context.Context) (Config, error)
	Save(ctx context.Context, cfg Config) error
}

type Source string

const (
	SourceBootstrap Source = "bootstrap"
	SourcePersisted Source = "persisted"
)

type InitializeResult struct {
	Config Config
	Source Source
}

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

func InitializeStore(ctx context.Context, store Store, bootstrap Config) (Config, error) {
	result, err := InitializeStoreWithSource(ctx, store, bootstrap)
	if err != nil {
		return Config{}, err
	}
	return result.Config, nil
}

func InitializeStoreWithSource(ctx context.Context, store Store, bootstrap Config) (InitializeResult, error) {
	cfg, err := store.Load(ctx)
	if err == nil {
		return InitializeResult{Config: cfg, Source: SourcePersisted}, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return InitializeResult{}, err
	}
	if err := bootstrap.Validate(); err != nil {
		return InitializeResult{}, fmt.Errorf("validate bootstrap config: %w", err)
	}
	if err := store.Save(ctx, bootstrap); err != nil {
		return InitializeResult{}, err
	}
	return InitializeResult{Config: bootstrap, Source: SourceBootstrap}, nil
}

func (s *SQLiteStore) Load(ctx context.Context) (Config, error) {
	if s == nil || s.db == nil {
		return Config{}, errors.New("config sqlite store requires a database")
	}

	var payload string
	err := s.db.QueryRowContext(ctx, "SELECT payload FROM app_config WHERE id = 1").Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, ErrNotFound
	}
	if err != nil {
		return Config{}, fmt.Errorf("load persisted config: %w", err)
	}

	cfg := Default()
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		return Config{}, fmt.Errorf("decode persisted config: %w", err)
	}
	normalizeLegacyCacheConfig(&cfg, []byte(payload))
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate persisted config: %w", err)
	}
	return cfg, nil
}

func (s *SQLiteStore) Save(ctx context.Context, cfg Config) error {
	if s == nil || s.db == nil {
		return errors.New("config sqlite store requires a database")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate persisted config: %w", err)
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode persisted config: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO app_config (id, payload, updated_at)
VALUES (1, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	payload = excluded.payload,
	updated_at = excluded.updated_at`,
		string(payload),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save persisted config: %w", err)
	}
	return nil
}

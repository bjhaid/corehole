package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrAlreadySetup = errors.New("admin user is already set up")
	ErrNotSetup     = errors.New("admin user is not set up")
)

type UserStore interface {
	IsSetup(ctx context.Context) (bool, error)
	CreateAdmin(ctx context.Context, passwordHash string) error
	AdminPasswordHash(ctx context.Context) (string, error)
}

type MemoryUserStore struct {
	mu                sync.RWMutex
	adminPasswordHash string
	nextAPIKeyID      int64
	apiKeys           map[int64]storedAPIKey
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		nextAPIKeyID: 1,
		apiKeys:      make(map[int64]storedAPIKey),
	}
}

func (s *MemoryUserStore) IsSetup(context.Context) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.adminPasswordHash != "", nil
}

func (s *MemoryUserStore) CreateAdmin(_ context.Context, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.adminPasswordHash != "" {
		return ErrAlreadySetup
	}
	s.adminPasswordHash = passwordHash
	return nil
}

func (s *MemoryUserStore) AdminPasswordHash(context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.adminPasswordHash == "" {
		return "", ErrNotSetup
	}
	return s.adminPasswordHash, nil
}

type SQLiteUserStore struct {
	db *sql.DB
}

func NewSQLiteUserStore(db *sql.DB) *SQLiteUserStore {
	return &SQLiteUserStore{db: db}
}

func (s *SQLiteUserStore) IsSetup(ctx context.Context) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM admin_users WHERE id = 1").Scan(&count); err != nil {
		return false, fmt.Errorf("check admin setup: %w", err)
	}
	return count > 0, nil
}

func (s *SQLiteUserStore) CreateAdmin(ctx context.Context, passwordHash string) error {
	result, err := s.db.ExecContext(
		ctx,
		"INSERT OR IGNORE INTO admin_users (id, password_hash, created_at) VALUES (1, ?, ?)",
		passwordHash,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check admin user creation: %w", err)
	}
	if rows == 0 {
		return ErrAlreadySetup
	}
	return nil
}

func (s *SQLiteUserStore) AdminPasswordHash(ctx context.Context) (string, error) {
	var passwordHash string
	err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM admin_users WHERE id = 1").Scan(&passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotSetup
	}
	if err != nil {
		return "", fmt.Errorf("load admin password hash: %w", err)
	}
	return passwordHash, nil
}

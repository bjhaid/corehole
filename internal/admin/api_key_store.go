package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

var ErrAPIKeyNotFound = errors.New("api key not found")

type APIKeyStore interface {
	ListAPIKeys(ctx context.Context) ([]APIKey, error)
	CreateAPIKey(ctx context.Context, name, keyHash, prefix, last4 string, createdAt time.Time) (APIKey, error)
	FindValidAPIKeyByHash(ctx context.Context, keyHash string) (APIKey, error)
	MarkAPIKeyUsed(ctx context.Context, id int64, usedAt time.Time) error
	RevokeAPIKey(ctx context.Context, id int64, revokedAt time.Time) error
}

type APIKey struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Last4      string     `json:"last4"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Disabled   bool       `json:"disabled"`
}

type storedAPIKey struct {
	APIKey
	KeyHash string
}

func (s *MemoryUserStore) ListAPIKeys(context.Context) ([]APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]APIKey, 0, len(s.apiKeys))
	for _, key := range s.apiKeys {
		keys = append(keys, key.APIKey)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].CreatedAt.Equal(keys[j].CreatedAt) {
			return keys[i].ID > keys[j].ID
		}
		return keys[i].CreatedAt.After(keys[j].CreatedAt)
	})
	return keys, nil
}

func (s *MemoryUserStore) CreateAPIKey(_ context.Context, name, keyHash, prefix, last4 string, createdAt time.Time) (APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, key := range s.apiKeys {
		if key.KeyHash == keyHash {
			return APIKey{}, fmt.Errorf("create api key: duplicate key hash")
		}
	}

	key := APIKey{
		ID:        s.nextAPIKeyID,
		Name:      name,
		Prefix:    prefix,
		Last4:     last4,
		CreatedAt: createdAt,
	}
	s.nextAPIKeyID++
	s.apiKeys[key.ID] = storedAPIKey{APIKey: key, KeyHash: keyHash}
	return key, nil
}

func (s *MemoryUserStore) FindValidAPIKeyByHash(_ context.Context, keyHash string) (APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, key := range s.apiKeys {
		if key.KeyHash == keyHash && !key.Disabled && key.RevokedAt == nil {
			return key.APIKey, nil
		}
	}
	return APIKey{}, ErrAPIKeyNotFound
}

func (s *MemoryUserStore) MarkAPIKeyUsed(_ context.Context, id int64, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, ok := s.apiKeys[id]
	if !ok {
		return ErrAPIKeyNotFound
	}
	key.LastUsedAt = &usedAt
	s.apiKeys[id] = key
	return nil
}

func (s *MemoryUserStore) RevokeAPIKey(_ context.Context, id int64, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, ok := s.apiKeys[id]
	if !ok {
		return ErrAPIKeyNotFound
	}
	key.Disabled = true
	key.RevokedAt = &revokedAt
	s.apiKeys[id] = key
	return nil
}

func (s *SQLiteUserStore) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, prefix, last4, created_at, last_used_at, revoked_at, disabled
FROM api_keys
ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		key, err := scanAPIKey(rows.Scan)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list api keys rows: %w", err)
	}
	return keys, nil
}

func (s *SQLiteUserStore) CreateAPIKey(ctx context.Context, name, keyHash, prefix, last4 string, createdAt time.Time) (APIKey, error) {
	result, err := s.db.ExecContext(ctx, `
INSERT INTO api_keys (name, key_hash, prefix, last4, created_at)
VALUES (?, ?, ?, ?, ?)`,
		name,
		keyHash,
		prefix,
		last4,
		formatAPIKeyTime(createdAt),
	)
	if err != nil {
		return APIKey{}, fmt.Errorf("create api key: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return APIKey{}, fmt.Errorf("load created api key id: %w", err)
	}
	return APIKey{
		ID:        id,
		Name:      name,
		Prefix:    prefix,
		Last4:     last4,
		CreatedAt: createdAt,
	}, nil
}

func (s *SQLiteUserStore) FindValidAPIKeyByHash(ctx context.Context, keyHash string) (APIKey, error) {
	key, err := scanAPIKey(s.db.QueryRowContext(ctx, `
SELECT id, name, prefix, last4, created_at, last_used_at, revoked_at, disabled
FROM api_keys
WHERE key_hash = ?
	AND disabled = 0
	AND revoked_at = ''
LIMIT 1`, keyHash).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, ErrAPIKeyNotFound
	}
	if err != nil {
		return APIKey{}, err
	}
	return key, nil
}

func (s *SQLiteUserStore) MarkAPIKeyUsed(ctx context.Context, id int64, usedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE api_keys
SET last_used_at = ?
WHERE id = ?`,
		formatAPIKeyTime(usedAt),
		id,
	)
	if err != nil {
		return fmt.Errorf("mark api key used: %w", err)
	}
	return nil
}

func (s *SQLiteUserStore) RevokeAPIKey(ctx context.Context, id int64, revokedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE api_keys
SET disabled = 1, revoked_at = ?
WHERE id = ?
	AND disabled = 0
	AND revoked_at = ''`,
		formatAPIKeyTime(revokedAt),
		id,
	)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check api key revoke: %w", err)
	}
	if rows == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

type scanner func(dest ...any) error

func scanAPIKey(scan scanner) (APIKey, error) {
	var key APIKey
	var createdAt string
	var lastUsedAt string
	var revokedAt string
	var disabled int

	if err := scan(
		&key.ID,
		&key.Name,
		&key.Prefix,
		&key.Last4,
		&createdAt,
		&lastUsedAt,
		&revokedAt,
		&disabled,
	); err != nil {
		return APIKey{}, err
	}

	parsedCreatedAt, err := parseAPIKeyTime(createdAt)
	if err != nil {
		return APIKey{}, fmt.Errorf("parse api key created_at: %w", err)
	}
	key.CreatedAt = parsedCreatedAt
	key.LastUsedAt, err = parseOptionalAPIKeyTime(lastUsedAt)
	if err != nil {
		return APIKey{}, fmt.Errorf("parse api key last_used_at: %w", err)
	}
	key.RevokedAt, err = parseOptionalAPIKeyTime(revokedAt)
	if err != nil {
		return APIKey{}, fmt.Errorf("parse api key revoked_at: %w", err)
	}
	key.Disabled = disabled != 0
	return key, nil
}

func formatAPIKeyTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseAPIKeyTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

func parseOptionalAPIKeyTime(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := parseAPIKeyTime(value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

type SessionStore interface {
	Create(now time.Time, ttl time.Duration) (string, error)
	Valid(token string, now time.Time) bool
	Delete(token string)
}

type unavailableSessionStore struct{}

func NewUnavailableSessionStore() SessionStore { return unavailableSessionStore{} }
func (unavailableSessionStore) Create(time.Time, time.Duration) (string, error) {
	return "", errors.New("session storage unavailable")
}
func (unavailableSessionStore) Valid(string, time.Time) bool { return false }
func (unavailableSessionStore) Delete(string)                {}

type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]memorySession
}

type memorySession struct {
	digest  []byte
	expires time.Time
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]memorySession)}
}

func (s *MemorySessionStore) Create(now time.Time, ttl time.Duration) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := tokenDigest(token)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[tokenDigestKey(digest)] = memorySession{
		digest:  digest,
		expires: now.Add(ttl),
	}
	return token, nil
}

func (s *MemorySessionStore) Valid(token string, now time.Time) bool {
	digest := tokenDigest(token)

	s.mu.Lock()
	defer s.mu.Unlock()
	for key, session := range s.sessions {
		if !session.expires.After(now) {
			delete(s.sessions, key)
			continue
		}
		if subtle.ConstantTimeCompare(digest, session.digest) == 1 {
			return true
		}
	}
	return false
}

func (s *MemorySessionStore) Delete(token string) {
	digest := tokenDigest(token)

	s.mu.Lock()
	defer s.mu.Unlock()
	for key, session := range s.sessions {
		if subtle.ConstantTimeCompare(digest, session.digest) == 1 {
			delete(s.sessions, key)
			return
		}
	}
}

type SQLiteSessionStore struct {
	db     *sql.DB
	readDB *sql.DB

	mu       sync.Mutex
	sessions map[string]memorySession
}

func NewSQLiteSessionStore(db *sql.DB) *SQLiteSessionStore {
	return NewSQLiteSessionStoreWithReader(db, db)
}

func NewSQLiteSessionStoreWithReader(db, readDB *sql.DB) *SQLiteSessionStore {
	return &SQLiteSessionStore{
		db:       db,
		readDB:   readDB,
		sessions: make(map[string]memorySession),
	}
}

func (s *SQLiteSessionStore) Create(now time.Time, ttl time.Duration) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := tokenDigest(token)
	key := tokenDigestKey(digest)
	expires := now.Add(ttl).UTC()

	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := s.db.ExecContext(ctx, `
INSERT INTO admin_sessions (token_hash, created_at, expires_at)
VALUES (?, ?, ?)`,
			key,
			now.UTC().Format(time.RFC3339Nano),
			expires.Format(time.RFC3339Nano),
		)
		if err != nil {
			return "", err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = memorySession{
		digest:  digest,
		expires: expires,
	}
	return token, nil
}

func (s *SQLiteSessionStore) Valid(token string, now time.Time) bool {
	digest := tokenDigest(token)
	key := tokenDigestKey(digest)

	if s.validCached(key, digest, now) {
		return true
	}
	if s.db == nil {
		return false
	}

	var expiresRaw string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.readDB.QueryRowContext(ctx, `
SELECT expires_at
FROM admin_sessions
WHERE token_hash = ?`, key).Scan(&expiresRaw)
	if err != nil {
		return false
	}

	expires, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil || !expires.After(now.UTC()) {
		s.Delete(token)
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = memorySession{
		digest:  digest,
		expires: expires,
	}
	return true
}

func (s *SQLiteSessionStore) validCached(key string, digest []byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for cachedKey, session := range s.sessions {
		if !session.expires.After(now.UTC()) {
			delete(s.sessions, cachedKey)
			continue
		}
	}
	session, ok := s.sessions[key]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(digest, session.digest) == 1
}

func (s *SQLiteSessionStore) Delete(token string) {
	digest := tokenDigest(token)
	key := tokenDigestKey(digest)

	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()

	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE token_hash = ?", key)
	}
}

// CopyLegacySessions runs once. The marker is committed with the copied rows
// so a later restart cannot resurrect a session deleted from the new database.
func CopyLegacySessions(ctx context.Context, source, target *sql.DB) error {
	var imported int
	if err := target.QueryRowContext(ctx, "SELECT COUNT(*) FROM session_metadata WHERE key='legacy_imported'").Scan(&imported); err != nil {
		return err
	}
	if imported != 0 {
		return nil
	}
	rows, err := source.QueryContext(ctx, "SELECT token_hash, created_at, expires_at FROM admin_sessions WHERE expires_at > ?", time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	type session struct{ hash, created, expires string }
	var sessions []session
	for rows.Next() {
		var s session
		if err := rows.Scan(&s.hash, &s.created, &s.expires); err != nil {
			_ = rows.Close()
			return err
		}
		sessions = append(sessions, s)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	tx, err := target.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, s := range sessions {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO admin_sessions(token_hash, created_at, expires_at) VALUES (?,?,?)", s.hash, s.created, s.expires); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO session_metadata(key) VALUES ('legacy_imported')"); err != nil {
		return err
	}
	return tx.Commit()
}

func tokenDigest(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func tokenDigestKey(digest []byte) string {
	return base64.RawStdEncoding.EncodeToString(digest)
}

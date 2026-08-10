package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

type SessionStore interface {
	Create(now time.Time, ttl time.Duration) (string, error)
	Valid(token string, now time.Time) bool
	Delete(token string)
}

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
	s.sessions[base64.RawStdEncoding.EncodeToString(digest)] = memorySession{
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

func tokenDigest(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

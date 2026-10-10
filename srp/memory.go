package srp

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"uuid"

	"github.com/tpyle/auth/v2"
)

// MemoryUserStore is an in-memory [UserStore]. It is intended for tests,
// examples and prototypes.
type MemoryUserStore struct {
	mu        sync.RWMutex
	verifiers map[string]string
}

// NewMemoryUserStore returns an empty [MemoryUserStore].
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{verifiers: map[string]string{}}
}

// SetVerifier creates or replaces username's verifier.
func (s *MemoryUserStore) SetVerifier(username string, v *Verifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifiers[username] = v.String()
}

// LookupVerifier implements [UserStore].
func (s *MemoryUserStore) LookupVerifier(_ context.Context, username string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.verifiers[username]
	if !ok {
		return "", fmt.Errorf("%w: %q", auth.ErrUserNotFound, username)
	}
	return v, nil
}

// MemorySessionStore is an in-memory [SessionStore]. It is the default when
// [New] is not given one, and is meant for development and single-instance
// deployments. Because it is not shared, a login can only be finished by the
// process that began it. It has no size limit: every BeginLogin call adds
// an entry that lives for [Config.SessionTTL], so rate-limit the login
// endpoints.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]memorySession
}

type memorySession struct {
	data      []byte
	expiresAt time.Time
}

// NewMemorySessionStore returns an empty [MemorySessionStore].
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: map[uuid.UUID]memorySession{}}
}

// SaveSession implements [SessionStore]. Sessions that expired before the
// wall-clock time are deleted on each call, so abandoned logins do not
// accumulate.
func (s *MemorySessionStore) SaveSession(_ context.Context, id uuid.UUID, data []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	maps.DeleteFunc(s.sessions, func(_ uuid.UUID, c memorySession) bool { return now.After(c.expiresAt) })
	s.sessions[id] = memorySession{data: bytes.Clone(data), expiresAt: expiresAt}
	return nil
}

// ConsumeSession implements [SessionStore].
func (s *MemorySessionStore) ConsumeSession(_ context.Context, id uuid.UUID, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	delete(s.sessions, id)
	if !now.Before(c.expiresAt) {
		return nil, ErrSessionNotFound
	}
	return c.data, nil
}

// Len returns the number of stored sessions, including expired ones not yet
// deleted.
func (s *MemorySessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

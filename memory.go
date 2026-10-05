package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryUserStore is an in-memory [UserStore] and [PasswordHashUpdater]. It is
// intended for tests, examples and prototypes.
type MemoryUserStore struct {
	mu     sync.RWMutex
	hashes map[string]string
}

// NewMemoryUserStore returns an empty [MemoryUserStore].
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{hashes: map[string]string{}}
}

// SetPasswordHash creates or replaces a user's PHC-encoded hash.
func (s *MemoryUserStore) SetPasswordHash(username, encodedHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hashes[username] = encodedHash
}

// LookupPasswordHash implements [UserStore].
func (s *MemoryUserStore) LookupPasswordHash(_ context.Context, username string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hashes[username]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUserNotFound, username)
	}
	return h, nil
}

// UpdatePasswordHash implements [PasswordHashUpdater].
func (s *MemoryUserStore) UpdatePasswordHash(_ context.Context, username, encodedHash string) error {
	s.SetPasswordHash(username, encodedHash)
	return nil
}

// MemoryKeyStore is an in-memory [KeyStore]. It is the default when [New] is
// not given a key store. Because it is not shared, tokens can only be
// verified by the process that issued them and do not survive a restart.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[uuid.UUID]*VerificationKey
}

// NewMemoryKeyStore returns an empty [MemoryKeyStore].
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{keys: map[uuid.UUID]*VerificationKey{}}
}

// StoreKey implements [KeyStore].
func (s *MemoryKeyStore) StoreKey(_ context.Context, key *VerificationKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := *key
	s.keys[key.ID] = &k
	return nil
}

// GetKey implements [KeyStore].
func (s *MemoryKeyStore) GetKey(_ context.Context, id uuid.UUID) (*VerificationKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	c := *k
	return &c, nil
}

// ListKeys implements [KeyStore].
func (s *MemoryKeyStore) ListKeys(_ context.Context) ([]*VerificationKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*VerificationKey, 0, len(s.keys))
	for _, k := range s.keys {
		c := *k
		out = append(out, &c)
	}
	return out, nil
}

// DeleteKeys implements [KeyStore].
func (s *MemoryKeyStore) DeleteKeys(_ context.Context, ids []uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		delete(s.keys, id)
	}
	return nil
}

// MemoryRefreshTokenStore is an in-memory [RefreshTokenStore] intended for
// tests and single-instance deployments. Expired records are purged whenever
// a new token is created.
type MemoryRefreshTokenStore struct {
	mu      sync.Mutex
	records map[uuid.UUID]RefreshTokenRecord
	now     func() time.Time
}

// NewMemoryRefreshTokenStore returns an empty [MemoryRefreshTokenStore].
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{records: map[uuid.UUID]RefreshTokenRecord{}, now: time.Now}
}

// CreateRefreshToken implements [RefreshTokenStore].
func (s *MemoryRefreshTokenStore) CreateRefreshToken(_ context.Context, rec RefreshTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, r := range s.records {
		if now.After(r.ExpiresAt) {
			delete(s.records, id)
		}
	}
	s.records[rec.ID] = rec
	return nil
}

// ConsumeRefreshToken implements [RefreshTokenStore].
func (s *MemoryRefreshTokenStore) ConsumeRefreshToken(_ context.Context, id uuid.UUID) (RefreshTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return RefreshTokenRecord{}, fmt.Errorf("%w: %s", ErrRefreshTokenNotFound, id)
	}
	used := rec
	used.Used = true
	s.records[id] = used
	return rec, nil
}

// RevokeRefreshTokenFamily implements [RefreshTokenStore].
func (s *MemoryRefreshTokenStore) RevokeRefreshTokenFamily(_ context.Context, familyID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.records {
		if r.FamilyID == familyID {
			delete(s.records, id)
		}
	}
	return nil
}

// Len returns the number of records held, including used ones.
func (s *MemoryRefreshTokenStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

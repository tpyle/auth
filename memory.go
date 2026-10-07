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
func (s *MemoryUserStore) UpdatePasswordHash(_ context.Context, username, oldHash, newHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.hashes[username]; ok && h == oldHash {
		s.hashes[username] = newHash
	}
	return nil
}

// MemoryKeyStore is an in-memory [KeyStore]. It is the default when [New] is
// not given a key store. Because it is not shared, tokens can only be
// verified by the process that issued them and do not survive a restart.
//
// Keys are held in encoded form, like a database would, so callers can never
// share mutable state with the store.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[uuid.UUID]memoryKey
}

type memoryKey struct {
	der                  []byte
	createdAt, expiresAt time.Time
}

// NewMemoryKeyStore returns an empty [MemoryKeyStore].
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{keys: map[uuid.UUID]memoryKey{}}
}

// StoreKey implements [KeyStore].
func (s *MemoryKeyStore) StoreKey(_ context.Context, key *VerificationKey) error {
	der, err := key.MarshalPublicKey()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.ID] = memoryKey{der: der, createdAt: key.CreatedAt, expiresAt: key.ExpiresAt}
	return nil
}

// ListKeys implements [KeyStore].
func (s *MemoryKeyStore) ListKeys(_ context.Context) ([]*VerificationKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*VerificationKey, 0, len(s.keys))
	for id, k := range s.keys {
		pub, err := ParsePublicKey(k.der)
		if err != nil {
			return nil, err
		}
		out = append(out, &VerificationKey{ID: id, PublicKey: pub, CreatedAt: k.createdAt, ExpiresAt: k.expiresAt})
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

// memoryPurgeInterval is the least time between the purges
// [MemoryRefreshTokenStore] runs when creating tokens.
const memoryPurgeInterval = time.Minute

// MemoryRefreshTokenStore is an in-memory [RefreshTokenStore] and
// [RefreshTokenPurger] intended for tests and single-instance deployments.
// It also purges records and families that expired more than a few minutes
// ago when a token is created, at most once a minute, so it stays bounded
// even with background purging disabled.
type MemoryRefreshTokenStore struct {
	mu        sync.Mutex
	records   map[uuid.UUID]RefreshTokenRecord
	families  map[uuid.UUID]*memoryFamily
	lastPurge time.Time // IssuedAt of the create that last purged
}

type memoryFamily struct {
	subject   string
	revoked   bool
	expiresAt time.Time // latest expiry of any token in the family
}

var _ RefreshTokenPurger = (*MemoryRefreshTokenStore)(nil)

// NewMemoryRefreshTokenStore returns an empty [MemoryRefreshTokenStore].
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{
		records:  map[uuid.UUID]RefreshTokenRecord{},
		families: map[uuid.UUID]*memoryFamily{},
	}
}

// CreateRefreshToken implements [RefreshTokenStore].
func (s *MemoryRefreshTokenStore) CreateRefreshToken(_ context.Context, rec RefreshTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Purge relative to the new record's issue time rather than the wall
	// clock, so the store follows the Authorizer's clock (see WithClock).
	// The margin matches the Authorizer's, for the same reason.
	// A clock that moved backwards also purges, so purging resumes at once.
	if s.lastPurge.IsZero() || rec.IssuedAt.Before(s.lastPurge) ||
		!rec.IssuedAt.Before(s.lastPurge.Add(memoryPurgeInterval)) {
		s.purgeLocked(rec.IssuedAt.Add(-refreshPurgeMargin))
		s.lastPurge = rec.IssuedAt
	}

	f := s.families[rec.FamilyID]
	switch {
	case f == nil && rec.ParentID == uuid.Nil:
		s.families[rec.FamilyID] = &memoryFamily{subject: rec.Subject, expiresAt: rec.ExpiresAt}
	case f == nil:
		return fmt.Errorf("%w: family %s no longer exists", ErrTokenRevoked, rec.FamilyID)
	case f.revoked:
		return fmt.Errorf("%w: family %s", ErrTokenRevoked, rec.FamilyID)
	case rec.ExpiresAt.After(f.expiresAt):
		f.expiresAt = rec.ExpiresAt
	}
	s.records[rec.ID] = rec
	return nil
}

// PurgeExpiredRefreshTokens implements [RefreshTokenPurger].
func (s *MemoryRefreshTokenStore) PurgeExpiredRefreshTokens(_ context.Context, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.purgeLocked(now), nil
}

// purgeLocked deletes records and families that expired before now and
// returns how many it removed.
func (s *MemoryRefreshTokenStore) purgeLocked(now time.Time) int64 {
	var n int64
	for id, r := range s.records {
		if now.After(r.ExpiresAt) {
			delete(s.records, id)
			n++
		}
	}
	for id, f := range s.families {
		if now.After(f.expiresAt) {
			delete(s.families, id)
			n++
		}
	}
	return n
}

// ConsumeRefreshToken implements [RefreshTokenStore].
func (s *MemoryRefreshTokenStore) ConsumeRefreshToken(_ context.Context, id uuid.UUID, now time.Time) (RefreshTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return RefreshTokenRecord{}, fmt.Errorf("%w: %s", ErrRefreshTokenNotFound, id)
	}
	if !rec.Used() {
		used := rec
		used.UsedAt = now
		s.records[id] = used
	}
	return rec, nil
}

// RevokeRefreshTokenFamily implements [RefreshTokenStore].
func (s *MemoryRefreshTokenStore) RevokeRefreshTokenFamily(_ context.Context, familyID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeLocked(familyID)
	return nil
}

// RevokeRefreshTokensForSubject implements [RefreshTokenStore].
func (s *MemoryRefreshTokenStore) RevokeRefreshTokensForSubject(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, f := range s.families {
		if f.subject == subject {
			s.revokeLocked(id)
		}
	}
	return nil
}

func (s *MemoryRefreshTokenStore) revokeLocked(familyID uuid.UUID) {
	if f := s.families[familyID]; f != nil {
		f.revoked = true
	}
	for id, r := range s.records {
		if r.FamilyID == familyID {
			delete(s.records, id)
		}
	}
}

// Len returns the number of records held, including used ones.
func (s *MemoryRefreshTokenStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

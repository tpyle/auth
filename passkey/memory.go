package passkey

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

// MemoryUserStore is an in-memory [UserStore]. It is intended for tests,
// examples and prototypes.
type MemoryUserStore struct {
	mu       sync.RWMutex
	users    map[string]User
	byHandle map[string]string // handle -> subject
}

// NewMemoryUserStore returns an empty [MemoryUserStore].
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{users: map[string]User{}, byHandle: map[string]string{}}
}

// AddUser creates a user with a new handle from [NewUserHandle], or returns
// the existing user if subject is already known.
func (s *MemoryUserStore) AddUser(subject, name string) User {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[subject]; ok {
		return cloneUser(u)
	}
	u := User{Subject: subject, Handle: NewUserHandle(), Name: name}
	s.users[subject] = u
	s.byHandle[string(u.Handle)] = subject
	return cloneUser(u)
}

// LookupUser implements [UserStore].
func (s *MemoryUserStore) LookupUser(_ context.Context, subject string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[subject]
	if !ok {
		return User{}, fmt.Errorf("%w: %q", auth.ErrUserNotFound, subject)
	}
	return cloneUser(u), nil
}

// LookupUserByHandle implements [UserStore].
func (s *MemoryUserStore) LookupUserByHandle(_ context.Context, handle []byte) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	subject, ok := s.byHandle[string(handle)]
	if !ok {
		return User{}, fmt.Errorf("%w: unknown handle", auth.ErrUserNotFound)
	}
	return cloneUser(s.users[subject]), nil
}

func cloneUser(u User) User {
	u.Handle = bytes.Clone(u.Handle)
	return u
}

// MemoryCredentialStore is an in-memory [CredentialStore]. It is intended
// for tests, examples and prototypes.
type MemoryCredentialStore struct {
	mu    sync.RWMutex
	creds map[string]Credential // by ID
}

// NewMemoryCredentialStore returns an empty [MemoryCredentialStore].
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{creds: map[string]Credential{}}
}

// ListCredentials implements [CredentialStore]. Credentials are ordered by
// creation time.
func (s *MemoryCredentialStore) ListCredentials(_ context.Context, subject string) ([]Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Credential
	for _, c := range s.creds {
		if c.Subject == subject {
			out = append(out, cloneCredential(c))
		}
	}
	slices.SortFunc(out, func(a, b Credential) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

// CreateCredential implements [CredentialStore].
func (s *MemoryCredentialStore) CreateCredential(_ context.Context, c Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.creds[string(c.ID)]; ok {
		return ErrCredentialExists
	}
	s.creds[string(c.ID)] = cloneCredential(c)
	return nil
}

// RecordCredentialUse implements [CredentialStore].
func (s *MemoryCredentialStore) RecordCredentialUse(_ context.Context, u CredentialUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[string(u.ID)]
	if !ok {
		return nil
	}
	c.SignCount = max(c.SignCount, u.SignCount)
	c.BackupState = u.BackupState
	c.UserVerified = c.UserVerified || u.UserVerified
	c.CloneWarning = c.CloneWarning || u.CloneWarning
	if !u.UsedAt.IsZero() {
		c.LastUsedAt = u.UsedAt
	}
	s.creds[string(u.ID)] = c
	return nil
}

// DeleteCredential implements [CredentialStore].
func (s *MemoryCredentialStore) DeleteCredential(_ context.Context, subject string, id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.creds[string(id)]; !ok || c.Subject != subject {
		return ErrCredentialNotFound
	}
	delete(s.creds, string(id))
	return nil
}

func cloneCredential(c Credential) Credential {
	c.ID = bytes.Clone(c.ID)
	c.PublicKey = bytes.Clone(c.PublicKey)
	c.AAGUID = bytes.Clone(c.AAGUID)
	c.Transports = slices.Clone(c.Transports)
	return c
}

// MemoryCeremonyStore is an in-memory [CeremonyStore]. It is the default
// when [New] is not given one, and is meant for development and
// single-instance deployments. Because it is not shared, a ceremony can only
// be finished by the process that began it. It has no size limit: every
// Begin call adds an entry that lives for [Config.CeremonyTTL], so
// rate-limit the Begin endpoints (as with any CeremonyStore, since
// [Passkeys.BeginLogin] needs no authentication).
type MemoryCeremonyStore struct {
	mu         sync.Mutex
	ceremonies map[uuid.UUID]memoryCeremony
}

type memoryCeremony struct {
	data      []byte
	expiresAt time.Time
}

// NewMemoryCeremonyStore returns an empty [MemoryCeremonyStore].
func NewMemoryCeremonyStore() *MemoryCeremonyStore {
	return &MemoryCeremonyStore{ceremonies: map[uuid.UUID]memoryCeremony{}}
}

// SaveCeremony implements [CeremonyStore]. Ceremonies that expired before
// the wall-clock time are deleted on each call, so abandoned ceremonies do
// not accumulate.
func (s *MemoryCeremonyStore) SaveCeremony(_ context.Context, id uuid.UUID, data []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	maps.DeleteFunc(s.ceremonies, func(_ uuid.UUID, c memoryCeremony) bool { return now.After(c.expiresAt) })
	s.ceremonies[id] = memoryCeremony{data: bytes.Clone(data), expiresAt: expiresAt}
	return nil
}

// ConsumeCeremony implements [CeremonyStore].
func (s *MemoryCeremonyStore) ConsumeCeremony(_ context.Context, id uuid.UUID, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ceremonies[id]
	if !ok {
		return nil, ErrCeremonyNotFound
	}
	delete(s.ceremonies, id)
	if !now.Before(c.expiresAt) {
		return nil, ErrCeremonyNotFound
	}
	return c.data, nil
}

// Len returns the number of stored ceremonies, including expired ones not
// yet deleted.
func (s *MemoryCeremonyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ceremonies)
}

package auth

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// testArgon2 is cheap enough to keep tests fast.
var testArgon2 = Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

var discardLogger = slog.New(slog.DiscardHandler)

// fakeClock is a manually advanced time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

// newFakeClock starts at the current time, so records it timestamps are not
// already expired by the wall-clock purging in MemoryRefreshTokenStore.
func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Now().Truncate(time.Second)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestAuthorizer builds an Authorizer with fast hashing and a silent
// logger, and closes it when the test ends. Later opts override the defaults.
func newTestAuthorizer(t *testing.T, opts ...Option) *Authorizer {
	t.Helper()
	base := []Option{WithArgon2Params(testArgon2), WithLogger(discardLogger)}
	a, err := New(context.Background(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// mustHash hashes password with testArgon2.
func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPassword([]byte(password), testArgon2)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// faultyKeyStore wraps a KeyStore and injects errors. Set errors with fail,
// since background rotation may read them concurrently.
type faultyKeyStore struct {
	KeyStore
	mu                           sync.Mutex
	storeErr, listErr, deleteErr error
	listCalls                    atomic.Int32
}

func newFaultyKeyStore() *faultyKeyStore {
	return &faultyKeyStore{KeyStore: NewMemoryKeyStore()}
}

func (f *faultyKeyStore) fail(field *error, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*field = err
}

func (f *faultyKeyStore) err(field *error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *field
}

func (f *faultyKeyStore) StoreKey(ctx context.Context, k *VerificationKey) error {
	if err := f.err(&f.storeErr); err != nil {
		return err
	}
	return f.KeyStore.StoreKey(ctx, k)
}

func (f *faultyKeyStore) ListKeys(ctx context.Context) ([]*VerificationKey, error) {
	f.listCalls.Add(1)
	if err := f.err(&f.listErr); err != nil {
		return nil, err
	}
	return f.KeyStore.ListKeys(ctx)
}

func (f *faultyKeyStore) DeleteKeys(ctx context.Context, ids []uuid.UUID) error {
	if err := f.err(&f.deleteErr); err != nil {
		return err
	}
	return f.KeyStore.DeleteKeys(ctx, ids)
}

// faultyRefreshStore wraps a RefreshTokenStore and injects errors.
type faultyRefreshStore struct {
	RefreshTokenStore
	createErr, consumeErr, revokeErr error
}

func (f *faultyRefreshStore) CreateRefreshToken(ctx context.Context, rec RefreshTokenRecord) error {
	if f.createErr != nil {
		return f.createErr
	}
	return f.RefreshTokenStore.CreateRefreshToken(ctx, rec)
}

func (f *faultyRefreshStore) ConsumeRefreshToken(ctx context.Context, id uuid.UUID, now time.Time) (RefreshTokenRecord, error) {
	if f.consumeErr != nil {
		return RefreshTokenRecord{}, f.consumeErr
	}
	return f.RefreshTokenStore.ConsumeRefreshToken(ctx, id, now)
}

func (f *faultyRefreshStore) RevokeRefreshTokensForSubject(ctx context.Context, subject string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	return f.RefreshTokenStore.RevokeRefreshTokensForSubject(ctx, subject)
}

func (f *faultyRefreshStore) RevokeRefreshTokenFamily(ctx context.Context, family uuid.UUID) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	return f.RefreshTokenStore.RevokeRefreshTokenFamily(ctx, family)
}

// userStoreFunc adapts a function to UserStore without PasswordHashUpdater.
type userStoreFunc func(ctx context.Context, username string) (string, error)

func (f userStoreFunc) LookupPasswordHash(ctx context.Context, username string) (string, error) {
	return f(ctx, username)
}

// failingUpdater is a UserStore whose UpdatePasswordHash always fails.
type failingUpdater struct {
	*MemoryUserStore
	calls atomic.Int32
}

func (f *failingUpdater) UpdatePasswordHash(context.Context, string, string) error {
	f.calls.Add(1)
	return errTest
}

type testError string

func (e testError) Error() string { return string(e) }

const errTest = testError("injected failure")

// storedKey returns the key with id from store, or nil.
func storedKey(t *testing.T, store KeyStore, id uuid.UUID) *VerificationKey {
	t.Helper()
	keys, err := store.ListKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.ID == id {
			return k
		}
	}
	return nil
}

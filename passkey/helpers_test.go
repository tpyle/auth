package passkey

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

var (
	discardLogger = slog.New(slog.DiscardHandler)
	errStore      = errors.New("store unavailable")
)

// fakeClock is a manually advanced time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

// newFakeClock starts at the current time, so ceremonies it timestamps are
// not already expired by the wall-clock purging in MemoryCeremonyStore.
func newFakeClock() *fakeClock { return &fakeClock{t: time.Now().Truncate(time.Second)} }

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

// fakeIssuer records IssueTokenPair calls.
type fakeIssuer struct {
	mu      sync.Mutex
	calls   []issueCall
	failErr error
}

type issueCall struct {
	subject string
	extra   map[string]any
}

func (f *fakeIssuer) IssueTokenPair(_ context.Context, subject string, extra map[string]any) (*auth.TokenPair, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, issueCall{subject, extra})
	if f.failErr != nil {
		return nil, f.failErr
	}
	return &auth.TokenPair{AccessToken: "access-" + subject, RefreshToken: "refresh-" + subject}, nil
}

func (f *fakeIssuer) Calls() []issueCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]issueCall(nil), f.calls...)
}

// env is a Passkeys service wired to memory stores and a virtual
// authenticator, with users alice and bob.
type env struct {
	t          *testing.T
	p          *Passkeys
	users      *MemoryUserStore
	creds      *MemoryCredentialStore
	ceremonies *MemoryCeremonyStore
	clock      *fakeClock
	issuer     *fakeIssuer
	va         *virtualAuthenticator
	alice, bob User
}

func newEnv(t *testing.T, opts ...Option) *env {
	t.Helper()
	e := &env{
		t:          t,
		users:      NewMemoryUserStore(),
		creds:      NewMemoryCredentialStore(),
		ceremonies: NewMemoryCeremonyStore(),
		clock:      newFakeClock(),
		issuer:     &fakeIssuer{},
		va:         newVirtualAuthenticator(t, testOrigin),
	}
	e.alice = e.users.AddUser("alice", "alice@example.com")
	e.bob = e.users.AddUser("bob", "bob@example.com")
	base := []Option{
		WithRelyingParty(testRPID, "Example", testOrigin),
		WithUserStore(e.users),
		WithCredentialStore(e.creds),
		WithCeremonyStore(e.ceremonies),
		WithTokenIssuer(e.issuer),
		WithLogger(discardLogger),
		WithClock(e.clock.Now),
	}
	p, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.p = p
	return e
}

// register adds a credential for subject through the full ceremony.
func (e *env) register(subject string) *virtualCredential {
	e.t.Helper()
	ch, err := e.p.BeginRegistration(context.Background(), subject)
	if err != nil {
		e.t.Fatalf("BeginRegistration: %v", err)
	}
	resp, cred := e.va.create(ch)
	if _, err := e.p.FinishRegistration(context.Background(), subject, ch.CeremonyID, resp, "test key"); err != nil {
		e.t.Fatalf("FinishRegistration: %v", err)
	}
	return cred
}

// beginLogin starts a discoverable login.
func (e *env) beginLogin() *Challenge {
	e.t.Helper()
	ch, err := e.p.BeginLogin(context.Background())
	if err != nil {
		e.t.Fatalf("BeginLogin: %v", err)
	}
	return ch
}

// login runs a discoverable login with cred and returns Authenticate's result.
func (e *env) login(cred *virtualCredential) (*Credential, error) {
	e.t.Helper()
	ch := e.beginLogin()
	return e.p.Authenticate(context.Background(), ch.CeremonyID, e.va.get(ch, cred, true))
}

// storedCredential returns subject's only credential.
func (e *env) storedCredential(subject string) Credential {
	e.t.Helper()
	creds, err := e.creds.ListCredentials(context.Background(), subject)
	if err != nil || len(creds) != 1 {
		e.t.Fatalf("ListCredentials(%q) = %d credentials, %v; want 1", subject, len(creds), err)
	}
	return creds[0]
}

// failingCeremonyStore wraps a CeremonyStore with injectable errors.
type failingCeremonyStore struct {
	CeremonyStore
	saveErr, consumeErr error
	consumeData         []byte // returned instead of the stored data if set
}

func (s *failingCeremonyStore) SaveCeremony(ctx context.Context, id uuid.UUID, data []byte, exp time.Time) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.CeremonyStore.SaveCeremony(ctx, id, data, exp)
}

func (s *failingCeremonyStore) ConsumeCeremony(ctx context.Context, id uuid.UUID, now time.Time) ([]byte, error) {
	if s.consumeErr != nil {
		return nil, s.consumeErr
	}
	if s.consumeData != nil {
		return s.consumeData, nil
	}
	return s.CeremonyStore.ConsumeCeremony(ctx, id, now)
}

// failingCredentialStore wraps a CredentialStore with injectable errors.
type failingCredentialStore struct {
	CredentialStore
	mu                                       sync.Mutex
	listErr, createErr, recordErr, deleteErr error
	extra                                    []Credential // appended to every list
}

func (s *failingCredentialStore) set(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

func (s *failingCredentialStore) ListCredentials(ctx context.Context, subject string) ([]Credential, error) {
	s.mu.Lock()
	err, extra := s.listErr, s.extra
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	creds, err := s.CredentialStore.ListCredentials(ctx, subject)
	return append(creds, extra...), err
}

func (s *failingCredentialStore) CreateCredential(ctx context.Context, c Credential) error {
	s.mu.Lock()
	err := s.createErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.CredentialStore.CreateCredential(ctx, c)
}

func (s *failingCredentialStore) RecordCredentialUse(ctx context.Context, u CredentialUse) error {
	s.mu.Lock()
	err := s.recordErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.CredentialStore.RecordCredentialUse(ctx, u)
}

func (s *failingCredentialStore) DeleteCredential(ctx context.Context, subject string, id []byte) error {
	s.mu.Lock()
	err := s.deleteErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.CredentialStore.DeleteCredential(ctx, subject, id)
}

// failingUserStore wraps a UserStore with injectable errors and handle
// tampering.
type failingUserStore struct {
	UserStore
	mu                sync.Mutex
	lookupErr         error
	handleErr         error
	wrongHandleResult bool // LookupUserByHandle returns a user with another handle
}

func (s *failingUserStore) set(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

func (s *failingUserStore) LookupUser(ctx context.Context, subject string) (User, error) {
	s.mu.Lock()
	err := s.lookupErr
	s.mu.Unlock()
	if err != nil {
		return User{}, err
	}
	return s.UserStore.LookupUser(ctx, subject)
}

func (s *failingUserStore) LookupUserByHandle(ctx context.Context, handle []byte) (User, error) {
	s.mu.Lock()
	err, wrong := s.handleErr, s.wrongHandleResult
	s.mu.Unlock()
	if err != nil {
		return User{}, err
	}
	u, err := s.UserStore.LookupUserByHandle(ctx, handle)
	if wrong {
		u.Handle = append(u.Handle, 0)
	}
	return u, err
}

// newTestLogger logs everything, including debug messages, to w.
func newTestLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

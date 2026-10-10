package srp

import (
	"context"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"uuid"

	"github.com/tpyle/auth/v2"
)

var (
	discardLogger = slog.New(slog.DiscardHandler)
	errStore      = errors.New("store unavailable")
	// testKDF is cheap so tests run fast. Never use it in production.
	testKDF = KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1}
)

// fakeClock is a manually advanced time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

// newFakeClock starts at the current time, so sessions it timestamps are
// not already expired by the wall-clock purging in MemorySessionStore.
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

// failingUserStore returns err from every lookup.
type failingUserStore struct{ err error }

func (s failingUserStore) LookupVerifier(context.Context, string) (string, error) {
	return "", s.err
}

// rawUserStore returns a fixed encoded verifier for every user.
type rawUserStore struct{ encoded string }

func (s rawUserStore) LookupVerifier(context.Context, string) (string, error) {
	return s.encoded, nil
}

// funcSessionStore lets tests override individual SessionStore methods; nil
// methods fall through to a MemorySessionStore.
type funcSessionStore struct {
	mem     *MemorySessionStore
	save    func(ctx context.Context, id uuid.UUID, data []byte, expiresAt time.Time) error
	consume func(ctx context.Context, id uuid.UUID, now time.Time) ([]byte, error)
}

func (s *funcSessionStore) SaveSession(ctx context.Context, id uuid.UUID, data []byte, expiresAt time.Time) error {
	if s.save != nil {
		return s.save(ctx, id, data, expiresAt)
	}
	return s.mem.SaveSession(ctx, id, data, expiresAt)
}

func (s *funcSessionStore) ConsumeSession(ctx context.Context, id uuid.UUID, now time.Time) ([]byte, error) {
	if s.consume != nil {
		return s.consume(ctx, id, now)
	}
	return s.mem.ConsumeSession(ctx, id, now)
}

// env is a Server wired to memory stores, with users alice and bob.
type env struct {
	t      *testing.T
	srv    *Server
	users  *MemoryUserStore
	clock  *fakeClock
	issuer *fakeIssuer
	client Client
}

const (
	alicePassword = "correct horse battery staple"
	bobPassword   = "hunter2"
)

func newEnv(t *testing.T, opts ...Option) *env {
	t.Helper()
	e := &env{t: t, users: NewMemoryUserStore(), clock: newFakeClock(), issuer: &fakeIssuer{}}
	base := []Option{
		WithGroup(Group2048),
		WithKDFParams(testKDF),
		WithUserStore(e.users),
		WithTokenIssuer(e.issuer),
		WithLogger(discardLogger),
		WithClock(e.clock.Now),
	}
	srv, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.srv = srv
	e.register("alice", alicePassword)
	e.register("bob", bobPassword)
	return e
}

// register stores a verifier created by the client from a server
// registration, as a real client would.
func (e *env) register(username, password string) *Verifier {
	e.t.Helper()
	v, err := e.client.NewVerifier([]byte(password), e.srv.NewRegistration())
	if err != nil {
		e.t.Fatalf("NewVerifier: %v", err)
	}
	if err := e.srv.CheckVerifier(v); err != nil {
		e.t.Fatalf("CheckVerifier: %v", err)
	}
	e.users.SetVerifier(username, v)
	return v
}

// begin starts a login and answers it with password.
func (e *env) begin(username, password string) (*Challenge, *ClientLogin) {
	e.t.Helper()
	ch, err := e.srv.BeginLogin(context.Background(), username)
	if err != nil {
		e.t.Fatalf("BeginLogin(%q): %v", username, err)
	}
	cl, err := e.client.Login(username, []byte(password), ch)
	if err != nil {
		e.t.Fatalf("Login: %v", err)
	}
	return ch, cl
}

// mustHex parses hex written as in the RFCs, with whitespace.
func mustHex(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(strings.Join(strings.Fields(s), ""), 16)
	if !ok {
		t.Fatalf("bad hex %q", s)
	}
	return n
}

package auth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// stubPurger is a RefreshTokenStore and RefreshTokenPurger that counts purge
// calls and returns err from each. If block is set, each call waits for its
// context to be cancelled, after signalling on started.
type stubPurger struct {
	RefreshTokenStore
	calls   atomic.Int32
	err     error
	block   bool
	started chan struct{}
}

func newStubPurger() *stubPurger {
	return &stubPurger{RefreshTokenStore: NewMemoryRefreshTokenStore(), started: make(chan struct{}, 1)}
}

func (p *stubPurger) PurgeExpiredRefreshTokens(ctx context.Context, _ time.Time) (int64, error) {
	p.calls.Add(1)
	if p.block {
		select {
		case p.started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return 0, p.err
}

// syncBuffer is a bytes.Buffer safe for use by a background logger.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// waitFor polls cond until it is true, failing the test after a few seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPurgeExpiredRefreshTokens(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	store := NewMemoryRefreshTokenStore()
	a := newRefreshAuthorizer(t, store, WithClock(clock.Now),
		WithRefreshTokenTTL(time.Hour), WithLeeway(time.Minute), WithRefreshPurgeInterval(0))

	if _, err := a.IssueTokenPair(ctx, "bob", nil); err != nil {
		t.Fatal(err)
	}
	pair, err := a.IssueTokenPair(ctx, "carol", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Logout(ctx, pair.RefreshToken); err != nil { // leaves a revoked family
		t.Fatal(err)
	}

	// Expired but within leeway: nothing may be purged yet.
	clock.Advance(time.Hour + 30*time.Second)
	if n, err := a.PurgeExpiredRefreshTokens(ctx); err != nil || n != 0 {
		t.Errorf("purge within leeway = %d, %v; want 0, nil", n, err)
	}
	if store.Len() != 1 {
		t.Errorf("Len = %d within leeway; want 1", store.Len())
	}

	// Past leeway: bob's record and both families go.
	clock.Advance(time.Minute)
	if n, err := a.PurgeExpiredRefreshTokens(ctx); err != nil || n != 3 {
		t.Errorf("purge = %d, %v; want 3, nil", n, err)
	}
	if store.Len() != 0 {
		t.Errorf("Len = %d after purge; want 0", store.Len())
	}
	if n, err := a.PurgeExpiredRefreshTokens(ctx); err != nil || n != 0 {
		t.Errorf("second purge = %d, %v; want 0, nil", n, err)
	}
}

func TestPurgeExpiredRefreshTokensAfterClose(t *testing.T) {
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore())
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PurgeExpiredRefreshTokens(context.Background()); err != nil {
		t.Errorf("purge after Close: %v", err)
	}
}

func TestPurgeExpiredRefreshTokensErrors(t *testing.T) {
	ctx := context.Background()
	tests := map[string]struct {
		opts []Option
		want error
	}{
		"no store":   {want: ErrNotConfigured},
		"not purger": {opts: []Option{WithRefreshTokenStore(&faultyRefreshStore{RefreshTokenStore: NewMemoryRefreshTokenStore()})}, want: ErrNotConfigured},
		"store fails": {opts: []Option{WithRefreshTokenStore(&stubPurger{
			RefreshTokenStore: NewMemoryRefreshTokenStore(), err: errTest,
		})}, want: errTest},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			a := newTestAuthorizer(t, tc.opts...)
			if _, err := a.PurgeExpiredRefreshTokens(ctx); !errors.Is(err, tc.want) {
				t.Errorf("err = %v; want %v", err, tc.want)
			}
		})
	}
}

func TestBackgroundPurger(t *testing.T) {
	purger := newStubPurger()
	plain := &faultyRefreshStore{RefreshTokenStore: NewMemoryRefreshTokenStore()}
	tests := map[string]struct {
		store    RefreshTokenStore
		interval time.Duration
		want     bool
	}{
		"purger":         {store: purger, interval: time.Hour, want: true},
		"disabled":       {store: purger, interval: 0, want: false},
		"no store":       {interval: time.Hour, want: false},
		"not a purger":   {store: plain, interval: time.Hour, want: false},
		"memory default": {store: NewMemoryRefreshTokenStore(), interval: DefaultConfig().RefreshPurgeInterval, want: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := &settings{Config: Config{RefreshPurgeInterval: tc.interval}, refreshStore: tc.store}
			p, ok := s.backgroundPurger()
			if ok != tc.want || (ok && p == nil) {
				t.Errorf("backgroundPurger() = %v, %v; want ok=%v", p, ok, tc.want)
			}
		})
	}
}

func TestBackgroundPurgeRemovesExpiredRecords(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	store := NewMemoryRefreshTokenStore()
	a := newRefreshAuthorizer(t, store, WithClock(clock.Now),
		WithRefreshTokenTTL(time.Hour), WithRefreshPurgeInterval(time.Millisecond))

	if _, err := a.IssueTokenPair(ctx, "bob", nil); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Hour)
	waitFor(t, "background purge", func() bool { return store.Len() == 0 })
}

func TestBackgroundPurgeRetriesAfterFailure(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := newStubPurger()
	store.err = errTest
	newRefreshAuthorizer(t, store, WithLogger(logger), WithRefreshPurgeInterval(time.Millisecond))

	waitFor(t, "repeated purges", func() bool { return store.calls.Load() >= 2 })
	waitFor(t, "warning", func() bool { return strings.Contains(logs.String(), errTest.Error()) })
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("failure not logged as a warning:\n%s", logs.String())
	}
}

func TestBackgroundPurgeLogsCountAtDebug(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clock := newFakeClock()
	store := NewMemoryRefreshTokenStore()
	a := newRefreshAuthorizer(t, store, WithClock(clock.Now), WithLogger(logger),
		WithRefreshTokenTTL(time.Hour), WithRefreshPurgeInterval(time.Millisecond))

	if _, err := a.IssueTokenPair(context.Background(), "bob", nil); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Hour)
	waitFor(t, "debug log", func() bool { return strings.Contains(logs.String(), "count=2") })
	if !strings.Contains(logs.String(), "level=DEBUG") {
		t.Errorf("count not logged at debug:\n%s", logs.String())
	}
}

func TestBackgroundPurgeDisabled(t *testing.T) {
	store := newStubPurger()
	a := newRefreshAuthorizer(t, store, WithRefreshPurgeInterval(0))
	time.Sleep(20 * time.Millisecond)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if n := store.calls.Load(); n != 0 {
		t.Errorf("purged %d times with purging disabled", n)
	}
}

// Close cancels an in-flight purge, waits for it, and does not log the
// cancellation as a failure.
func TestCloseStopsBackgroundPurge(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := newStubPurger()
	store.block = true
	a := newRefreshAuthorizer(t, store, WithLogger(logger), WithRefreshPurgeInterval(time.Millisecond))

	<-store.started
	closed := make(chan struct{})
	go func() {
		_ = a.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	calls := store.calls.Load()
	time.Sleep(20 * time.Millisecond)
	if store.calls.Load() != calls {
		t.Error("purging continued after Close")
	}
	if logs.String() != "" {
		t.Errorf("unexpected logs:\n%s", logs.String())
	}
}

func TestJitter(t *testing.T) {
	for _, d := range []time.Duration{0, 1, time.Second, time.Hour} {
		lo, hi := d-d/4, d-d/4+d/2
		if d/2 == 0 {
			lo, hi = d, d+1
		}
		for range 1000 {
			if got := jitter(d); got < lo || got >= hi {
				t.Fatalf("jitter(%v) = %v; want in [%v, %v)", d, got, lo, hi)
			}
		}
	}
	seen := map[time.Duration]bool{}
	for range 100 {
		seen[jitter(time.Hour)] = true
	}
	if len(seen) < 2 {
		t.Error("jitter is not random")
	}
}

func TestMemoryRefreshStorePurge(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	s := NewMemoryRefreshTokenStore()
	live, dead := uuid.New(), uuid.New()
	revoked := uuid.New()
	add := func(family, parent uuid.UUID, exp time.Time) uuid.UUID {
		t.Helper()
		id := uuid.New()
		rec := RefreshTokenRecord{ID: id, ParentID: parent, FamilyID: family, Subject: "bob", IssuedAt: now, ExpiresAt: exp}
		if err := s.CreateRefreshToken(ctx, rec); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := add(live, uuid.Nil, now.Add(time.Minute))
	add(live, first, now.Add(time.Hour)) // keeps the family alive
	add(dead, uuid.Nil, now.Add(time.Minute))
	add(revoked, uuid.Nil, now.Add(time.Hour))
	if err := s.RevokeRefreshTokenFamily(ctx, revoked); err != nil {
		t.Fatal(err)
	}

	// At exactly ExpiresAt a record is still kept.
	if n, _ := s.PurgeExpiredRefreshTokens(ctx, now.Add(time.Minute)); n != 0 {
		t.Errorf("purge at expiry removed %d; want 0", n)
	}
	// First live record, the dead record, and the dead family.
	if n, err := s.PurgeExpiredRefreshTokens(ctx, now.Add(2*time.Minute)); err != nil || n != 3 {
		t.Errorf("purge = %d, %v; want 3, nil", n, err)
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d; want 1", s.Len())
	}
	// The revoked family's tombstone survives until it expires.
	rec := RefreshTokenRecord{ID: uuid.New(), ParentID: uuid.New(), FamilyID: revoked, Subject: "bob", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateRefreshToken(ctx, rec); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("continuing revoked family: %v; want ErrTokenRevoked", err)
	}
	if n, _ := s.PurgeExpiredRefreshTokens(ctx, now.Add(2*time.Hour)); n != 3 {
		t.Errorf("final purge removed %d; want 3 (record and two families)", n)
	}
}

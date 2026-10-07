package auth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

	// Records are kept through the leeway and then the purge margin.
	for _, d := range []time.Duration{
		time.Hour + 30*time.Second,                   // expired, within leeway
		time.Hour + time.Minute + refreshPurgeMargin, // exactly at the end of the margin
	} {
		at := clock.Now()
		clock.Advance(d)
		if n, err := a.PurgeExpiredRefreshTokens(ctx); err != nil || n != 0 {
			t.Errorf("purge %v after issue = %d, %v; want 0, nil", d, n, err)
		}
		if store.Len() != 1 {
			t.Errorf("Len = %d %v after issue; want 1", store.Len(), d)
		}
		clock.Advance(at.Sub(clock.Now()))
	}

	// Past the margin: bob's record and both families go.
	clock.Advance(time.Hour + time.Minute + refreshPurgeMargin + time.Second)
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

// A refresh accepted at the last moment completes even if another instance,
// whose clock is ahead, purges between consuming the old token and storing
// the new one.
func TestPurgeDuringLastMomentRefresh(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	inner := NewMemoryRefreshTokenStore()
	store := &purgeOnCreateStore{MemoryRefreshTokenStore: inner}
	a := newRefreshAuthorizer(t, store, WithClock(clock.Now),
		WithRefreshTokenTTL(time.Hour), WithRefreshPurgeInterval(0))
	other := newRefreshAuthorizer(t, inner, WithClock(func() time.Time { return clock.Now().Add(time.Minute) }),
		WithRefreshPurgeInterval(0))
	store.purge = func() {
		if _, err := other.PurgeExpiredRefreshTokens(ctx); err != nil {
			t.Error(err)
		}
	}

	pair, err := a.IssueTokenPair(ctx, "bob", nil)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Hour - time.Second) // the token's last valid moment
	store.armed.Store(true)
	if _, err := a.Refresh(ctx, pair.RefreshToken); err != nil {
		t.Errorf("last-moment refresh: %v", err)
	}
}

// purgeOnCreateStore runs purge before each refresh's CreateRefreshToken
// once armed, simulating a purge racing the refresh.
type purgeOnCreateStore struct {
	*MemoryRefreshTokenStore
	armed atomic.Bool
	purge func()
}

func (s *purgeOnCreateStore) CreateRefreshToken(ctx context.Context, rec RefreshTokenRecord) error {
	if rec.ParentID != uuid.Nil && s.armed.Load() {
		s.purge()
	}
	return s.MemoryRefreshTokenStore.CreateRefreshToken(ctx, rec)
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

// newPurgeLoopAuthorizer returns an Authorizer that purges store every hour,
// for use inside a synctest bubble. It is closed when the test ends.
func newPurgeLoopAuthorizer(t *testing.T, store RefreshTokenStore, opts ...Option) *Authorizer {
	t.Helper()
	base := []Option{WithRefreshTokenStore(store), WithLogger(discardLogger),
		WithRefreshTokenTTL(time.Hour), WithRefreshPurgeInterval(time.Hour)}
	a, err := New(t.Context(), append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// The first purge runs within the jitter window around the interval, and
// later ones keep running.
func TestBackgroundPurgeSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := newStubPurger()
		newPurgeLoopAuthorizer(t, store)

		time.Sleep(45*time.Minute - time.Nanosecond)
		synctest.Wait()
		if n := store.calls.Load(); n != 0 {
			t.Fatalf("purged %d times before 0.75 intervals", n)
		}
		time.Sleep(30 * time.Minute)
		synctest.Wait()
		if n := store.calls.Load(); n != 1 {
			t.Fatalf("purged %d times by 1.25 intervals; want 1", n)
		}
		time.Sleep(10 * time.Hour)
		synctest.Wait()
		if n := store.calls.Load(); n < 8 || n > 15 {
			t.Errorf("purged %d times in 11h15m; want 8-15", n)
		}
	})
}

func TestBackgroundPurgeRemovesExpiredRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := NewMemoryRefreshTokenStore()
		a := newPurgeLoopAuthorizer(t, store)
		if _, err := a.IssueTokenPair(t.Context(), "bob", nil); err != nil {
			t.Fatal(err)
		}
		// Expiry, the margin, and up to 1.25 intervals until the next purge.
		time.Sleep(time.Hour + refreshPurgeMargin + 75*time.Minute)
		synctest.Wait()
		if store.Len() != 0 {
			t.Errorf("Len = %d; want 0", store.Len())
		}
	})
}

func TestBackgroundPurgeRetriesAfterFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		store := newStubPurger()
		store.err = errTest
		newPurgeLoopAuthorizer(t, store, WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))

		time.Sleep(3 * time.Hour)
		synctest.Wait()
		if n := store.calls.Load(); n < 2 {
			t.Errorf("purged %d times after failures; want at least 2", n)
		}
		if out := logs.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, errTest.Error()) {
			t.Errorf("failure not logged as a warning:\n%s", out)
		}
	})
}

func TestBackgroundPurgeLogsCountAtDebug(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		a := newPurgeLoopAuthorizer(t, NewMemoryRefreshTokenStore(), WithLogger(logger))
		if _, err := a.IssueTokenPair(t.Context(), "bob", nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Hour)
		synctest.Wait()
		if out := logs.String(); !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "count=2") {
			t.Errorf("count not logged at debug:\n%s", out)
		}
	})
}

// With the interval set to 0, no purge runs however long the Authorizer
// lives, though the store supports purging.
func TestBackgroundPurgeDisabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := newStubPurger()
		newPurgeLoopAuthorizer(t, store, WithRefreshPurgeInterval(0))
		time.Sleep(1000 * time.Hour)
		synctest.Wait()
		if n := store.calls.Load(); n != 0 {
			t.Errorf("purged %d times with purging disabled", n)
		}
	})
}

// Close cancels an in-flight purge, waits for it, and does not log the
// cancellation as a failure.
func TestCloseStopsBackgroundPurge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		store := newStubPurger()
		store.block = true
		a := newPurgeLoopAuthorizer(t, store, WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))

		time.Sleep(2 * time.Hour)
		synctest.Wait()
		select {
		case <-store.started:
		default:
			t.Fatal("purge did not start")
		}
		if err := a.Close(); err != nil { // returns only once the purge has stopped
			t.Fatal(err)
		}
		calls := store.calls.Load()
		time.Sleep(100 * time.Hour)
		synctest.Wait()
		if store.calls.Load() != calls {
			t.Error("purging continued after Close")
		}
		if logs.String() != "" {
			t.Errorf("unexpected logs:\n%s", logs.String())
		}
	})
}

func TestJitter(t *testing.T) {
	for _, d := range []time.Duration{0, 1, time.Second, time.Hour, maxJitterBase} {
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
	// Larger durations are capped rather than overflowing.
	for _, d := range []time.Duration{maxJitterBase + 1, math.MaxInt64} {
		for range 1000 {
			if got := jitter(d); got < maxJitterBase-maxJitterBase/4 {
				t.Fatalf("jitter(%v) = %v; want at least %v", d, got, maxJitterBase-maxJitterBase/4)
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

// CreateRefreshToken purges at most once per memoryPurgeInterval, and keeps
// records for refreshPurgeMargin past expiry.
func TestMemoryRefreshStoreRateLimitsPurge(t *testing.T) {
	ctx := context.Background()
	start := time.Now().Truncate(time.Second)
	s := NewMemoryRefreshTokenStore()
	create := func(after, ttl time.Duration, wantLen int) {
		t.Helper()
		at := start.Add(after)
		rec := RefreshTokenRecord{ID: uuid.New(), FamilyID: uuid.New(), Subject: "bob", IssuedAt: at, ExpiresAt: at.Add(ttl)}
		if err := s.CreateRefreshToken(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if s.Len() != wantLen {
			t.Errorf("Len = %d after create at +%v; want %d", s.Len(), after, wantLen)
		}
	}
	short := 30 * time.Second // expires at +31s, purgeable from +31s+margin
	create(0, time.Hour, 1)   // first create purges
	create(time.Second, short, 2)
	// Purges, but the short record is still within the margin.
	create(refreshPurgeMargin, time.Hour, 3)
	// Past the short record's margin, but under a minute since the last purge.
	create(refreshPurgeMargin+memoryPurgeInterval-time.Second, time.Hour, 4)
	// A minute after the last purge: the short record goes.
	create(refreshPurgeMargin+memoryPurgeInterval, time.Hour, 4)
}

// If the clock moves backwards, CreateRefreshToken keeps purging rather than
// waiting for the clock to pass the previous purge again.
func TestMemoryRefreshStorePurgesAfterClockRewind(t *testing.T) {
	ctx := context.Background()
	start := time.Now().Truncate(time.Second)
	s := NewMemoryRefreshTokenStore()
	create := func(after, ttl time.Duration, wantLen int) {
		t.Helper()
		at := start.Add(after)
		rec := RefreshTokenRecord{ID: uuid.New(), FamilyID: uuid.New(), Subject: "bob", IssuedAt: at, ExpiresAt: at.Add(ttl)}
		if err := s.CreateRefreshToken(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if s.Len() != wantLen {
			t.Errorf("Len = %d after create at %+v; want %d", s.Len(), after, wantLen)
		}
	}
	year := 365 * 24 * time.Hour
	create(0, time.Hour, 1)
	create(year, time.Hour, 1)           // clock jumps ahead a year; purges the first
	create(0, time.Second, 2)            // clock set back
	create(10*time.Minute, time.Hour, 2) // purges the short record
}

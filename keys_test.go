package auth

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// nextID returns the ID of the pre-generated next key, or uuid.Nil.
func (km *keyManager) nextID() uuid.UUID {
	km.rotMu.Lock()
	defer km.rotMu.Unlock()
	if km.next == nil {
		return uuid.Nil
	}
	return km.next.id
}

func TestNewStoresCurrentAndNextKeys(t *testing.T) {
	clock := newFakeClock()
	keys := NewMemoryKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys), WithClock(clock.Now),
		WithKeyRotationInterval(time.Hour), WithAccessTokenTTL(time.Minute), WithRefreshTokenTTL(24*time.Hour))

	cur := storedKey(t, keys, a.keys.current.Load().id)
	next := storedKey(t, keys, a.keys.nextID())
	if cur == nil || next == nil {
		t.Fatalf("current %v / next %v not stored", cur, next)
	}
	retention := 24*time.Hour + keyRetentionMargin
	if want := clock.Now().Add(time.Hour + retention); !cur.ExpiresAt.Equal(want) {
		t.Errorf("current ExpiresAt = %v; want %v", cur.ExpiresAt, want)
	}
	// The next key starts signing one interval from now, so it is retained
	// one interval longer.
	if want := clock.Now().Add(2*time.Hour + retention); !next.ExpiresAt.Equal(want) {
		t.Errorf("next ExpiresAt = %v; want %v", next.ExpiresAt, want)
	}
	set, _ := a.JWKS(context.Background())
	if len(set.Keys) != 2 {
		t.Errorf("JWKS has %d keys; want current and next", len(set.Keys))
	}
}

// Very large (but valid) durations must not overflow when summed into a
// key's retention.
func TestKeyRetentionDoesNotOverflow(t *testing.T) {
	const year = 365 * 24 * time.Hour
	keys := NewMemoryKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys), WithRefreshTokenTTL(200*year), WithLeeway(100*year))
	k := storedKey(t, keys, a.keys.current.Load().id)
	if want := k.CreatedAt.Add(200 * year).Add(100 * year); k.ExpiresAt.Before(want) {
		t.Errorf("ExpiresAt = %v; want after %v", k.ExpiresAt, want)
	}
}

func TestKeysNeverExpireWithoutRotation(t *testing.T) {
	keys := NewMemoryKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys), WithKeyRotationInterval(0))
	list, _ := keys.ListKeys(context.Background())
	if len(list) != 1 || !list[0].ExpiresAt.IsZero() {
		t.Errorf("keys = %+v; want one key that never expires", list)
	}
	if a.keys.nextID() != uuid.Nil {
		t.Error("next key generated with rotation disabled")
	}
}

func TestNewFailsWhenKeyCannotBeStored(t *testing.T) {
	keys := newFaultyKeyStore()
	keys.fail(&keys.storeErr, errTest)
	if _, err := New(context.Background(), WithKeyStore(keys)); !errors.Is(err, errTest) {
		t.Errorf("err = %v; want errTest", err)
	}
}

func TestNewFailsWhenNextKeyCannotBeStored(t *testing.T) {
	keys := &failAfterStore{KeyStore: NewMemoryKeyStore(), ok: 1}
	if _, err := New(context.Background(), WithKeyStore(keys)); !errors.Is(err, errTest) {
		t.Errorf("err = %v; want errTest", err)
	}
}

// failAfterStore fails every StoreKey call after the first ok calls.
type failAfterStore struct {
	KeyStore
	ok int
}

func (f *failAfterStore) StoreKey(ctx context.Context, k *VerificationKey) error {
	if f.ok == 0 {
		return errTest
	}
	f.ok--
	return f.KeyStore.StoreKey(ctx, k)
}

func TestCleanupSkipsMalformedKeys(t *testing.T) {
	keys := newFaultyKeyStore()
	keys.extra = []*VerificationKey{nil, {ID: uuid.New()}}
	a := newTestAuthorizer(t, WithKeyStore(keys)) // New runs cleanup
	if err := a.keys.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewToleratesCleanupFailure(t *testing.T) {
	keys := newFaultyKeyStore()
	keys.fail(&keys.listErr, errTest)
	newTestAuthorizer(t, WithKeyStore(keys))
}

func TestRotationUsesPregeneratedKey(t *testing.T) {
	ctx := context.Background()
	a := newTestAuthorizer(t)
	before, _ := a.IssueAccessToken("bob", nil)
	next := a.keys.nextID()

	if err := a.keys.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := a.keys.current.Load().id; got != next {
		t.Fatalf("current = %s; want pre-generated %s", got, next)
	}
	if a.keys.nextID() != uuid.Nil {
		t.Error("next key not cleared after rotation")
	}
	after, _ := a.IssueAccessToken("bob", nil)
	for _, tok := range []string{before, after} {
		if _, err := a.VerifyAccessToken(ctx, tok); err != nil {
			t.Errorf("verify after rotation: %v", err)
		}
	}
}

func TestRotateWithoutPregeneratedKey(t *testing.T) {
	ctx := context.Background()
	keys := newFaultyKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys))
	if err := a.keys.rotate(ctx); err != nil { // uses up the next key
		t.Fatal(err)
	}
	cur := a.keys.current.Load().id

	keys.fail(&keys.storeErr, errTest)
	if err := a.keys.rotate(ctx); !errors.Is(err, errTest) {
		t.Errorf("err = %v; want errTest", err)
	}
	if a.keys.current.Load().id != cur {
		t.Error("current key changed although no new key could be stored")
	}

	keys.fail(&keys.storeErr, nil)
	if err := a.keys.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if a.keys.current.Load().id == cur || storedKey(t, keys, a.keys.current.Load().id) == nil {
		t.Error("rotation did not generate and store a fresh key")
	}
}

func TestCleanup(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := newFaultyKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys), WithClock(clock.Now), WithKeyRotationInterval(time.Hour))
	oldTok, _ := a.IssueAccessToken("bob", nil)
	if err := a.keys.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.keys.ensureNext(ctx, clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Long after everything expired, cleanup removes the old key but never
	// the current or next key, even though they are past ExpiresAt.
	clock.Advance(365 * 24 * time.Hour)
	if err := a.keys.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := keys.ListKeys(ctx)
	if len(list) != 2 || storedKey(t, keys, a.keys.current.Load().id) == nil || storedKey(t, keys, a.keys.nextID()) == nil {
		t.Errorf("remaining keys = %v; want only current and next", list)
	}
	if len(a.keys.known) != 2 {
		t.Errorf("in-memory set holds %d keys; want 2", len(a.keys.known))
	}
	clock.Advance(-365 * 24 * time.Hour)
	if _, err := a.VerifyAccessToken(ctx, oldTok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token signed by deleted key: err = %v", err)
	}

	keys.fail(&keys.listErr, errTest)
	if err := a.keys.cleanup(ctx); !errors.Is(err, errTest) {
		t.Errorf("list failure: err = %v", err)
	}
	keys.fail(&keys.listErr, nil)
	if err := a.keys.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	clock.Advance(365 * 24 * time.Hour)
	keys.fail(&keys.deleteErr, errTest)
	if err := a.keys.cleanup(ctx); !errors.Is(err, errTest) {
		t.Errorf("delete failure: err = %v", err)
	}
}

// otherInstance returns another Authorizer sharing keys, to exercise lookups
// of keys that are not the verifier's own current key.
func otherInstance(t *testing.T, keys KeyStore, opts ...Option) *Authorizer {
	return newTestAuthorizer(t, append([]Option{WithKeyStore(keys)}, opts...)...)
}

func TestLookupCachesKeySet(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := newFaultyKeyStore()
	issuer := otherInstance(t, keys, WithClock(clock.Now))
	verifier := otherInstance(t, keys, WithClock(clock.Now), WithKeyCacheTTL(time.Minute))
	tok, _ := issuer.IssueAccessToken("bob", nil)
	base := keys.listCalls.Load()

	for range 3 {
		if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if n := keys.listCalls.Load() - base; n != 1 {
		t.Errorf("ListKeys called %d times; want 1 (cached)", n)
	}
	clock.Advance(time.Minute)
	if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if n := keys.listCalls.Load() - base; n != 2 {
		t.Errorf("ListKeys called %d times; want 2 after KeyCacheTTL", n)
	}
}

// A rotated-in key was stored an interval earlier, so a verifier that has
// loaded the key set since then knows it without another store call.
func TestPregeneratedKeyIsKnownBeforeUse(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := newFaultyKeyStore()
	issuer := otherInstance(t, keys, WithClock(clock.Now))
	verifier := otherInstance(t, keys, WithClock(clock.Now))
	first, _ := issuer.IssueAccessToken("bob", nil)
	if _, err := verifier.VerifyAccessToken(ctx, first); err != nil {
		t.Fatal(err)
	}
	base := keys.listCalls.Load()

	if err := issuer.keys.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	second, _ := issuer.IssueAccessToken("bob", nil)
	if _, err := verifier.VerifyAccessToken(ctx, second); err != nil {
		t.Fatal(err)
	}
	if n := keys.listCalls.Load() - base; n != 0 {
		t.Errorf("ListKeys called %d times; the pre-published key should already be known", n)
	}
}

func TestUnknownKeyIDsAreRateLimited(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := newFaultyKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys), WithClock(clock.Now))
	now := clock.Now().Unix()
	forged := func() string {
		mc := jwt.MapClaims{"sub": "bob", "iat": now, "exp": now + 60, "jti": uuid.NewString(), "typ": "access"}
		return signRaw(t, a, mc, map[string]any{"kid": uuid.NewString()})
	}
	base := keys.listCalls.Load()

	for range 50 {
		if _, err := a.VerifyAccessToken(ctx, forged()); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v; want ErrInvalidToken", err)
		}
	}
	if n := keys.listCalls.Load() - base; n != 1 {
		t.Errorf("ListKeys called %d times for 50 unknown kids; want 1", n)
	}
	clock.Advance(keyRefreshMinInterval)
	_, _ = a.VerifyAccessToken(ctx, forged())
	if n := keys.listCalls.Load() - base; n != 2 {
		t.Errorf("ListKeys called %d times after the rate-limit interval; want 2", n)
	}
}

// A brand-new instance's first key is found by the reload triggered by the
// unknown kid.
func TestNewInstanceKeyFoundOnMiss(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := NewMemoryKeyStore()
	verifier := otherInstance(t, keys, WithClock(clock.Now))
	early := otherInstance(t, keys, WithClock(clock.Now))
	tok, _ := early.IssueAccessToken("bob", nil)
	if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	clock.Advance(keyRefreshMinInterval)
	late := otherInstance(t, keys, WithClock(clock.Now))
	tok, _ = late.IssueAccessToken("bob", nil)
	if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
		t.Errorf("new instance's token rejected: %v", err)
	}
}

func TestLookupStoreFailure(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := newFaultyKeyStore()
	issuer := otherInstance(t, keys, WithClock(clock.Now))
	verifier := otherInstance(t, keys, WithClock(clock.Now), WithKeyCacheTTL(time.Minute))
	tok, _ := issuer.IssueAccessToken("bob", nil)

	keys.fail(&keys.listErr, errTest)
	for i := range 2 { // the second call is rate-limited but reports the same failure
		_, err := verifier.VerifyAccessToken(ctx, tok)
		if !errors.Is(err, errTest) || errors.Is(err, ErrInvalidToken) {
			t.Errorf("call %d: err = %v; want internal errTest", i, err)
		}
	}

	// Once the key is known, a store outage does not break verification.
	keys.fail(&keys.listErr, nil)
	clock.Advance(keyRefreshMinInterval)
	if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	keys.fail(&keys.listErr, errTest)
	clock.Advance(time.Minute)
	if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
		t.Errorf("known key rejected during store outage: %v", err)
	}
}

func TestLookupSkipsMalformedStoredKeys(t *testing.T) {
	ctx := context.Background()
	keys := newFaultyKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys))
	id := uuid.New()
	keys.mu.Lock()
	keys.extra = []*VerificationKey{nil, {ID: id}}
	keys.mu.Unlock()
	mc := jwt.MapClaims{"sub": "bob", "iat": time.Now().Unix(), "exp": time.Now().Unix() + 60, "jti": uuid.NewString(), "typ": "access"}
	if _, err := a.VerifyAccessToken(ctx, signRaw(t, a, mc, map[string]any{"kid": id.String()})); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v; want ErrInvalidToken", err)
	}
}

// The current key's stored expiry is honored even if rotation has stalled.
func TestCurrentKeyExpiry(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithClock(clock.Now), WithKeyRotationInterval(time.Hour))
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	cur := a.keys.current.Load()
	clock.Advance(cur.expiresAt.Sub(clock.Now()))
	if err := a.Logout(ctx, pair.RefreshToken); err != nil {
		t.Errorf("logout at the key's expiry: %v", err)
	}
	clock.Advance(time.Second)
	if _, err := a.keys.lookup(ctx, cur.id); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired current key accepted: %v", err)
	}
	if err := a.Logout(ctx, pair.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("logout with a token signed by the expired current key: err = %v", err)
	}
}

func TestLookupExpiredKey(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := NewMemoryKeyStore()
	issuer := otherInstance(t, keys, WithClock(clock.Now), WithKeyRotationInterval(time.Hour))
	verifier := otherInstance(t, keys, WithClock(clock.Now), WithLeeway(1000*time.Hour))
	tok, _ := issuer.IssueAccessToken("bob", nil)
	clock.Advance(time.Hour + 7*24*time.Hour + keyRetentionMargin + time.Second)
	if _, err := verifier.VerifyAccessToken(ctx, tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v; want ErrInvalidToken", err)
	}
}

// The rotation loop can fall behind, e.g. while the process is suspended.
// Signing must never use a key past the window its stored expiry covers.
func TestSignerRotatesOverdueKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("promotes pre-generated key", func(t *testing.T) {
		clock := newFakeClock()
		a := newTestAuthorizer(t, WithClock(clock.Now), WithKeyRotationInterval(time.Hour))
		next := a.keys.nextID()
		clock.Advance(time.Hour + keyRetentionMargin) // last instant the old key is covered
		if _, err := a.IssueAccessToken("bob", nil); err != nil || a.keys.nextID() != next {
			t.Fatalf("rotated too early: err %v", err)
		}
		clock.Advance(time.Second)
		tok, err := a.IssueAccessToken("bob", nil)
		if err != nil {
			t.Fatal(err)
		}
		if a.keys.current.Load().id != next {
			t.Error("overdue key was not replaced by the pre-generated key")
		}
		if _, err := a.VerifyAccessToken(ctx, tok); err != nil {
			t.Error(err)
		}
	})

	t.Run("replaces stale pre-generated key", func(t *testing.T) {
		clock := newFakeClock()
		a := newTestAuthorizer(t, WithClock(clock.Now), WithKeyRotationInterval(time.Hour))
		next := a.keys.nextID()
		clock.Advance(3 * time.Hour) // past the next key's window too
		if _, err := a.IssueAccessToken("bob", nil); err != nil {
			t.Fatal(err)
		}
		cur := a.keys.current.Load()
		if cur.id == next || !cur.usable(clock.Now()) {
			t.Error("stale pre-generated key was promoted")
		}
	})

	t.Run("fails closed when no key can be stored", func(t *testing.T) {
		clock := newFakeClock()
		keys := newFaultyKeyStore()
		a := newTestAuthorizer(t, WithClock(clock.Now), WithKeyStore(keys), WithKeyRotationInterval(time.Hour))
		clock.Advance(3 * time.Hour)
		keys.fail(&keys.storeErr, errTest)
		if _, err := a.IssueAccessToken("bob", nil); !errors.Is(err, errTest) {
			t.Errorf("err = %v; want errTest", err)
		}
	})

	t.Run("no window without rotation", func(t *testing.T) {
		clock := newFakeClock()
		a := newTestAuthorizer(t, WithClock(clock.Now), WithKeyRotationInterval(0))
		first := a.keys.current.Load().id
		clock.Advance(365 * 24 * time.Hour)
		if _, err := a.IssueAccessToken("bob", nil); err != nil || a.keys.current.Load().id != first {
			t.Errorf("key rotated without rotation enabled: %v", err)
		}
	})
}

func newLoopAuthorizer(t *testing.T, keys KeyStore) *Authorizer {
	a, err := New(t.Context(), WithKeyStore(keys), WithLogger(discardLogger),
		WithKeyRotationInterval(time.Hour), WithAccessTokenTTL(time.Minute), WithRefreshTokenTTL(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRotationLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		keys := NewMemoryKeyStore()
		a := newLoopAuthorizer(t, keys)
		first, next := a.keys.current.Load().id, a.keys.nextID()

		time.Sleep(time.Hour)
		synctest.Wait()
		if got := a.keys.current.Load().id; got != next {
			t.Fatalf("after one interval current = %s; want pre-generated %s", got, next)
		}
		if n := a.keys.nextID(); n == uuid.Nil || n == next {
			t.Error("a new next key was not pre-generated")
		}

		// After the first key's retention window, a rotation deletes it.
		time.Sleep(time.Hour)
		synctest.Wait()
		if storedKey(t, keys, first) != nil {
			t.Error("first key still stored")
		}
		if storedKey(t, keys, next) == nil {
			t.Error("second key deleted too early")
		}

		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		if err := a.Close(); err != nil {
			t.Fatal("second Close:", err)
		}
	})
}

// A store outage at rotation time does not delay rotation, because the next
// key was stored an interval earlier.
func TestRotationLoopSurvivesStoreOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		keys := newFaultyKeyStore()
		a := newLoopAuthorizer(t, keys)
		defer a.Close()
		next := a.keys.nextID()

		keys.fail(&keys.storeErr, errTest)
		time.Sleep(time.Hour)
		synctest.Wait()
		if a.keys.current.Load().id != next {
			t.Fatal("rotation did not use the pre-generated key")
		}
		if a.keys.nextID() != uuid.Nil {
			t.Fatal("next key reported although storing it failed")
		}

		keys.fail(&keys.storeErr, nil)
		time.Sleep(rotationRetryDelay)
		synctest.Wait()
		if a.keys.nextID() == uuid.Nil {
			t.Error("next key was not regenerated after rotationRetryDelay")
		}
	})
}

func TestRotationLoopRetriesWhenNoKeyAvailable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		keys := newFaultyKeyStore()
		a := newLoopAuthorizer(t, keys)
		defer a.Close()

		keys.fail(&keys.storeErr, errTest)
		time.Sleep(2 * time.Hour) // first rotation uses next; the second has nothing
		synctest.Wait()
		stuck := a.keys.current.Load().id

		keys.fail(&keys.storeErr, nil)
		time.Sleep(rotationRetryDelay)
		synctest.Wait()
		if a.keys.current.Load().id == stuck {
			t.Error("rotation was not retried after rotationRetryDelay")
		}
	})
}

func TestRotationLoopLogsCleanupFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		keys := newFaultyKeyStore()
		a := newLoopAuthorizer(t, keys)
		defer a.Close()
		first := a.keys.current.Load().id
		keys.fail(&keys.listErr, errTest)
		time.Sleep(time.Hour)
		synctest.Wait()
		if a.keys.current.Load().id == first {
			t.Error("cleanup failure prevented rotation")
		}
	})
}

func TestJWK(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := uuid.New()
	jwk, err := newJWK(id, &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.KeyType != "EC" || jwk.Curve != "P-256" || jwk.Algorithm != "ES256" || jwk.Use != "sig" || jwk.KeyID != id.String() {
		t.Errorf("unexpected JWK metadata %+v", jwk)
	}
	x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	y, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
	point := append(append([]byte{4}, x...), y...)
	rebuilt, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := priv.PublicKey.ECDH()
	if !rebuilt.Equal(want) {
		t.Error("JWK coordinates do not match the key")
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := newJWK(id, &p384.PublicKey); err == nil {
		t.Error("expected error for P-384 key")
	}
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParsePublicKey(der); err == nil {
		t.Error("ParsePublicKey accepted a P-384 key")
	}
}

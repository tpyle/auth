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

	"github.com/google/uuid"
)

func TestFirstKeyIsStoredWithExpiry(t *testing.T) {
	clock := newFakeClock()
	keys := NewMemoryKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys), WithClock(clock.Now),
		WithKeyRotationInterval(time.Hour), WithAccessTokenTTL(time.Minute), WithRefreshTokenTTL(24*time.Hour))

	stored, err := keys.GetKey(context.Background(), a.keys.current.Load().id)
	if err != nil {
		t.Fatalf("current key not in store: %v", err)
	}
	want := clock.Now().Add(time.Hour + 24*time.Hour + keyRetentionMargin)
	if !stored.ExpiresAt.Equal(want) || !stored.CreatedAt.Equal(clock.Now()) {
		t.Errorf("CreatedAt %v ExpiresAt %v; want %v, %v", stored.CreatedAt, stored.ExpiresAt, clock.Now(), want)
	}
}

func TestKeysNeverExpireWithoutRotation(t *testing.T) {
	keys := NewMemoryKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys), WithKeyRotationInterval(0))
	stored, _ := keys.GetKey(context.Background(), a.keys.current.Load().id)
	if !stored.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v; want zero", stored.ExpiresAt)
	}
}

func TestNewFailsWhenKeyCannotBeStored(t *testing.T) {
	keys := newFaultyKeyStore()
	keys.fail(&keys.storeErr, errTest)
	if _, err := New(context.Background(), WithKeyStore(keys)); !errors.Is(err, errTest) {
		t.Errorf("err = %v; want errTest", err)
	}
}

func TestNewToleratesCleanupFailure(t *testing.T) {
	keys := newFaultyKeyStore()
	keys.fail(&keys.listErr, errTest)
	newTestAuthorizer(t, WithKeyStore(keys))
}

func TestRotationKeepsOldTokensValid(t *testing.T) {
	a := newTestAuthorizer(t)
	ctx := context.Background()
	before, _ := a.IssueAccessToken("bob", nil)
	oldID := a.keys.current.Load().id

	if err := a.keys.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if a.keys.current.Load().id == oldID {
		t.Fatal("rotate did not change the current key")
	}
	after, _ := a.IssueAccessToken("bob", nil)
	for _, tok := range []string{before, after} {
		if _, err := a.VerifyAccessToken(ctx, tok); err != nil {
			t.Errorf("verify after rotation: %v", err)
		}
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

	// Long after everything expired, cleanup removes the old key but never
	// the current one, even though it is past its own ExpiresAt.
	clock.Advance(365 * 24 * time.Hour)
	if err := a.keys.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := keys.ListKeys(ctx)
	if len(list) != 1 || list[0].ID != a.keys.current.Load().id {
		t.Errorf("remaining keys = %v; want only the current key", list)
	}
	if len(a.keys.cache) != 0 {
		t.Errorf("cache still holds %d expired keys", len(a.keys.cache))
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

// otherInstance returns a second Authorizer sharing keys, to exercise lookups
// of keys that are not the verifier's own current key.
func otherInstance(t *testing.T, keys KeyStore, opts ...Option) *Authorizer {
	return newTestAuthorizer(t, append([]Option{WithKeyStore(keys)}, opts...)...)
}

func TestLookupFromStoreAndCache(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := newFaultyKeyStore()
	issuer := otherInstance(t, keys, WithClock(clock.Now))
	verifier := otherInstance(t, keys, WithClock(clock.Now), WithKeyCacheTTL(time.Minute))
	tok, _ := issuer.IssueAccessToken("bob", nil)

	for range 3 {
		if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if n := keys.getCalls.Load(); n != 1 {
		t.Errorf("GetKey called %d times; want 1 (cached)", n)
	}
	clock.Advance(time.Minute)
	if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if n := keys.getCalls.Load(); n != 2 {
		t.Errorf("GetKey called %d times; want 2 after cache TTL", n)
	}
}

func TestLookupWithoutCache(t *testing.T) {
	ctx := context.Background()
	keys := newFaultyKeyStore()
	issuer := otherInstance(t, keys)
	verifier := otherInstance(t, keys, WithKeyCacheTTL(0))
	tok, _ := issuer.IssueAccessToken("bob", nil)
	for range 2 {
		if _, err := verifier.VerifyAccessToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if n := keys.getCalls.Load(); n != 2 {
		t.Errorf("GetKey called %d times; want 2", n)
	}
}

func TestLookupErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("store failure is internal", func(t *testing.T) {
		keys := newFaultyKeyStore()
		issuer := otherInstance(t, keys)
		verifier := otherInstance(t, keys)
		tok, _ := issuer.IssueAccessToken("bob", nil)
		keys.fail(&keys.getErr, errTest)
		_, err := verifier.VerifyAccessToken(ctx, tok)
		if !errors.Is(err, errTest) || errors.Is(err, ErrInvalidToken) {
			t.Errorf("err = %v; want internal errTest", err)
		}
	})

	t.Run("store returns nil key", func(t *testing.T) {
		keys := newFaultyKeyStore()
		issuer := otherInstance(t, keys)
		verifier := otherInstance(t, keys)
		tok, _ := issuer.IssueAccessToken("bob", nil)
		keys.nilGet = true
		if _, err := verifier.VerifyAccessToken(ctx, tok); err == nil || errors.Is(err, ErrInvalidToken) {
			t.Errorf("err = %v; want internal error", err)
		}
	})

	t.Run("expired key", func(t *testing.T) {
		clock := newFakeClock()
		keys := NewMemoryKeyStore()
		issuer := otherInstance(t, keys, WithClock(clock.Now), WithKeyRotationInterval(time.Hour))
		verifier := otherInstance(t, keys, WithClock(clock.Now), WithLeeway(1000*time.Hour))
		tok, _ := issuer.IssueAccessToken("bob", nil)
		clock.Advance(time.Hour + 7*24*time.Hour + keyRetentionMargin + time.Second)
		if _, err := verifier.VerifyAccessToken(ctx, tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("err = %v; want ErrInvalidToken", err)
		}
	})
}

func TestRotationLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		keys := NewMemoryKeyStore()
		a, err := New(t.Context(), WithKeyStore(keys), WithLogger(discardLogger),
			WithKeyRotationInterval(time.Hour), WithAccessTokenTTL(time.Minute), WithRefreshTokenTTL(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		first := a.keys.current.Load().id

		time.Sleep(time.Hour + time.Second)
		synctest.Wait()
		second := a.keys.current.Load().id
		if second == first {
			t.Fatal("key was not rotated after one interval")
		}

		// After the first key's retention window, a rotation deletes it.
		time.Sleep(time.Hour)
		synctest.Wait()
		if _, err := keys.GetKey(context.Background(), first); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("first key still stored: %v", err)
		}
		if _, err := keys.GetKey(context.Background(), second); err != nil {
			t.Errorf("second key deleted too early: %v", err)
		}

		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		if err := a.Close(); err != nil {
			t.Fatal("second Close:", err)
		}
	})
}

func TestRotationLoopRetriesFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		keys := newFaultyKeyStore()
		a, err := New(t.Context(), WithKeyStore(keys), WithLogger(discardLogger), WithKeyRotationInterval(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		first := a.keys.current.Load().id

		keys.fail(&keys.storeErr, errTest)
		time.Sleep(time.Hour + time.Second)
		synctest.Wait()
		if a.keys.current.Load().id != first {
			t.Fatal("key changed even though storing it failed")
		}

		keys.fail(&keys.storeErr, nil)
		time.Sleep(rotationRetryDelay)
		synctest.Wait()
		if a.keys.current.Load().id == first {
			t.Error("rotation was not retried after rotationRetryDelay")
		}
	})
}

func TestRotationLoopLogsCleanupFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		keys := newFaultyKeyStore()
		a, err := New(t.Context(), WithKeyStore(keys), WithLogger(discardLogger), WithKeyRotationInterval(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		first := a.keys.current.Load().id
		keys.fail(&keys.listErr, errTest)
		time.Sleep(time.Hour + time.Second)
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

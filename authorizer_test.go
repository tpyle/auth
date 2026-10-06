package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	users := NewMemoryUserStore()
	users.SetPasswordHash("bob", mustHash(t, "correct"))
	users.SetPasswordHash("broken", "not-a-hash")
	a := newTestAuthorizer(t, WithUserStore(users))

	tests := []struct {
		name, user, pass string
		want             error
	}{
		{"success", "bob", "correct", nil},
		{"wrong password", "bob", "wrong", ErrInvalidCredentials},
		{"unknown user", "alice", "correct", ErrInvalidCredentials},
		{"malformed stored hash", "broken", "x", ErrInvalidHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := a.Authenticate(ctx, tt.user, []byte(tt.pass))
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Errorf("err = %v; want %v", err, tt.want)
			}
		})
	}
	if a.dummyHash == "" {
		t.Error("dummy hash was not computed")
	}
}

func TestAuthenticateRejectsHashOverLimits(t *testing.T) {
	users := NewMemoryUserStore()
	big := testArgon2
	big.MemoryKiB = 1024
	h, _ := HashPassword([]byte("pw"), big)
	users.SetPasswordHash("bob", h)
	a := newTestAuthorizer(t, WithUserStore(users), WithArgon2Limits(testArgon2))
	if err := a.Authenticate(context.Background(), "bob", []byte("pw")); !errors.Is(err, ErrInvalidHash) {
		t.Errorf("err = %v; want ErrInvalidHash", err)
	}
}

func TestAuthenticateStoreFailure(t *testing.T) {
	a := newTestAuthorizer(t, WithUserStore(userStoreFunc(func(context.Context, string) (string, error) {
		return "", errTest
	})))
	err := a.Authenticate(context.Background(), "bob", []byte("pw"))
	if !errors.Is(err, errTest) || errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v; want internal errTest", err)
	}
}

func TestAuthenticateNotConfigured(t *testing.T) {
	a := newTestAuthorizer(t)
	if err := a.Authenticate(context.Background(), "bob", nil); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v", err)
	}
	if _, err := a.Login(context.Background(), "bob", nil); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Login err = %v", err)
	}
}

func TestAuthenticateRehashesOutdatedHashes(t *testing.T) {
	ctx := context.Background()
	old := testArgon2
	old.Iterations = 2
	oldHash, _ := HashPassword([]byte("pw"), old)

	t.Run("updater", func(t *testing.T) {
		users := NewMemoryUserStore()
		users.SetPasswordHash("bob", oldHash)
		a := newTestAuthorizer(t, WithUserStore(users))
		if err := a.Authenticate(ctx, "bob", []byte("pw")); err != nil {
			t.Fatal(err)
		}
		h, _ := users.LookupPasswordHash(ctx, "bob")
		if stale, _ := NeedsRehash(h, testArgon2); stale {
			t.Error("hash was not upgraded")
		}
		if err := a.Authenticate(ctx, "bob", []byte("pw")); err != nil {
			t.Errorf("login with upgraded hash: %v", err)
		}
	})

	t.Run("no rehash on failed login", func(t *testing.T) {
		users := NewMemoryUserStore()
		users.SetPasswordHash("bob", oldHash)
		a := newTestAuthorizer(t, WithUserStore(users))
		_ = a.Authenticate(ctx, "bob", []byte("wrong"))
		if h, _ := users.LookupPasswordHash(ctx, "bob"); h != oldHash {
			t.Error("hash changed after a failed login")
		}
	})

	t.Run("update failure does not fail login", func(t *testing.T) {
		users := &failingUpdater{MemoryUserStore: NewMemoryUserStore()}
		users.SetPasswordHash("bob", oldHash)
		a := newTestAuthorizer(t, WithUserStore(users))
		if err := a.Authenticate(ctx, "bob", []byte("pw")); err != nil {
			t.Fatal(err)
		}
		if users.calls.Load() != 1 {
			t.Error("UpdatePasswordHash not attempted")
		}
	})

	t.Run("does not undo a concurrent password change", func(t *testing.T) {
		newHash := mustHash(t, "new password")
		users := &racingUserStore{MemoryUserStore: NewMemoryUserStore(), changeTo: newHash}
		users.SetPasswordHash("bob", oldHash)
		a := newTestAuthorizer(t, WithUserStore(users))
		if err := a.Authenticate(ctx, "bob", []byte("pw")); err != nil {
			t.Fatal(err)
		}
		if h, _ := users.MemoryUserStore.LookupPasswordHash(ctx, "bob"); h != newHash {
			t.Error("rehash of the old password overwrote the new password")
		}
	})

	t.Run("store without updater", func(t *testing.T) {
		users := userStoreFunc(func(context.Context, string) (string, error) { return oldHash, nil })
		a := newTestAuthorizer(t, WithUserStore(users))
		if err := a.Authenticate(ctx, "bob", []byte("pw")); err != nil {
			t.Fatal(err)
		}
	})
}

func TestHashConcurrencyLimit(t *testing.T) {
	a := newTestAuthorizer(t, WithMaxConcurrentHashes(1))
	h, err := a.HashPassword(context.Background(), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPassword([]byte("pw"), h); !ok {
		t.Fatal("HashPassword produced an unverifiable hash")
	}

	users := NewMemoryUserStore()
	a.s.userStore = users
	a.dummyHash = mustHash(t, "dummy")
	a.hashSem <- struct{}{} // occupy the only slot
	defer a.releaseHashSlot()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.HashPassword(ctx, []byte("pw")); !errors.Is(err, context.Canceled) {
		t.Errorf("HashPassword err = %v; want context.Canceled", err)
	}
	users.SetPasswordHash("bob", h)
	if err := a.Authenticate(ctx, "bob", []byte("pw")); !errors.Is(err, context.Canceled) {
		t.Errorf("Authenticate err = %v; want context.Canceled", err)
	}
	// Unknown users report cancellation the same way known users do.
	if err := a.Authenticate(ctx, "nobody", []byte("pw")); !errors.Is(err, context.Canceled) {
		t.Errorf("Authenticate(unknown) err = %v; want context.Canceled", err)
	}
}

func TestLogin(t *testing.T) {
	ctx := context.Background()
	users := NewMemoryUserStore()
	users.SetPasswordHash("bob", mustHash(t, "pw"))
	provider := func(_ context.Context, sub string) (map[string]any, error) {
		return map[string]any{"role": "admin", "user": sub}, nil
	}

	t.Run("access only", func(t *testing.T) {
		a := newTestAuthorizer(t, WithUserStore(users), WithClaimsProvider(provider))
		pair, err := a.Login(ctx, "bob", []byte("pw"))
		if err != nil {
			t.Fatal(err)
		}
		if pair.RefreshToken != "" || !pair.RefreshTokenExpiresAt.IsZero() {
			t.Error("refresh token issued without a RefreshTokenStore")
		}
		c, err := a.VerifyAccessToken(ctx, pair.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if role, _ := c.GetString("role"); role != "admin" || c.Subject != "bob" || c.Extra["user"] != "bob" {
			t.Errorf("claims = %+v", c)
		}
	})

	t.Run("with refresh", func(t *testing.T) {
		a := newTestAuthorizer(t, WithUserStore(users), WithRefreshTokenStore(NewMemoryRefreshTokenStore()))
		pair, err := a.Login(ctx, "bob", []byte("pw"))
		if err != nil || pair.RefreshToken == "" {
			t.Fatalf("Login = %+v, %v", pair, err)
		}
	})

	t.Run("bad password", func(t *testing.T) {
		a := newTestAuthorizer(t, WithUserStore(users))
		if _, err := a.Login(ctx, "bob", []byte("nope")); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("provider error", func(t *testing.T) {
		a := newTestAuthorizer(t, WithUserStore(users), WithClaimsProvider(func(context.Context, string) (map[string]any, error) {
			return nil, errTest
		}))
		if _, err := a.Login(ctx, "bob", []byte("pw")); !errors.Is(err, errTest) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("provider returns reserved claim", func(t *testing.T) {
		a := newTestAuthorizer(t, WithUserStore(users), WithClaimsProvider(func(context.Context, string) (map[string]any, error) {
			return map[string]any{"typ": "refresh"}, nil
		}))
		if _, err := a.Login(ctx, "bob", []byte("pw")); !errors.Is(err, ErrReservedClaim) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("refresh store failure", func(t *testing.T) {
		store := &faultyRefreshStore{RefreshTokenStore: NewMemoryRefreshTokenStore(), createErr: errTest}
		a := newTestAuthorizer(t, WithUserStore(users), WithRefreshTokenStore(store))
		if _, err := a.Login(ctx, "bob", []byte("pw")); !errors.Is(err, errTest) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestIssueAccessToken(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	a := newTestAuthorizer(t, WithClock(clock.Now), WithIssuer("me"), WithAudience("api", "web"))

	if _, err := a.IssueAccessToken("", nil); err == nil {
		t.Error("empty subject accepted")
	}
	for name := range reservedClaims {
		if _, err := a.IssueAccessToken("bob", map[string]any{name: "x"}); !errors.Is(err, ErrReservedClaim) {
			t.Errorf("claim %q: err = %v; want ErrReservedClaim", name, err)
		}
	}
	if IsReservedClaim("role") {
		t.Error("role should not be reserved")
	}

	tok, err := a.IssueAccessToken("bob", map[string]any{"n": 3, "tags": []string{"a"}, "kid": "custom"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.VerifyAccessToken(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if hdr := strings.SplitN(tok, ".", 2)[0]; !strings.Contains(decodeSegment(t, hdr), `"typ":"at+jwt"`) {
		t.Errorf("access token header lacks RFC 9068 typ")
	}
	if c.Subject != "bob" || c.Issuer != "me" || strings.Join(c.Audience, ",") != "api,web" || c.Type != TokenTypeAccess {
		t.Errorf("claims = %+v", c)
	}
	if _, err := uuid.Parse(c.ID); err != nil {
		t.Errorf("jti %q is not a UUID", c.ID)
	}
	if !c.IssuedAt.Equal(clock.Now()) || !c.ExpiresAt.Equal(clock.Now().Add(15*time.Minute)) {
		t.Errorf("iat %v exp %v", c.IssuedAt, c.ExpiresAt)
	}
	if c.Extra["n"] != float64(3) || c.Extra["kid"] != "custom" || len(c.Extra) != 3 {
		t.Errorf("Extra = %v", c.Extra)
	}
	if _, ok := c.GetString("n"); ok {
		t.Error("String accepted a non-string claim")
	}

	// The "kid" claim must not affect key selection, which uses the header.
	hdr, _, _ := strings.Cut(tok, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(hdr)
	if !strings.Contains(string(raw), a.keys.current.Load().id.String()) {
		t.Errorf("header %s lacks kid", raw)
	}
}

// signRaw signs arbitrary claims with a's current key.
func signRaw(t *testing.T, a *Authorizer, mc jwt.MapClaims, header map[string]any) string {
	t.Helper()
	k := a.keys.current.Load()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, mc)
	tok.Header["kid"] = k.id.String()
	tok.Header["typ"] = headerTypeAccess
	if mc["typ"] == "refresh" {
		tok.Header["typ"] = headerTypeRefresh
	}
	for h, v := range header {
		if v == nil {
			delete(tok.Header, h)
		} else {
			tok.Header[h] = v
		}
	}
	s, err := tok.SignedString(k.private)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyAccessTokenRejects(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	a := newTestAuthorizer(t, WithClock(clock.Now), WithRefreshTokenStore(NewMemoryRefreshTokenStore()))
	stranger := newTestAuthorizer(t, WithClock(clock.Now))
	now := clock.Now().Unix()
	valid := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": "bob", "iat": now, "exp": now + 60, "jti": uuid.NewString(), "typ": "access"}
	}
	without := func(k string) jwt.MapClaims { mc := valid(); delete(mc, k); return mc }
	with := func(k string, v any) jwt.MapClaims { mc := valid(); mc[k] = v; return mc }

	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	good, _ := a.IssueAccessToken("bob", nil)
	foreign, _ := stranger.IssueAccessToken("bob", nil)
	hmac, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, valid()).SignedString([]byte("secret"))
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, valid()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`)) + "." + parts[2]

	if _, err := a.VerifyAccessToken(ctx, signRaw(t, a, valid(), nil)); err != nil {
		t.Fatalf("baseline token rejected: %v", err)
	}

	tests := map[string]string{
		"refresh token as access": pair.RefreshToken,
		"other authorizer":        foreign,
		"HS256":                   hmac,
		"alg none":                none,
		"tampered payload":        tampered,
		"garbage":                 "not.a.jwt",
		"empty":                   "",
		"missing kid":             signRaw(t, a, valid(), map[string]any{"kid": nil}),
		"generic typ header":      signRaw(t, a, valid(), map[string]any{"typ": "JWT"}),
		"refresh typ header":      signRaw(t, a, valid(), map[string]any{"typ": headerTypeRefresh}),
		"missing typ header":      signRaw(t, a, valid(), map[string]any{"typ": nil}),
		"non-string kid":          signRaw(t, a, valid(), map[string]any{"kid": 7}),
		"malformed kid":           signRaw(t, a, valid(), map[string]any{"kid": "abc"}),
		"unknown kid":             signRaw(t, a, valid(), map[string]any{"kid": uuid.NewString()}),
		"missing sub":             signRaw(t, a, without("sub"), nil),
		"empty sub":               signRaw(t, a, with("sub", ""), nil),
		"non-string sub":          signRaw(t, a, with("sub", 1), nil),
		"missing jti":             signRaw(t, a, without("jti"), nil),
		"missing typ":             signRaw(t, a, without("typ"), nil),
		"unknown typ":             signRaw(t, a, with("typ", "id"), nil),
		"missing exp":             signRaw(t, a, without("exp"), nil),
		"string exp":              signRaw(t, a, with("exp", "soon"), nil),
		"future iat":              signRaw(t, a, with("iat", now+3600), nil),
		"non-string fam":          signRaw(t, a, with("fam", 1), nil),
		"non-string iss":          signRaw(t, a, with("iss", 1), nil),
		"numeric aud":             signRaw(t, a, with("aud", 1), nil),
		"numeric aud element":     signRaw(t, a, with("aud", []any{"x", 1}), nil),
	}
	for name, tok := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := a.VerifyAccessToken(ctx, tok); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v; want ErrInvalidToken", err)
			}
		})
	}
}

func TestVerifyAccessTokenExpiry(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	a := newTestAuthorizer(t, WithClock(clock.Now))
	lenient := newTestAuthorizer(t, WithClock(clock.Now), WithLeeway(time.Minute), WithKeyStore(a.s.keyStore))
	tok, _ := a.IssueAccessToken("bob", nil)

	clock.Advance(15*time.Minute + time.Second)
	if _, err := a.VerifyAccessToken(ctx, tok); !errors.Is(err, ErrTokenExpired) || errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v; want only ErrTokenExpired", err)
	}
	if _, err := lenient.VerifyAccessToken(ctx, tok); err != nil {
		t.Errorf("leeway not applied: %v", err)
	}
}

// The wrong kind of token is invalid even when it has also expired.
func TestExpiredTokenOfWrongType(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithClock(clock.Now))
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	clock.Advance(30 * 24 * time.Hour)
	if _, err := a.VerifyAccessToken(ctx, pair.RefreshToken); !errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired refresh token as access: err = %v; want only ErrInvalidToken", err)
	}
	if _, err := a.Refresh(ctx, pair.AccessToken); !errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired access token to Refresh: err = %v; want only ErrInvalidToken", err)
	}
	if _, err := a.VerifyAccessToken(ctx, pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired access token: err = %v; want ErrTokenExpired", err)
	}
}

// Tokens are accepted until exp + Leeway, so their records and signing keys
// must be retained that long.
func TestLeewayRetention(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	store := NewMemoryRefreshTokenStore()
	store.now = clock.Now
	keys := NewMemoryKeyStore()
	a := newRefreshAuthorizer(t, store, WithClock(clock.Now), WithKeyStore(keys),
		WithLeeway(time.Minute), WithRefreshTokenTTL(time.Hour), WithKeyRotationInterval(time.Hour))

	cur := storedKey(t, keys, a.keys.current.Load().id)
	if want := clock.Now().Add(time.Hour + time.Hour + keyRetentionMargin + time.Minute); !cur.ExpiresAt.Equal(want) {
		t.Errorf("key ExpiresAt = %v; want %v", cur.ExpiresAt, want)
	}

	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	clock.Advance(time.Hour + 30*time.Second)                      // expired, but within leeway
	if _, err := a.IssueTokenPair(ctx, "carol", nil); err != nil { // triggers a purge
		t.Fatal(err)
	}
	if _, err := a.Refresh(ctx, pair.RefreshToken); err != nil {
		t.Errorf("refresh within leeway after purge: %v", err)
	}
}

// An expired token is only reported as expired if it is otherwise valid.
func TestExpiredTokenMustOtherwiseBeValid(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := NewMemoryKeyStore()
	a := newTestAuthorizer(t, WithClock(clock.Now), WithKeyStore(keys), WithIssuer("me"))
	other := newTestAuthorizer(t, WithClock(clock.Now), WithKeyStore(keys), WithIssuer("someone-else"))
	now := clock.Now().Unix()
	noJTI := signRaw(t, a, jwt.MapClaims{"sub": "bob", "iss": "me", "iat": now, "exp": now + 60, "typ": "access"}, nil)
	wrongIssuer, _ := other.IssueAccessToken("bob", nil)
	valid, _ := a.IssueAccessToken("bob", nil)

	clock.Advance(time.Hour)
	for name, tok := range map[string]string{"missing jti": noJTI, "wrong issuer": wrongIssuer} {
		if _, err := a.VerifyAccessToken(ctx, tok); !errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrTokenExpired) {
			t.Errorf("%s: err = %v; want only ErrInvalidToken", name, err)
		}
	}
	if _, err := a.VerifyAccessToken(ctx, valid); !errors.Is(err, ErrTokenExpired) || errors.Is(err, ErrInvalidToken) {
		t.Errorf("valid expired token: err = %v; want only ErrTokenExpired", err)
	}
}

func TestVerifyIssuerAndAudience(t *testing.T) {
	ctx := context.Background()
	keys := NewMemoryKeyStore()
	plain := newTestAuthorizer(t, WithKeyStore(keys))
	issuerA := newTestAuthorizer(t, WithKeyStore(keys), WithIssuer("a"), WithAudience("x"))
	issuerB := newTestAuthorizer(t, WithKeyStore(keys), WithIssuer("b"), WithAudience("x"))
	audY := newTestAuthorizer(t, WithKeyStore(keys), WithIssuer("a"), WithAudience("y", "z"))
	audMulti := newTestAuthorizer(t, WithKeyStore(keys), WithIssuer("a"), WithAudience("q", "x"))

	tokA, _ := issuerA.IssueAccessToken("bob", nil)
	tokPlain, _ := plain.IssueAccessToken("bob", nil)

	if _, err := issuerB.VerifyAccessToken(ctx, tokA); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong issuer: err = %v", err)
	}
	if _, err := audY.VerifyAccessToken(ctx, tokA); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong audience: err = %v", err)
	}
	if _, err := audMulti.VerifyAccessToken(ctx, tokA); err != nil {
		t.Errorf("overlapping audience rejected: %v", err)
	}
	if _, err := issuerA.VerifyAccessToken(ctx, tokPlain); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token without iss accepted: %v", err)
	}
	if _, err := plain.VerifyAccessToken(ctx, tokA); err != nil {
		t.Errorf("unconstrained verifier rejected token: %v", err)
	}
}

// Instances that share a KeyStore verify each other's tokens.
func TestMultiInstance(t *testing.T) {
	ctx := context.Background()
	keys := NewMemoryKeyStore()
	refresh := NewMemoryRefreshTokenStore()
	one := newTestAuthorizer(t, WithKeyStore(keys), WithRefreshTokenStore(refresh))
	two := newTestAuthorizer(t, WithKeyStore(keys), WithRefreshTokenStore(refresh))

	pair, err := one.IssueTokenPair(ctx, "bob", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := two.VerifyAccessToken(ctx, pair.AccessToken); err != nil {
		t.Errorf("instance two rejected instance one's token: %v", err)
	}
	if _, err := two.Refresh(ctx, pair.RefreshToken); err != nil {
		t.Errorf("instance two could not refresh: %v", err)
	}
}

func newRefreshAuthorizer(t *testing.T, store RefreshTokenStore, opts ...Option) *Authorizer {
	return newTestAuthorizer(t, append([]Option{WithRefreshTokenStore(store)}, opts...)...)
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()
	role := "user"
	var mu sync.Mutex
	provider := func(context.Context, string) (map[string]any, error) {
		mu.Lock()
		defer mu.Unlock()
		return map[string]any{"role": role}, nil
	}
	clock := newFakeClock()
	store := NewMemoryRefreshTokenStore()
	a := newRefreshAuthorizer(t, store, WithClaimsProvider(provider), WithClock(clock.Now))

	first, err := a.IssueTokenPair(ctx, "bob", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Refresh(ctx, first.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("access token accepted as refresh token: %v", err)
	}

	mu.Lock()
	role = "admin"
	mu.Unlock()
	second, err := a.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := a.VerifyAccessToken(ctx, second.AccessToken)
	if r, _ := c.GetString("role"); r != "admin" || c.Subject != "bob" {
		t.Errorf("refreshed claims = %+v; want role admin from provider", c)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}

	// Reusing the consumed token after the grace period revokes the whole
	// family, including the token that replaced it.
	clock.Advance(DefaultConfig().RefreshReuseGrace + time.Second)
	if _, err := a.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("reuse: err = %v; want ErrRefreshTokenReused", err)
	}
	if _, err := a.Refresh(ctx, second.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("after reuse: err = %v; want ErrTokenRevoked", err)
	}
}

func TestRefreshFamiliesAreIndependent(t *testing.T) {
	ctx := context.Background()
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore())
	phone, _ := a.IssueTokenPair(ctx, "bob", nil)
	laptop, _ := a.IssueTokenPair(ctx, "bob", nil)
	if err := a.Logout(ctx, phone.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Refresh(ctx, phone.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("phone: err = %v; want ErrTokenRevoked", err)
	}
	if _, err := a.Refresh(ctx, laptop.RefreshToken); err != nil {
		t.Errorf("laptop session affected by phone logout: %v", err)
	}
}

// concurrentRefreshes refreshes token n times in parallel and returns how
// many succeeded.
func concurrentRefreshes(a *Authorizer, token string, n int) int {
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := a.Refresh(context.Background(), token)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	succeeded := 0
	for err := range errs {
		if err == nil {
			succeeded++
		}
	}
	return succeeded
}

// Several tabs refreshing with the same token at once all succeed within the
// grace period, and the session survives.
func TestRefreshConcurrentWithinGrace(t *testing.T) {
	ctx := context.Background()
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore())
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	if got := concurrentRefreshes(a, pair.RefreshToken, 8); got != 8 {
		t.Errorf("%d of 8 concurrent refreshes succeeded; want all", got)
	}
}

func TestRefreshConcurrentWithoutGrace(t *testing.T) {
	ctx := context.Background()
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithRefreshReuseGrace(0))
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	// Any reuse is theft, so the session is revoked. The first request may
	// still win if it finishes before a reuse is detected.
	if got := concurrentRefreshes(a, pair.RefreshToken, 8); got > 1 {
		t.Errorf("%d concurrent refreshes succeeded; want at most 1", got)
	}
}

func TestRefreshReuseGrace(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithClock(clock.Now), WithRefreshReuseGrace(30*time.Second))
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)

	first, err := a.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	// A retry inside the window, e.g. after a lost response, gets its own pair.
	clock.Advance(30 * time.Second)
	retry, err := a.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("reuse at the end of the grace window: %v", err)
	}
	if retry.RefreshToken == first.RefreshToken {
		t.Error("grace refresh returned the same refresh token")
	}
	// The window is measured from the first use, so it does not slide.
	clock.Advance(time.Second)
	if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("reuse after grace: err = %v; want ErrRefreshTokenReused", err)
	}
	for _, p := range []*TokenPair{first, retry} {
		if _, err := a.Refresh(ctx, p.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
			t.Errorf("sibling token after theft detection: err = %v; want ErrTokenRevoked", err)
		}
	}
}

// The reusing request may have read its clock before the first use was
// recorded, so the reuse appears to precede the first use.
func TestRefreshReuseClockOrdering(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		grace time.Duration
		want  error
	}{
		{0, ErrRefreshTokenReused},
		{30 * time.Second, nil},
	} {
		clock := newFakeClock()
		a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithClock(clock.Now), WithRefreshReuseGrace(tt.grace))
		pair, _ := a.IssueTokenPair(ctx, "bob", nil)
		clock.Advance(2 * time.Second)
		if _, err := a.Refresh(ctx, pair.RefreshToken); err != nil {
			t.Fatal(err)
		}
		clock.Advance(-time.Second) // still after the token's iat
		if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
			t.Errorf("grace %v: err = %v; want %v", tt.grace, err, tt.want)
		}
	}
}

// A revocation that lands between consuming a refresh token and storing its
// replacement must not leave the replacement usable.
func TestRevocationDuringRefresh(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name   string
		revoke func(a *Authorizer, pair *TokenPair) error
	}{
		{"logout", func(a *Authorizer, p *TokenPair) error { return a.Logout(ctx, p.RefreshToken) }},
		{"revoke all", func(a *Authorizer, _ *TokenPair) error { return a.RevokeAllSessions(ctx, "bob") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &faultyRefreshStore{RefreshTokenStore: NewMemoryRefreshTokenStore()}
			a := newRefreshAuthorizer(t, store)
			pair, _ := a.IssueTokenPair(ctx, "bob", nil)
			store.beforeCreate = func() {
				store.beforeCreate = nil
				if err := tt.revoke(a, pair); err != nil {
					t.Error(err)
				}
			}
			if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
				t.Errorf("err = %v; want ErrTokenRevoked", err)
			}
		})
	}
}

// A refresh stalled long enough for its revoked family to be purged must not
// recreate the family.
func TestRefreshAfterFamilyPurged(t *testing.T) {
	ctx := context.Background()
	mem := NewMemoryRefreshTokenStore()
	store := &faultyRefreshStore{RefreshTokenStore: mem}
	a := newRefreshAuthorizer(t, store)
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	store.beforeCreate = func() {
		store.beforeCreate = nil
		_ = a.Logout(ctx, pair.RefreshToken)
		mem.mu.Lock()
		clear(mem.families) // what a purge does once the family has expired
		mem.mu.Unlock()
	}
	if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("err = %v; want ErrTokenRevoked", err)
	}
	if mem.Len() != 0 {
		t.Error("the stalled refresh recreated the session")
	}
}

func TestRevokeAllSessions(t *testing.T) {
	ctx := context.Background()
	store := &faultyRefreshStore{RefreshTokenStore: NewMemoryRefreshTokenStore()}
	a := newRefreshAuthorizer(t, store)
	phone, _ := a.IssueTokenPair(ctx, "bob", nil)
	laptop, _ := a.IssueTokenPair(ctx, "bob", nil)
	other, _ := a.IssueTokenPair(ctx, "carol", nil)

	if err := a.RevokeAllSessions(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*TokenPair{"phone": phone, "laptop": laptop} {
		if _, err := a.Refresh(ctx, p.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
			t.Errorf("%s: err = %v; want ErrTokenRevoked", name, err)
		}
	}
	if _, err := a.Refresh(ctx, other.RefreshToken); err != nil {
		t.Errorf("another user's session was affected: %v", err)
	}
	// Access tokens are stateless and remain valid until they expire.
	if _, err := a.VerifyAccessToken(ctx, phone.AccessToken); err != nil {
		t.Errorf("access token: %v", err)
	}

	if err := a.RevokeAllSessions(ctx, ""); err == nil {
		t.Error("empty subject accepted")
	}
	store.revokeErr = errTest
	if err := a.RevokeAllSessions(ctx, "bob"); !errors.Is(err, errTest) {
		t.Errorf("store failure: err = %v", err)
	}
	if err := newTestAuthorizer(t).RevokeAllSessions(ctx, "bob"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no store: err = %v", err)
	}
}

func TestRefreshErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("not configured", func(t *testing.T) {
		a := newTestAuthorizer(t)
		if _, err := a.Refresh(ctx, "x"); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("err = %v", err)
		}
		if err := a.Logout(ctx, "x"); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("Logout err = %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		clock := newFakeClock()
		a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithClock(clock.Now))
		pair, _ := a.IssueTokenPair(ctx, "bob", nil)
		clock.Advance(8 * 24 * time.Hour)
		if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, ErrTokenExpired) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("consume failure", func(t *testing.T) {
		store := &faultyRefreshStore{RefreshTokenStore: NewMemoryRefreshTokenStore()}
		a := newRefreshAuthorizer(t, store)
		pair, _ := a.IssueTokenPair(ctx, "bob", nil)
		store.consumeErr = errTest
		if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, errTest) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("revoke failure on reuse", func(t *testing.T) {
		store := &faultyRefreshStore{RefreshTokenStore: NewMemoryRefreshTokenStore()}
		a := newRefreshAuthorizer(t, store, WithRefreshReuseGrace(0))
		pair, _ := a.IssueTokenPair(ctx, "bob", nil)
		if _, err := a.Refresh(ctx, pair.RefreshToken); err != nil {
			t.Fatal(err)
		}
		store.revokeErr = errTest
		_, err := a.Refresh(ctx, pair.RefreshToken)
		if !errors.Is(err, ErrRefreshTokenReused) || !errors.Is(err, errTest) {
			t.Errorf("err = %v; want both ErrRefreshTokenReused and errTest", err)
		}
	})

	t.Run("record mismatch", func(t *testing.T) {
		store := NewMemoryRefreshTokenStore()
		a := newRefreshAuthorizer(t, store)
		pair, _ := a.IssueTokenPair(ctx, "bob", nil)
		c, _, err := a.parseRefresh(ctx, pair.RefreshToken, true)
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(c.ID)
		store.records[id] = RefreshTokenRecord{ID: id, FamilyID: uuid.New(), Subject: "eve", ExpiresAt: time.Now().Add(time.Hour)}
		if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("malformed jti and fam", func(t *testing.T) {
		clock := newFakeClock()
		a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithClock(clock.Now))
		now := clock.Now().Unix()
		base := jwt.MapClaims{"sub": "bob", "iat": now, "exp": now + 60, "typ": "refresh"}
		badJTI := jwt.MapClaims{"jti": "nope", "fam": uuid.NewString()}
		badFam := jwt.MapClaims{"jti": uuid.NewString(), "fam": "nope"}
		for name, extra := range map[string]jwt.MapClaims{"jti": badJTI, "fam": badFam} {
			mc := jwt.MapClaims{}
			for k, v := range base {
				mc[k] = v
			}
			for k, v := range extra {
				mc[k] = v
			}
			if _, err := a.Refresh(ctx, signRaw(t, a, mc, nil)); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("%s: err = %v", name, err)
			}
		}
	})

	t.Run("provider failure", func(t *testing.T) {
		a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore())
		pair, _ := a.IssueTokenPair(ctx, "bob", nil)
		a.s.claimsProvider = func(context.Context, string) (map[string]any, error) { return nil, errTest }
		if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, errTest) {
			t.Errorf("err = %v", err)
		}
		// The token was not consumed, so a retry succeeds.
		a.s.claimsProvider = nil
		if _, err := a.Refresh(ctx, pair.RefreshToken); err != nil {
			t.Errorf("retry after provider failure: %v", err)
		}
	})
}

func TestLogout(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	store := &faultyRefreshStore{RefreshTokenStore: NewMemoryRefreshTokenStore()}
	a := newRefreshAuthorizer(t, store, WithClock(clock.Now))
	stranger := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore())

	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	clock.Advance(30 * 24 * time.Hour)
	if err := a.Logout(ctx, pair.RefreshToken); err != nil {
		t.Errorf("logout with expired token: %v", err)
	}
	if err := a.Logout(ctx, pair.RefreshToken); err != nil {
		t.Errorf("second logout: %v", err)
	}
	if err := a.Logout(ctx, pair.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("logout with access token: %v", err)
	}
	foreign, _ := stranger.IssueTokenPair(ctx, "bob", nil)
	if err := a.Logout(ctx, foreign.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("logout with foreign token: %v", err)
	}
	shared := newRefreshAuthorizer(t, store, WithKeyStore(a.s.keyStore), WithIssuer("a"), WithAudience("x"))
	wrongIss := newRefreshAuthorizer(t, store, WithKeyStore(a.s.keyStore), WithIssuer("b"), WithAudience("x"))
	wrongAud := newRefreshAuthorizer(t, store, WithKeyStore(a.s.keyStore), WithIssuer("a"), WithAudience("y"))
	scoped, _ := shared.IssueTokenPair(ctx, "bob", nil)
	if err := wrongIss.Logout(ctx, scoped.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("logout with wrong issuer: %v", err)
	}
	if err := wrongAud.Logout(ctx, scoped.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("logout with wrong audience: %v", err)
	}
	if err := shared.Logout(ctx, scoped.RefreshToken); err != nil {
		t.Errorf("logout with matching issuer: %v", err)
	}

	store.revokeErr = errTest
	if err := a.Logout(ctx, pair.RefreshToken); !errors.Is(err, errTest) {
		t.Errorf("revoke failure: %v", err)
	}
}

func TestClose(t *testing.T) {
	ctx := context.Background()
	users := NewMemoryUserStore()
	users.SetPasswordHash("bob", mustHash(t, "pw"))
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithUserStore(users))
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := a.IssueAccessToken("bob", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("IssueAccessToken: %v", err)
	}
	if _, err := a.IssueTokenPair(ctx, "bob", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("IssueTokenPair: %v", err)
	}
	if _, err := a.Login(ctx, "bob", []byte("pw")); !errors.Is(err, ErrClosed) {
		t.Errorf("Login: %v", err)
	}
	if _, err := a.Refresh(ctx, pair.RefreshToken); !errors.Is(err, ErrClosed) {
		t.Errorf("Refresh: %v", err)
	}
	if _, err := a.VerifyAccessToken(ctx, pair.AccessToken); err != nil {
		t.Errorf("verification should still work after Close: %v", err)
	}
	if err := a.Logout(ctx, pair.RefreshToken); err != nil {
		t.Errorf("logout should still work after Close: %v", err)
	}
}

func TestJWKS(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	keys := newFaultyKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys), WithClock(clock.Now))

	// An expired key left in the store is not published.
	_ = keys.StoreKey(ctx, &VerificationKey{ID: uuid.New(), PublicKey: &a.keys.current.Load().private.PublicKey,
		CreatedAt: clock.Now().Add(-48 * time.Hour), ExpiresAt: clock.Now().Add(-time.Hour)})
	clock.Advance(time.Second)
	if err := a.keys.rotate(ctx); err != nil {
		t.Fatal(err)
	}

	set, err := a.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("got %d keys; want 2", len(set.Keys))
	}
	listed := map[string]bool{}
	for _, k := range set.Keys {
		listed[k.KeyID] = true
	}
	if !listed[a.keys.current.Load().id.String()] {
		t.Error("current key is not listed")
	}

	// A third-party verifier can check our tokens using only the JWKS.
	tok, _ := a.IssueAccessToken("bob", nil)
	_, err = jwt.Parse(tok, func(t *jwt.Token) (any, error) {
		for _, k := range set.Keys {
			if k.KeyID == t.Header["kid"] {
				x, _ := base64.RawURLEncoding.DecodeString(k.X)
				y, _ := base64.RawURLEncoding.DecodeString(k.Y)
				return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
			}
		}
		return nil, errors.New("kid not in JWKS")
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithTimeFunc(clock.Now))
	if err != nil {
		t.Errorf("verifying with JWKS: %v", err)
	}

	keys.fail(&keys.listErr, errTest)
	if _, err := a.JWKS(ctx); !errors.Is(err, errTest) {
		t.Errorf("err = %v", err)
	}
	keys.fail(&keys.listErr, nil)

	// Malformed rows are skipped rather than crashing the endpoint.
	keys.mu.Lock()
	keys.extra = []*VerificationKey{nil, {ID: uuid.New()}}
	keys.mu.Unlock()
	if set, err := a.JWKS(ctx); err != nil || len(set.Keys) != 2 {
		t.Errorf("JWKS with malformed keys = %v, %v", set, err)
	}

	bad, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_ = keys.StoreKey(ctx, &VerificationKey{ID: uuid.New(), PublicKey: &bad.PublicKey})
	if _, err := a.JWKS(ctx); err == nil {
		t.Error("expected error for a non-P-256 key")
	}
}

func decodeSegment(t *testing.T, seg string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

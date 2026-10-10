package srp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"uuid"

	"github.com/tpyle/auth/v2"
)

func TestLogin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ch, cl := e.begin("alice", alicePassword)
	if ch.Group != Group2048 || ch.KDF != testKDF || len(ch.Salt) != 16 || len(ch.ServerPublic) != 256 {
		t.Errorf("challenge = %+v", ch)
	}
	if want := e.clock.Now().Add(DefaultConfig().SessionTTL); !ch.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", ch.ExpiresAt, want)
	}

	res, err := e.srv.Authenticate(ctx, cl.Response())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.Subject != "alice" || res.VerifierOutdated || res.Tokens != nil {
		t.Errorf("result = %+v", res)
	}
	if err := cl.VerifyServer(res.ServerProof); err != nil {
		t.Fatalf("VerifyServer: %v", err)
	}
	if k := cl.SessionKey(); len(k) != 32 || !bytes.Equal(k, res.SessionKey) {
		t.Error("client and server session keys differ")
	}
	if len(e.issuer.Calls()) != 0 {
		t.Error("Authenticate issued tokens")
	}
}

func TestLoginAllGroups(t *testing.T) {
	for _, g := range []Group{Group2048, Group3072, Group4096} {
		t.Run(g.String(), func(t *testing.T) {
			e := newEnv(t, WithGroup(g))
			ch, cl := e.begin("bob", bobPassword)
			if ch.Group != g {
				t.Errorf("group = %d", ch.Group)
			}
			res, err := e.srv.Authenticate(context.Background(), cl.Response())
			if err != nil {
				t.Fatal(err)
			}
			if err := cl.VerifyServer(res.ServerProof); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoginThroughJSON(t *testing.T) {
	// The wire types survive a JSON round trip, as they would over HTTP.
	e := newEnv(t)
	ch, err := e.srv.BeginLogin(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	var gotCh Challenge
	roundTrip(t, ch, &gotCh)
	cl, err := e.client.Login("alice", []byte(alicePassword), &gotCh)
	if err != nil {
		t.Fatal(err)
	}
	var resp LoginResponse
	roundTrip(t, cl.Response(), &resp)
	if _, err := e.srv.FinishLogin(context.Background(), resp); err != nil {
		t.Fatal(err)
	}
}

func roundTrip(t *testing.T, in, out any) {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

func TestChallengeJSONFields(t *testing.T) {
	ch := Challenge{Group: Group2048, KDF: testKDF, Salt: []byte{1}, ServerPublic: []byte{2}}
	b, _ := json.Marshal(ch)
	for _, want := range []string{`"sessionId":`, `"group":2048`, `"kdf":{"m":64,"t":1,"p":1}`, `"salt":"AQ=="`, `"serverPublic":"Ag=="`, `"expiresAt":`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not contain %s", b, want)
		}
	}
	b, _ = json.Marshal(LoginResponse{ClientPublic: []byte{1}, ClientProof: []byte{2}})
	for _, want := range []string{`"sessionId":`, `"clientPublic":"AQ=="`, `"clientProof":"Ag=="`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not contain %s", b, want)
		}
	}
}

func TestFinishLogin(t *testing.T) {
	var claimsFor string
	e := newEnv(t, WithClaimsProvider(func(_ context.Context, subject string) (map[string]any, error) {
		claimsFor = subject
		return map[string]any{"role": "admin"}, nil
	}))
	_, cl := e.begin("alice", alicePassword)
	res, err := e.srv.FinishLogin(context.Background(), cl.Response())
	if err != nil {
		t.Fatal(err)
	}
	if res.Tokens == nil || res.Tokens.AccessToken != "access-alice" || res.Subject != "alice" {
		t.Errorf("result = %+v", res)
	}
	if err := cl.VerifyServer(res.ServerProof); err != nil {
		t.Error(err)
	}
	calls := e.issuer.Calls()
	if len(calls) != 1 || calls[0].subject != "alice" || calls[0].extra["role"] != "admin" || claimsFor != "alice" {
		t.Errorf("issuer calls = %+v", calls)
	}
}

func TestFinishLoginWithoutClaimsProvider(t *testing.T) {
	e := newEnv(t)
	_, cl := e.begin("alice", alicePassword)
	if _, err := e.srv.FinishLogin(context.Background(), cl.Response()); err != nil {
		t.Fatal(err)
	}
	if calls := e.issuer.Calls(); len(calls) != 1 || calls[0].extra != nil {
		t.Errorf("issuer calls = %+v", calls)
	}
}

func TestFinishLoginErrors(t *testing.T) {
	t.Run("no issuer", func(t *testing.T) {
		users := NewMemoryUserStore()
		srv, err := New(WithUserStore(users), WithKDFParams(testKDF), WithGroup(Group2048))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := srv.FinishLogin(context.Background(), LoginResponse{}); !errors.Is(err, auth.ErrNotConfigured) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("claims provider", func(t *testing.T) {
		boom := errors.New("boom")
		e := newEnv(t, WithClaimsProvider(func(context.Context, string) (map[string]any, error) { return nil, boom }))
		_, cl := e.begin("alice", alicePassword)
		if _, err := e.srv.FinishLogin(context.Background(), cl.Response()); !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
		if len(e.issuer.Calls()) != 0 {
			t.Error("tokens issued")
		}
	})
	t.Run("issuer", func(t *testing.T) {
		e := newEnv(t)
		e.issuer.failErr = auth.ErrClosed
		_, cl := e.begin("alice", alicePassword)
		if _, err := e.srv.FinishLogin(context.Background(), cl.Response()); !errors.Is(err, auth.ErrClosed) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		e := newEnv(t)
		_, cl := e.begin("alice", bobPassword)
		if _, err := e.srv.FinishLogin(context.Background(), cl.Response()); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("err = %v", err)
		}
		if len(e.issuer.Calls()) != 0 {
			t.Error("tokens issued")
		}
	})
}

func TestWrongPassword(t *testing.T) {
	e := newEnv(t)
	for _, pw := range []string{bobPassword, "", alicePassword + " ", strings.ToUpper(alicePassword)} {
		_, cl := e.begin("alice", pw)
		res, err := e.srv.Authenticate(context.Background(), cl.Response())
		if !errors.Is(err, auth.ErrInvalidCredentials) || res != nil {
			t.Errorf("password %q: %v, %v", pw, res, err)
		}
	}
}

func TestWrongUsernameInProof(t *testing.T) {
	// The username is part of M1, so a client must use the exact string the
	// login was begun with.
	e := newEnv(t)
	ch, err := e.srv.BeginLogin(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := e.client.Login("Alice", []byte(alicePassword), ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Authenticate(context.Background(), cl.Response()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestOtherUsersPassword(t *testing.T) {
	// Bob's password does not log in as alice, nor does a response to bob's
	// challenge.
	e := newEnv(t)
	ctx := context.Background()
	chAlice, err := e.srv.BeginLogin(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_, clBob := e.begin("bob", bobPassword)
	resp := clBob.Response()
	resp.SessionID = chAlice.SessionID
	if _, err := e.srv.Authenticate(ctx, resp); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestMalformedResponse(t *testing.T) {
	p := groups[Group2048]
	tests := map[string]func(*LoginResponse){
		"A missing":     func(r *LoginResponse) { r.ClientPublic = nil },
		"A zero":        func(r *LoginResponse) { r.ClientPublic = make([]byte, p.size) },
		"A N":           func(r *LoginResponse) { r.ClientPublic = p.pad(p.n) },
		"A 2N":          func(r *LoginResponse) { r.ClientPublic = new(big.Int).Lsh(p.n, 1).Bytes() },
		"A too long":    func(r *LoginResponse) { r.ClientPublic = append([]byte{0}, r.ClientPublic...) },
		"A changed":     func(r *LoginResponse) { r.ClientPublic[10] ^= 1 },
		"proof missing": func(r *LoginResponse) { r.ClientProof = nil },
		"proof short":   func(r *LoginResponse) { r.ClientProof = r.ClientProof[:31] },
		"proof changed": func(r *LoginResponse) { r.ClientProof[0] ^= 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			_, cl := e.begin("alice", alicePassword)
			resp := cl.Response()
			mutate(&resp)
			if _, err := e.srv.Authenticate(context.Background(), resp); !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestUnpaddedClientPublicAccepted(t *testing.T) {
	// A is padded before hashing, so a client that sends it without leading
	// zeros still logs in. Retry until A has a leading zero byte.
	e := newEnv(t)
	for range 2000 {
		_, cl := e.begin("alice", alicePassword)
		resp := cl.Response()
		if resp.ClientPublic[0] != 0 {
			continue
		}
		resp.ClientPublic = new(big.Int).SetBytes(resp.ClientPublic).Bytes()
		if _, err := e.srv.Authenticate(context.Background(), resp); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Skip("no A with a leading zero byte found")
}

func TestSessionSingleUse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	_, cl := e.begin("alice", alicePassword)
	if _, err := e.srv.Authenticate(ctx, cl.Response()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Authenticate(ctx, cl.Response()); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("replay: %v", err)
	}

	// A failed attempt also uses up the session.
	ch, err := e.srv.BeginLogin(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := e.client.Login("alice", []byte("guess"), ch)
	if _, err := e.srv.Authenticate(ctx, bad.Response()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal(err)
	}
	good, _ := e.client.Login("alice", []byte(alicePassword), ch)
	if _, err := e.srv.Authenticate(ctx, good.Response()); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("after failure: %v", err)
	}
}

func TestUnknownSession(t *testing.T) {
	e := newEnv(t)
	_, cl := e.begin("alice", alicePassword)
	resp := cl.Response()
	resp.SessionID = uuid.New()
	if _, err := e.srv.Authenticate(context.Background(), resp); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("err = %v", err)
	}
	if _, err := e.srv.Authenticate(context.Background(), LoginResponse{}); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("zero response: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t, WithSessionTTL(time.Minute))
	_, cl := e.begin("alice", alicePassword)
	e.clock.Advance(time.Minute)
	if _, err := e.srv.Authenticate(context.Background(), cl.Response()); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("at expiry: %v", err)
	}

	_, cl = e.begin("alice", alicePassword)
	e.clock.Advance(time.Minute - time.Second)
	if _, err := e.srv.Authenticate(context.Background(), cl.Response()); err != nil {
		t.Errorf("before expiry: %v", err)
	}
}

func TestSessionExpiryCheckedDespiteStore(t *testing.T) {
	// A store that ignores expiry cannot extend the window.
	mem := NewMemorySessionStore()
	store := &funcSessionStore{mem: mem, consume: func(ctx context.Context, id uuid.UUID, _ time.Time) ([]byte, error) {
		return mem.ConsumeSession(ctx, id, time.Time{})
	}}
	e := newEnv(t, WithSessionStore(store), WithSessionTTL(time.Minute))
	_, cl := e.begin("alice", alicePassword)
	e.clock.Advance(2 * time.Minute)
	if _, err := e.srv.Authenticate(context.Background(), cl.Response()); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("err = %v", err)
	}
}

func TestSessionStoreErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("save", func(t *testing.T) {
		store := &funcSessionStore{mem: NewMemorySessionStore(), save: func(context.Context, uuid.UUID, []byte, time.Time) error { return errStore }}
		e := newEnv(t, WithSessionStore(store))
		if _, err := e.srv.BeginLogin(ctx, "alice"); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("consume", func(t *testing.T) {
		store := &funcSessionStore{mem: NewMemorySessionStore(), consume: func(context.Context, uuid.UUID, time.Time) ([]byte, error) { return nil, errStore }}
		e := newEnv(t, WithSessionStore(store))
		_, cl := e.begin("alice", alicePassword)
		_, err := e.srv.Authenticate(ctx, cl.Response())
		if !errors.Is(err, errStore) || errors.Is(err, ErrInvalidSession) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("wrapped not found", func(t *testing.T) {
		store := &funcSessionStore{mem: NewMemorySessionStore(), consume: func(context.Context, uuid.UUID, time.Time) ([]byte, error) {
			return nil, errors.Join(errStore, ErrSessionNotFound)
		}}
		e := newEnv(t, WithSessionStore(store))
		_, cl := e.begin("alice", alicePassword)
		if _, err := e.srv.Authenticate(ctx, cl.Response()); !errors.Is(err, ErrInvalidSession) {
			t.Errorf("err = %v", err)
		}
	})
	for name, data := range map[string]string{
		"not json":     "{",
		"bad verifier": `{"user":"alice","verifier":"nope","exp":"2999-01-01T00:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			store := &funcSessionStore{mem: NewMemorySessionStore(), consume: func(context.Context, uuid.UUID, time.Time) ([]byte, error) {
				return []byte(data), nil
			}}
			e := newEnv(t, WithSessionStore(store))
			_, cl := e.begin("alice", alicePassword)
			_, err := e.srv.Authenticate(ctx, cl.Response())
			if err == nil || errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, ErrInvalidSession) {
				t.Errorf("err = %v, want an internal error", err)
			}
		})
	}
}

func TestSessionDataHasNoPassword(t *testing.T) {
	var saved []byte
	mem := NewMemorySessionStore()
	store := &funcSessionStore{mem: mem, save: func(ctx context.Context, id uuid.UUID, data []byte, exp time.Time) error {
		saved = data
		return mem.SaveSession(ctx, id, data, exp)
	}}
	e := newEnv(t, WithSessionStore(store))
	e.begin("alice", alicePassword)
	if len(saved) == 0 || len(saved) > 2048 {
		t.Fatalf("saved %d bytes", len(saved))
	}
	if bytes.Contains(saved, []byte(alicePassword)) {
		t.Error("session contains the password")
	}
}

func TestUserStoreErrors(t *testing.T) {
	ctx := context.Background()
	srv, err := New(WithUserStore(failingUserStore{errStore}), WithLogger(discardLogger))
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.BeginLogin(ctx, "alice")
	if !errors.Is(err, errStore) {
		t.Errorf("err = %v", err)
	}
}

func TestStoredVerifierProblems(t *testing.T) {
	ctx := context.Background()
	heavy := testVerifier(t, Group2048)
	heavy.KDF = KDFParams{MemoryKiB: 1024, Iterations: 1, Parallelism: 1}
	for name, encoded := range map[string]string{
		"malformed":   "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"over limits": heavy.String(),
	} {
		t.Run(name, func(t *testing.T) {
			srv, err := New(WithUserStore(rawUserStore{encoded}), WithKDFParams(testKDF),
				WithKDFLimits(KDFParams{MemoryKiB: 512, Iterations: 4, Parallelism: 4}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = srv.BeginLogin(ctx, "alice")
			if !errors.Is(err, ErrInvalidVerifier) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestDecoy(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{42}, 32)
	e := newEnv(t, WithDecoyKey(key), WithSaltLength(20))

	ch1, err := e.srv.BeginLogin(ctx, "mallory")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if ch1.Group != Group2048 || ch1.KDF != testKDF || len(ch1.Salt) != 20 {
		t.Errorf("decoy challenge = %+v", ch1)
	}
	if _, ok := groups[Group2048].decodePublic(ch1.ServerPublic); !ok {
		t.Error("decoy B out of range")
	}

	// The salt is stable for a username, so asking twice reveals nothing,
	// while B is fresh, as for a real user.
	ch2, _ := e.srv.BeginLogin(ctx, "mallory")
	if !bytes.Equal(ch1.Salt, ch2.Salt) {
		t.Error("decoy salt changed between calls")
	}
	if bytes.Equal(ch1.ServerPublic, ch2.ServerPublic) || ch1.SessionID == ch2.SessionID {
		t.Error("decoy B or session reused")
	}
	other, _ := e.srv.BeginLogin(ctx, "trent")
	if bytes.Equal(other.Salt, ch1.Salt) {
		t.Error("two unknown users share a salt")
	}

	// Another instance with the same key gives the same salt; with a
	// different key, a different one.
	e2 := newEnv(t, WithDecoyKey(key), WithSaltLength(20))
	if ch, _ := e2.srv.BeginLogin(ctx, "mallory"); !bytes.Equal(ch.Salt, ch1.Salt) {
		t.Error("decoy salt differs between instances sharing a key")
	}
	e3 := newEnv(t, WithDecoyKey(bytes.Repeat([]byte{43}, 32)), WithSaltLength(20))
	if ch, _ := e3.srv.BeginLogin(ctx, "mallory"); bytes.Equal(ch.Salt, ch1.Salt) {
		t.Error("decoy salt does not depend on the key")
	}

	// Answering a decoy fails like a wrong password.
	cl, err := e.client.Login("mallory", []byte("anything"), ch1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Authenticate(ctx, cl.Response()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestDecoyRejectedEvenWithMatchingProof(t *testing.T) {
	// A session marked as a decoy never succeeds, even with a correct proof.
	// Mark a real session as a decoy so the proof matches.
	mem := NewMemorySessionStore()
	store := &funcSessionStore{mem: mem, consume: func(ctx context.Context, id uuid.UUID, now time.Time) ([]byte, error) {
		data, err := mem.ConsumeSession(ctx, id, now)
		if err != nil {
			return nil, err
		}
		var rec sessionRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, err
		}
		rec.Decoy = true
		return json.Marshal(rec)
	}}
	e := newEnv(t, WithSessionStore(store))
	_, cl := e.begin("alice", alicePassword)
	if _, err := e.srv.Authenticate(context.Background(), cl.Response()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestFailureReasonsLogged(t *testing.T) {
	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e := newEnv(t, WithLogger(logger))
	ctx := context.Background()

	_, cl := e.begin("alice", "wrong")
	_, _ = e.srv.Authenticate(ctx, cl.Response())
	_, cl = e.begin("nobody", "wrong")
	_, _ = e.srv.Authenticate(ctx, cl.Response())

	out := buf.String()
	for _, want := range []string{`username=alice reason="wrong client proof"`, `username=nobody reason="unknown user"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "wrong\"") || strings.Contains(out, alicePassword) {
		t.Error("log contains a password")
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRegistration(t *testing.T) {
	e := newEnv(t, WithSaltLength(24))
	r1, r2 := e.srv.NewRegistration(), e.srv.NewRegistration()
	if r1.Group != Group2048 || r1.KDF != testKDF || len(r1.Salt) != 24 {
		t.Errorf("registration = %+v", r1)
	}
	if bytes.Equal(r1.Salt, r2.Salt) {
		t.Error("salt reused")
	}
}

func TestServerNewVerifier(t *testing.T) {
	e := newEnv(t)
	v, err := e.srv.NewVerifier([]byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.CheckVerifier(v); err != nil {
		t.Fatal(err)
	}
	e.users.SetVerifier("carol", v)
	_, cl := e.begin("carol", "s3cret")
	if _, err := e.srv.Authenticate(context.Background(), cl.Response()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckVerifier(t *testing.T) {
	e := newEnv(t, WithSaltLength(20))
	good := func() *Verifier {
		v, err := e.client.NewVerifier([]byte("pw"), e.srv.NewRegistration())
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if err := e.srv.CheckVerifier(good()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	longer := good()
	longer.Salt = append(longer.Salt, 1, 2, 3)
	if err := e.srv.CheckVerifier(longer); err != nil {
		t.Errorf("longer salt: %v", err)
	}

	tests := map[string]func(*Verifier){
		"other group":   func(v *Verifier) { *v = *testVerifier(t, Group3072) },
		"other kdf":     func(v *Verifier) { v.KDF.Iterations = 2 },
		"short salt":    func(v *Verifier) { v.Salt = v.Salt[:16] },
		"tiny salt":     func(v *Verifier) { v.Salt = v.Salt[:4] },
		"value one":     func(v *Verifier) { v.Value = groups[Group2048].pad(big.NewInt(1)) },
		"value short":   func(v *Verifier) { v.Value = v.Value[1:] },
		"unknown group": func(v *Verifier) { v.Group = 7 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			v := good()
			mutate(v)
			if err := e.srv.CheckVerifier(v); !errors.Is(err, ErrInvalidVerifier) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestVerifierOutdated(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	// Alice registered under the old settings; the server now wants a larger
	// group and more iterations.
	old := e.users
	srv, err := New(WithUserStore(old), WithGroup(Group3072),
		WithKDFParams(KDFParams{MemoryKiB: 64, Iterations: 2, Parallelism: 1}), WithLogger(discardLogger))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := srv.BeginLogin(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Group != Group2048 || ch.KDF != testKDF {
		t.Errorf("challenge does not use the stored verifier's parameters: %+v", ch)
	}
	cl, _ := e.client.Login("alice", []byte(alicePassword), ch)
	res, err := srv.Authenticate(ctx, cl.Response())
	if err != nil {
		t.Fatal(err)
	}
	if !res.VerifierOutdated {
		t.Error("VerifierOutdated = false")
	}

	// The client upgrades, and the next login is current.
	v, err := e.client.NewVerifier([]byte(alicePassword), srv.NewRegistration())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.CheckVerifier(v); err != nil {
		t.Fatal(err)
	}
	old.SetVerifier("alice", v)
	ch, _ = srv.BeginLogin(ctx, "alice")
	cl, _ = e.client.Login("alice", []byte(alicePassword), ch)
	if res, err = srv.Authenticate(ctx, cl.Response()); err != nil || res.VerifierOutdated {
		t.Errorf("after upgrade: %+v, %v", res, err)
	}
}

func TestConcurrentLogins(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		user, pw := "alice", alicePassword
		if i%2 == 1 {
			user, pw = "bob", bobPassword
		}
		wg.Go(func() {
			ch, err := e.srv.BeginLogin(ctx, user)
			if err != nil {
				errs <- err
				return
			}
			cl, err := e.client.Login(user, []byte(pw), ch)
			if err != nil {
				errs <- err
				return
			}
			res, err := e.srv.FinishLogin(ctx, cl.Response())
			if err == nil && res.Subject != user {
				err = errors.New("wrong subject " + res.Subject)
			}
			if err == nil {
				err = cl.VerifyServer(res.ServerProof)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestConcurrentFinishOfOneSession(t *testing.T) {
	e := newEnv(t)
	_, cl := e.begin("alice", alicePassword)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if _, err := e.srv.Authenticate(context.Background(), cl.Response()); err == nil {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Errorf("%d concurrent finishes succeeded, want 1", ok.Load())
	}
}

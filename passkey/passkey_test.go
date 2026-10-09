package passkey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

var ctx = context.Background()

func TestRegisterAndDiscoverableLogin(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")

	stored := e.storedCredential("alice")
	if !bytes.Equal(stored.ID, cred.id) || stored.Subject != "alice" || stored.Label != "test key" {
		t.Errorf("stored credential = %+v", stored)
	}
	if !stored.CreatedAt.Equal(e.clock.Now()) || !stored.LastUsedAt.IsZero() {
		t.Errorf("CreatedAt = %v, LastUsedAt = %v", stored.CreatedAt, stored.LastUsedAt)
	}
	if !stored.UserVerified || stored.BackupEligible || stored.AttestationFormat != "none" || len(stored.PublicKey) == 0 {
		t.Errorf("stored credential flags/attestation = %+v", stored)
	}
	if !slices.Equal(stored.Transports, []string{"internal", "hybrid"}) {
		t.Errorf("Transports = %v", stored.Transports)
	}

	e.clock.Advance(time.Minute)
	ch := e.beginLogin()
	pair, err := e.p.FinishLogin(ctx, ch.CeremonyID, e.va.get(ch, cred, true))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if pair.AccessToken != "access-alice" {
		t.Errorf("AccessToken = %q", pair.AccessToken)
	}
	if calls := e.issuer.Calls(); len(calls) != 1 || calls[0].subject != "alice" || calls[0].extra != nil {
		t.Errorf("issuer calls = %+v", calls)
	}
	if got := e.storedCredential("alice"); !got.LastUsedAt.Equal(e.clock.Now()) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, e.clock.Now())
	}
}

func TestChallengeOptions(t *testing.T) {
	e := newEnv(t, WithCeremonyTTL(2*time.Minute))
	ch, err := e.p.BeginRegistration(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !ch.ExpiresAt.Equal(e.clock.Now().Add(2 * time.Minute)) {
		t.Errorf("ExpiresAt = %v", ch.ExpiresAt)
	}
	var opts struct {
		PublicKey struct {
			RP          struct{ ID, Name string }
			User        struct{ ID, Name, DisplayName string }
			Timeout     int
			Attestation string
			Selection   struct {
				ResidentKey      string
				UserVerification string
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	mustUnmarshal(t, ch.Options, &opts)
	pk := opts.PublicKey
	if pk.RP.ID != testRPID || pk.RP.Name != "Example" {
		t.Errorf("rp = %+v", pk.RP)
	}
	if pk.User.ID != b64.EncodeToString(e.alice.Handle) || pk.User.Name != "alice@example.com" || pk.User.DisplayName != "alice@example.com" {
		t.Errorf("user = %+v", pk.User)
	}
	if pk.Timeout != 120000 || pk.Attestation != "none" {
		t.Errorf("timeout = %d, attestation = %q", pk.Timeout, pk.Attestation)
	}
	if pk.Selection.ResidentKey != "required" || pk.Selection.UserVerification != "required" {
		t.Errorf("authenticatorSelection = %+v", pk.Selection)
	}
}

func TestDisplayNameUsedWhenSet(t *testing.T) {
	u := &waUser{user: User{Name: "a", DisplayName: "Alice A."}}
	if u.WebAuthnDisplayName() != "Alice A." {
		t.Errorf("WebAuthnDisplayName = %q", u.WebAuthnDisplayName())
	}
}

func TestExcludeCredentials(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")
	ch, err := e.p.BeginRegistration(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	var opts creationOptions
	mustUnmarshal(t, ch.Options, &opts)
	if len(opts.PublicKey.ExcludeCredentials) != 1 || opts.PublicKey.ExcludeCredentials[0].ID != b64.EncodeToString(cred.id) {
		t.Errorf("excludeCredentials = %+v", opts.PublicKey.ExcludeCredentials)
	}
}

func TestBeginLoginFor(t *testing.T) {
	for _, sendHandle := range []bool{true, false} {
		e := newEnv(t)
		cred := e.register("alice")
		e.register("alice")
		ch, err := e.p.BeginLoginFor(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		var opts requestOptions
		mustUnmarshal(t, ch.Options, &opts)
		if len(opts.PublicKey.AllowCredentials) != 2 {
			t.Errorf("allowCredentials = %+v", opts.PublicKey.AllowCredentials)
		}
		got, err := e.p.Authenticate(ctx, ch.CeremonyID, e.va.get(ch, cred, sendHandle))
		if err != nil {
			t.Fatalf("sendHandle=%v: Authenticate: %v", sendHandle, err)
		}
		if got.Subject != "alice" || !bytes.Equal(got.ID, cred.id) {
			t.Errorf("credential = %+v", got)
		}
	}
}

func TestBeginLoginForErrors(t *testing.T) {
	e := newEnv(t)
	if _, err := e.p.BeginLoginFor(ctx, "nobody"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("unknown user: err = %v", err)
	}
	if _, err := e.p.BeginLoginFor(ctx, "alice"); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("no credentials: err = %v", err)
	}
	if _, err := e.p.BeginRegistration(ctx, "nobody"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("BeginRegistration unknown user: err = %v", err)
	}
}

func TestBeginLoginForOtherUsersCredential(t *testing.T) {
	e := newEnv(t)
	aliceCred := e.register("alice")
	e.register("bob")
	ch, err := e.p.BeginLoginFor(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, sendHandle := range []bool{true, false} {
		ch2 := ch
		if !sendHandle {
			if ch2, err = e.p.BeginLoginFor(ctx, "bob"); err != nil {
				t.Fatal(err)
			}
		}
		_, err := e.p.Authenticate(ctx, ch2.CeremonyID, e.va.get(ch2, aliceCred, sendHandle))
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("sendHandle=%v: err = %v, want ErrInvalidCredentials", sendHandle, err)
		}
	}
}

func TestCeremonySingleUse(t *testing.T) {
	e := newEnv(t)
	ch, err := e.p.BeginRegistration(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	resp, cred := e.va.create(ch)
	if _, err := e.p.FinishRegistration(ctx, "alice", ch.CeremonyID, resp, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.FinishRegistration(ctx, "alice", ch.CeremonyID, resp, ""); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("replayed registration: err = %v", err)
	}

	lc := e.beginLogin()
	assertion := e.va.get(lc, cred, true)
	if _, err := e.p.Authenticate(ctx, lc.CeremonyID, assertion); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.Authenticate(ctx, lc.CeremonyID, assertion); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("replayed login: err = %v", err)
	}
	// Replaying the assertion against a fresh ceremony fails on the challenge.
	if _, err := e.p.Authenticate(ctx, e.beginLogin().CeremonyID, assertion); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("assertion on new ceremony: err = %v", err)
	}
}

func TestFailedFinishConsumesCeremony(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")
	ch := e.beginLogin()
	if _, err := e.p.Authenticate(ctx, ch.CeremonyID, []byte("{")); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
	if _, err := e.p.Authenticate(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("retry after failure: err = %v", err)
	}
}

func TestCeremonyExpired(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")
	ch := e.beginLogin()
	e.clock.Advance(DefaultConfig().CeremonyTTL)
	if _, err := e.p.Authenticate(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("err = %v, want ErrInvalidCeremony", err)
	}
}

func TestCeremonyExpiryCheckedWhenStoreDoesNot(t *testing.T) {
	// A store that hands back data regardless of expiry.
	data := mustMarshal(t, ceremonyRecord{Kind: kindLogin, ExpiresAt: time.Now().Add(-time.Second)})
	e := newEnv(t, WithCeremonyStore(&failingCeremonyStore{CeremonyStore: NewMemoryCeremonyStore(), consumeData: data}))
	if _, err := e.p.Authenticate(ctx, uuid.New(), nil); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("err = %v, want ErrInvalidCeremony", err)
	}
}

func TestUnknownCeremony(t *testing.T) {
	e := newEnv(t)
	if _, err := e.p.Authenticate(ctx, uuid.New(), nil); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("Authenticate: err = %v", err)
	}
	if _, err := e.p.FinishRegistration(ctx, "alice", uuid.New(), nil, ""); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("FinishRegistration: err = %v", err)
	}
}

func TestCeremonyKindMismatch(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")

	reg, err := e.p.BeginRegistration(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.Authenticate(ctx, reg.CeremonyID, e.va.assert(cred, "x", testRPID, true)); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("registration ceremony used for login: err = %v", err)
	}

	login := e.beginLogin()
	if _, err := e.p.FinishRegistration(ctx, "alice", login.CeremonyID, nil, ""); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("login ceremony used for registration: err = %v", err)
	}
}

func TestRegistrationSubjectMismatch(t *testing.T) {
	e := newEnv(t)
	ch, err := e.p.BeginRegistration(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := e.va.create(ch)
	if _, err := e.p.FinishRegistration(ctx, "bob", ch.CeremonyID, resp, ""); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("err = %v, want ErrInvalidCeremony", err)
	}
	if creds, _ := e.creds.ListCredentials(ctx, "bob"); len(creds) != 0 {
		t.Errorf("bob has credentials %+v", creds)
	}
	// Bob's attempt did not use up alice's ceremony.
	if _, err := e.p.FinishRegistration(ctx, "alice", ch.CeremonyID, resp, ""); err != nil {
		t.Errorf("alice's finish after bob's attempt: %v", err)
	}
}

func TestRegistrationRejected(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(e *env, opts *creationOptions)
		resp   func(e *env, ch *Challenge) []byte
	}{
		{name: "wrong origin", mutate: func(e *env, _ *creationOptions) { e.va.origin = "https://evil.example" }},
		{name: "http origin", mutate: func(e *env, _ *creationOptions) { e.va.origin = "http://example.com" }},
		{name: "wrong rp id", mutate: func(_ *env, o *creationOptions) { o.PublicKey.RP.ID = "evil.example" }},
		{name: "tampered challenge", mutate: func(_ *env, o *creationOptions) { o.PublicKey.Challenge = b64.EncodeToString(make([]byte, 32)) }},
		{name: "no user verification", mutate: func(e *env, _ *creationOptions) { e.va.userVerified = false }},
		{name: "backup state without eligibility", mutate: func(e *env, _ *creationOptions) { e.va.backupState = true }},
		{name: "malformed", resp: func(*env, *Challenge) []byte { return []byte(`{"id":`) }},
		{name: "empty", resp: func(*env, *Challenge) []byte { return nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			ch, err := e.p.BeginRegistration(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}
			var resp []byte
			if tt.resp != nil {
				resp = tt.resp(e, ch)
			} else {
				var opts creationOptions
				mustUnmarshal(t, ch.Options, &opts)
				tt.mutate(e, &opts)
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				cred := &virtualCredential{id: randomBytes(t, 16), key: key, rpID: opts.PublicKey.RP.ID, handle: e.alice.Handle}
				resp = e.va.attest(cred, opts.PublicKey.Challenge, "webauthn.create")
			}
			if _, err := e.p.FinishRegistration(ctx, "alice", ch.CeremonyID, resp, ""); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("err = %v, want ErrInvalidResponse", err)
			}
			if creds, _ := e.creds.ListCredentials(ctx, "alice"); len(creds) != 0 {
				t.Errorf("credential saved: %+v", creds)
			}
		})
	}
}

func TestRegistrationWrongCeremonyType(t *testing.T) {
	e := newEnv(t)
	ch, err := e.p.BeginRegistration(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	var opts creationOptions
	mustUnmarshal(t, ch.Options, &opts)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cred := &virtualCredential{id: randomBytes(t, 16), key: key, rpID: testRPID, handle: e.alice.Handle}
	resp := e.va.attest(cred, opts.PublicKey.Challenge, "webauthn.get")
	if _, err := e.p.FinishRegistration(ctx, "alice", ch.CeremonyID, resp, ""); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("err = %v, want ErrInvalidResponse", err)
	}
}

func TestDuplicateCredential(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")
	// The same authenticator credential presented for bob.
	ch, err := e.p.BeginRegistration(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	var opts creationOptions
	mustUnmarshal(t, ch.Options, &opts)
	resp := e.va.attest(cred, opts.PublicKey.Challenge, "webauthn.create")
	if _, err := e.p.FinishRegistration(ctx, "bob", ch.CeremonyID, resp, ""); !errors.Is(err, ErrCredentialExists) {
		t.Errorf("err = %v, want ErrCredentialExists", err)
	}
}

func TestLoginRejected(t *testing.T) {
	tests := []struct {
		name string
		// resp builds the response to ch given alice's registered credential.
		resp func(e *env, ch *Challenge, cred *virtualCredential) []byte
	}{
		{"wrong origin", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			e.va.origin = "https://login.evil.example"
			return e.va.get(ch, cred, true)
		}},
		{"wrong rp id", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			var opts requestOptions
			mustUnmarshal(e.t, ch.Options, &opts)
			return e.va.assert(cred, opts.PublicKey.Challenge, "evil.example", true)
		}},
		{"tampered challenge", func(e *env, _ *Challenge, cred *virtualCredential) []byte {
			return e.va.assert(cred, b64.EncodeToString(make([]byte, 32)), testRPID, true)
		}},
		{"bad signature", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			forged := *cred
			forged.key = other
			return e.va.get(ch, &forged, true)
		}},
		{"unregistered credential", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			unknown := *cred
			unknown.id = randomBytes(e.t, 32)
			return e.va.get(ch, &unknown, true)
		}},
		{"another user's handle", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			stolen := *cred
			stolen.handle = e.bob.Handle
			return e.va.get(ch, &stolen, true)
		}},
		{"unknown handle", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			stolen := *cred
			stolen.handle = NewUserHandle()
			return e.va.get(ch, &stolen, true)
		}},
		{"no user handle", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			return e.va.get(ch, cred, false)
		}},
		{"no user verification", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			e.va.userVerified = false
			return e.va.get(ch, cred, true)
		}},
		{"backup eligibility changed", func(e *env, ch *Challenge, cred *virtualCredential) []byte {
			e.va.backupEligible = true
			return e.va.get(ch, cred, true)
		}},
		{"malformed", func(*env, *Challenge, *virtualCredential) []byte { return []byte(`not json`) }},
		{"empty", func(*env, *Challenge, *virtualCredential) []byte { return nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			cred := e.register("alice")
			e.register("bob")
			ch := e.beginLogin()
			_, err := e.p.FinishLogin(ctx, ch.CeremonyID, tt.resp(e, ch, cred))
			if !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Errorf("err = %v, want ErrInvalidCredentials", err)
			}
			if calls := e.issuer.Calls(); len(calls) != 0 {
				t.Errorf("tokens issued: %+v", calls)
			}
		})
	}
}

func TestUserVerificationPreferred(t *testing.T) {
	e := newEnv(t, WithUserVerification(Preferred))
	e.va.userVerified = false
	cred := e.register("alice")
	got, err := e.login(cred)
	if err != nil {
		t.Fatalf("login without UV: %v", err)
	}
	if got.UserVerified {
		t.Error("UserVerified = true")
	}
	// As in WebAuthn §7.2, a later verified login does not upgrade the
	// credential without separate authorization.
	e.va.userVerified = true
	if _, err := e.login(cred); err != nil {
		t.Fatal(err)
	}
	if e.storedCredential("alice").UserVerified {
		t.Error("stored UserVerified = true after unauthorized upgrade")
	}
}

func TestSyncedPasskeyBackupState(t *testing.T) {
	e := newEnv(t)
	e.va.backupEligible = true
	cred := e.register("alice")
	if c := e.storedCredential("alice"); !c.BackupEligible || c.BackupState {
		t.Fatalf("stored = %+v", c)
	}
	e.va.backupState = true
	got, err := e.login(cred)
	if err != nil {
		t.Fatal(err)
	}
	if !got.BackupState || !e.storedCredential("alice").BackupState {
		t.Error("BackupState not recorded")
	}
}

func TestSignCountAndCloneWarning(t *testing.T) {
	for _, allow := range []bool{false, true} {
		e := newEnv(t, WithAllowCloneWarning(allow))
		e.va.useCounter = true
		cred := e.register("alice")

		for want := uint32(1); want <= 2; want++ {
			got, err := e.login(cred)
			if err != nil {
				t.Fatalf("login %d: %v", want, err)
			}
			if got.SignCount != want || e.storedCredential("alice").SignCount != want {
				t.Errorf("SignCount = %d, want %d", got.SignCount, want)
			}
		}

		lastUse := e.storedCredential("alice").LastUsedAt
		e.clock.Advance(time.Minute)
		e.va.counter = 0 // the clone reports 1, which is not greater than 2
		got, err := e.login(cred)
		if allow {
			if err != nil || !got.CloneWarning {
				t.Errorf("allowed clone: credential = %+v, err = %v", got, err)
			}
		} else if !errors.Is(err, ErrPossibleClone) || !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("err = %v, want ErrPossibleClone and ErrInvalidCredentials", err)
		}
		stored := e.storedCredential("alice")
		if !stored.CloneWarning || stored.SignCount != 2 {
			t.Errorf("allow=%v: stored = %+v", allow, stored)
		}

		if !allow && !stored.LastUsedAt.Equal(lastUse) {
			t.Errorf("refused login changed LastUsedAt from %v to %v", lastUse, stored.LastUsedAt)
		}

		// The warning is sticky even once the counter moves on.
		e.va.counter = 10
		_, err = e.login(cred)
		if allow != (err == nil) {
			t.Errorf("allow=%v: login after warning: err = %v", allow, err)
		}
	}
}

func TestZeroCounterIsNotAClone(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")
	for range 3 {
		if _, err := e.login(cred); err != nil {
			t.Fatal(err)
		}
	}
	if e.storedCredential("alice").CloneWarning {
		t.Error("CloneWarning set for an authenticator without a counter")
	}
}

func TestClaimsProvider(t *testing.T) {
	var gotSubject string
	e := newEnv(t, WithClaimsProvider(func(_ context.Context, subject string) (map[string]any, error) {
		gotSubject = subject
		return map[string]any{"role": "admin"}, nil
	}))
	cred := e.register("alice")
	ch := e.beginLogin()
	if _, err := e.p.FinishLogin(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); err != nil {
		t.Fatal(err)
	}
	calls := e.issuer.Calls()
	if gotSubject != "alice" || len(calls) != 1 || calls[0].extra["role"] != "admin" {
		t.Errorf("subject = %q, calls = %+v", gotSubject, calls)
	}
}

func TestClaimsProviderError(t *testing.T) {
	errProvider := errors.New("claims down")
	e := newEnv(t, WithClaimsProvider(func(context.Context, string) (map[string]any, error) { return nil, errProvider }))
	cred := e.register("alice")
	ch := e.beginLogin()
	if _, err := e.p.FinishLogin(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, errProvider) {
		t.Errorf("err = %v", err)
	}
	if len(e.issuer.Calls()) != 0 {
		t.Error("tokens issued despite provider error")
	}
}

func TestIssuerError(t *testing.T) {
	e := newEnv(t)
	e.issuer.failErr = auth.ErrReservedClaim
	cred := e.register("alice")
	ch := e.beginLogin()
	if _, err := e.p.FinishLogin(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, auth.ErrReservedClaim) {
		t.Errorf("err = %v", err)
	}
}

func TestFinishLoginWithoutIssuer(t *testing.T) {
	e := newEnv(t, WithTokenIssuer(nil))
	cred := e.register("alice")
	ch := e.beginLogin()
	resp := e.va.get(ch, cred, true)
	if _, err := e.p.FinishLogin(ctx, ch.CeremonyID, resp); !errors.Is(err, auth.ErrNotConfigured) {
		t.Errorf("FinishLogin: err = %v", err)
	}
	// The ceremony was not consumed, so Authenticate can still use it.
	if _, err := e.p.Authenticate(ctx, ch.CeremonyID, resp); err != nil {
		t.Errorf("Authenticate: %v", err)
	}
}

func TestWithRealAuthorizer(t *testing.T) {
	a, err := auth.New(ctx, auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	e := newEnv(t, WithTokenIssuer(a))
	cred := e.register("alice")
	ch := e.beginLogin()
	pair, err := e.p.FinishLogin(ctx, ch.CeremonyID, e.va.get(ch, cred, true))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil || claims.Subject != "alice" {
		t.Fatalf("claims = %+v, err = %v", claims, err)
	}
	if _, err := a.Refresh(ctx, pair.RefreshToken); err != nil {
		t.Errorf("Refresh: %v", err)
	}
}

func TestListAndDeleteCredentials(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")
	e.clock.Advance(time.Second)
	e.register("alice")
	bobCred := e.register("bob")

	list, err := e.p.ListCredentials(ctx, "alice")
	if err != nil || len(list) != 2 || !bytes.Equal(list[0].ID, cred.id) {
		t.Fatalf("ListCredentials = %+v, %v", list, err)
	}
	if err := e.p.DeleteCredential(ctx, "alice", bobCred.id); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("deleting bob's credential as alice: err = %v", err)
	}
	if err := e.p.DeleteCredential(ctx, "alice", cred.id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.login(cred); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("login with deleted credential: err = %v", err)
	}
	if _, err := e.login(bobCred); err != nil {
		t.Errorf("bob's login: %v", err)
	}
}

func TestStoreErrors(t *testing.T) {
	t.Run("save ceremony", func(t *testing.T) {
		e := newEnv(t, WithCeremonyStore(&failingCeremonyStore{CeremonyStore: NewMemoryCeremonyStore(), saveErr: errStore}))
		if _, err := e.p.BeginLogin(ctx); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("consume ceremony", func(t *testing.T) {
		e := newEnv(t, WithCeremonyStore(&failingCeremonyStore{CeremonyStore: NewMemoryCeremonyStore(), consumeErr: errStore}))
		if _, err := e.p.Authenticate(ctx, uuid.New(), nil); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("corrupt ceremony", func(t *testing.T) {
		e := newEnv(t, WithCeremonyStore(&failingCeremonyStore{CeremonyStore: NewMemoryCeremonyStore(), consumeData: []byte("{")}))
		_, err := e.p.Authenticate(ctx, uuid.New(), nil)
		if err == nil || errors.Is(err, ErrInvalidCeremony) || errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("err = %v, want an internal error", err)
		}
	})

	newFailing := func(t *testing.T) (*env, *failingUserStore, *failingCredentialStore) {
		users := &failingUserStore{}
		creds := &failingCredentialStore{}
		e := newEnv(t)
		users.UserStore, creds.CredentialStore = e.users, e.creds
		e2 := newEnv(t, WithUserStore(users), WithCredentialStore(creds))
		// Share alice and bob, and the virtual authenticator, with e.
		e2.users, e2.creds, e2.alice, e2.bob = e.users, e.creds, e.alice, e.bob
		return e2, users, creds
	}

	t.Run("list credentials", func(t *testing.T) {
		e, _, creds := newFailing(t)
		cred := e.register("alice")
		creds.set(func() { creds.listErr = errStore })
		if _, err := e.p.BeginRegistration(ctx, "alice"); !errors.Is(err, errStore) {
			t.Errorf("BeginRegistration: err = %v", err)
		}
		if _, err := e.p.BeginLoginFor(ctx, "alice"); !errors.Is(err, errStore) {
			t.Errorf("BeginLoginFor: err = %v", err)
		}
		if _, err := e.p.ListCredentials(ctx, "alice"); !errors.Is(err, errStore) {
			t.Errorf("ListCredentials: err = %v", err)
		}
		if _, err := e.login(cred); !errors.Is(err, errStore) || errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("discoverable login: err = %v, want the store error", err)
		}
	})
	t.Run("lookup user by handle", func(t *testing.T) {
		e, users, _ := newFailing(t)
		cred := e.register("alice")
		users.set(func() { users.handleErr = errStore })
		if _, err := e.login(cred); !errors.Is(err, errStore) || errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("err = %v, want the store error", err)
		}
	})
	t.Run("handle mismatch", func(t *testing.T) {
		e, users, _ := newFailing(t)
		cred := e.register("alice")
		users.set(func() { users.wrongHandleResult = true })
		if _, err := e.login(cred); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("err = %v, want ErrInvalidCredentials", err)
		}
	})
	t.Run("lookup user for login", func(t *testing.T) {
		e, users, _ := newFailing(t)
		cred := e.register("alice")
		ch, err := e.p.BeginLoginFor(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		users.set(func() { users.lookupErr = errStore })
		if _, err := e.p.Authenticate(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("user deleted during login", func(t *testing.T) {
		e, users, _ := newFailing(t)
		cred := e.register("alice")
		ch, err := e.p.BeginLoginFor(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		users.set(func() { users.lookupErr = auth.ErrUserNotFound })
		if _, err := e.p.Authenticate(ctx, ch.CeremonyID, e.va.get(ch, cred, true)); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("lookup user for registration", func(t *testing.T) {
		e, users, _ := newFailing(t)
		ch, err := e.p.BeginRegistration(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := e.va.create(ch)
		users.set(func() { users.lookupErr = errStore })
		if _, err := e.p.FinishRegistration(ctx, "alice", ch.CeremonyID, resp, ""); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("create credential", func(t *testing.T) {
		e, _, creds := newFailing(t)
		ch, err := e.p.BeginRegistration(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := e.va.create(ch)
		creds.set(func() { creds.createErr = errStore })
		if _, err := e.p.FinishRegistration(ctx, "alice", ch.CeremonyID, resp, ""); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("record use", func(t *testing.T) {
		e, _, creds := newFailing(t)
		cred := e.register("alice")
		creds.set(func() { creds.recordErr = errStore })
		if _, err := e.login(cred); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("record clone warning", func(t *testing.T) {
		e, _, creds := newFailing(t)
		e.va.useCounter = true
		cred := e.register("alice")
		if _, err := e.login(cred); err != nil {
			t.Fatal(err)
		}
		e.va.counter = 0
		creds.set(func() { creds.recordErr = errStore })
		if _, err := e.login(cred); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		e, _, creds := newFailing(t)
		creds.set(func() { creds.deleteErr = errStore })
		if err := e.p.DeleteCredential(ctx, "alice", []byte{1}); !errors.Is(err, errStore) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("store returns another user's credential", func(t *testing.T) {
		e, _, creds := newFailing(t)
		e.register("alice")
		bobCred := e.register("bob")
		creds.set(func() { creds.extra = []Credential{e.storedCredential("bob")} })
		// alice's handle with bob's key: the foreign record must be ignored.
		forged := *bobCred
		forged.handle = e.alice.Handle
		if _, err := e.login(&forged); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("err = %v, want ErrInvalidCredentials", err)
		}
	})
}

func TestLoginFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	e := newEnv(t, WithLogger(newTestLogger(&buf)))
	ch := e.beginLogin()
	_, _ = e.p.Authenticate(ctx, ch.CeremonyID, []byte("{}"))
	if !strings.Contains(buf.String(), "login refused") {
		t.Errorf("log = %q", buf.String())
	}
}

func TestNewValidation(t *testing.T) {
	users, creds := NewMemoryUserStore(), NewMemoryCredentialStore()
	rp := WithRelyingParty(testRPID, "Example", testOrigin)
	tests := []struct {
		name string
		opts []Option
		want string
	}{
		{"no user store", []Option{rp, WithCredentialStore(creds)}, "no UserStore"},
		{"no credential store", []Option{rp, WithUserStore(users)}, "no CredentialStore"},
		{"no relying party", []Option{WithUserStore(users), WithCredentialStore(creds)}, "RPID is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
	if _, err := New(rp, WithUserStore(users)); !errors.Is(err, auth.ErrNotConfigured) {
		t.Errorf("missing store: err = %v, want ErrNotConfigured", err)
	}
	p, err := New(rp, WithUserStore(users), WithCredentialStore(creds))
	if err != nil {
		t.Fatalf("minimal options: %v", err)
	}
	if _, ok := p.s.ceremonies.(*MemoryCeremonyStore); !ok || p.s.logger == nil {
		t.Error("defaults not applied")
	}
}

func TestNewCopiesOrigins(t *testing.T) {
	origins := []string{testOrigin}
	cfg := DefaultConfig()
	cfg.RPID, cfg.RPDisplayName, cfg.RPOrigins = testRPID, "Example", origins
	p, err := New(WithConfig(cfg), WithUserStore(NewMemoryUserStore()), WithCredentialStore(NewMemoryCredentialStore()))
	if err != nil {
		t.Fatal(err)
	}
	origins[0] = "https://evil.example"
	if p.s.RPOrigins[0] != testOrigin {
		t.Error("RPOrigins aliases the caller's slice")
	}
}

func TestChallengeJSON(t *testing.T) {
	e := newEnv(t)
	ch := e.beginLogin()
	var decoded map[string]json.RawMessage
	mustUnmarshal(t, mustMarshal(t, ch), &decoded)
	for _, k := range []string{"ceremonyId", "options", "expiresAt"} {
		if _, ok := decoded[k]; !ok {
			t.Errorf("Challenge JSON lacks %q: %s", k, mustMarshal(t, ch))
		}
	}
}

func TestAuthenticateFor(t *testing.T) {
	e := newEnv(t)
	aliceCred := e.register("alice")
	bobCred := e.register("bob")

	// Discoverable ceremony, own credential.
	ch := e.beginLogin()
	got, err := e.p.AuthenticateFor(ctx, "alice", ch.CeremonyID, e.va.get(ch, aliceCred, true))
	if err != nil || got.Subject != "alice" {
		t.Fatalf("own passkey: credential = %+v, err = %v", got, err)
	}

	// BeginLoginFor ceremony for the same subject.
	ch, err = e.p.BeginLoginFor(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.AuthenticateFor(ctx, "alice", ch.CeremonyID, e.va.get(ch, aliceCred, false)); err != nil {
		t.Errorf("BeginLoginFor ceremony: %v", err)
	}

	// Someone else's passkey on a discoverable ceremony is refused, and its
	// use is not recorded.
	e.clock.Advance(time.Minute)
	bobBefore := e.storedCredential("bob")
	ch = e.beginLogin()
	if _, err := e.p.AuthenticateFor(ctx, "alice", ch.CeremonyID, e.va.get(ch, bobCred, true)); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("other user's passkey: err = %v, want ErrInvalidCredentials", err)
	}
	if bobAfter := e.storedCredential("bob"); !bobAfter.LastUsedAt.Equal(bobBefore.LastUsedAt) {
		t.Errorf("refused use recorded: LastUsedAt %v -> %v", bobBefore.LastUsedAt, bobAfter.LastUsedAt)
	}

	// A ceremony begun for another subject.
	ch, err = e.p.BeginLoginFor(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.AuthenticateFor(ctx, "alice", ch.CeremonyID, e.va.get(ch, bobCred, true)); !errors.Is(err, ErrInvalidCeremony) {
		t.Errorf("bob's ceremony: err = %v, want ErrInvalidCeremony", err)
	}

	if _, err := e.p.AuthenticateFor(ctx, "", e.beginLogin().CeremonyID, nil); err == nil {
		t.Error("empty subject accepted")
	}
}

func TestStoreKey(t *testing.T) {
	id := uuid.New()
	if storeKey(id, kindLogin, "alice") != id {
		t.Error("login key is not the ceremony ID")
	}
	a, b := storeKey(id, kindRegistration, "alice"), storeKey(id, kindRegistration, "bob")
	if a == id || a == b || a != storeKey(id, kindRegistration, "alice") {
		t.Errorf("registration keys: alice %v, bob %v, id %v", a, b, id)
	}
}

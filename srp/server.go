package srp

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"uuid"

	"github.com/tpyle/auth/v2"
)

// Server registers verifiers and logs users in with SRP. It is safe for
// concurrent use. Create it with [New].
type Server struct {
	s *settings
}

// New validates the options and returns a [Server]. [WithUserStore] is
// required.
func New(opts ...Option) (*Server, error) {
	s, err := buildSettings(opts)
	if err != nil {
		return nil, err
	}
	return &Server{s: s}, nil
}

// Result is a successful login.
type Result struct {
	// Subject is the username the login was begun with.
	Subject string
	// ServerProof is M2. Send it to the client, which checks it with
	// [ClientLogin.VerifyServer] to confirm it is talking to a server that
	// holds the user's verifier.
	ServerProof []byte
	// SessionKey is K, a 32-byte secret shared with the client. Most
	// applications rely on the tokens instead and can ignore it.
	SessionKey []byte
	// VerifierOutdated reports that the user's verifier does not match the
	// current configuration (see [Server.NeedsUpgrade]). The client has just
	// shown it knows the password, so this is the moment to ask it for a new
	// verifier from [Server.NewRegistration].
	VerifierOutdated bool
	// Tokens is set by [Server.FinishLogin].
	Tokens *auth.TokenPair
}

// NewRegistration returns the configured group and KDF cost with a fresh
// random salt, for a client to create a verifier with [Client.NewVerifier].
func (srv *Server) NewRegistration() *Registration {
	salt := make([]byte, srv.s.SaltLength)
	_, _ = rand.Read(salt) // crypto/rand.Read never fails.
	return &Registration{Group: srv.s.Group, KDF: srv.s.KDF, Salt: salt}
}

// NewVerifier creates a verifier for password on the server, for example to
// import existing accounts or when the client cannot run SRP during
// registration. The server then sees the password once, so prefer having the
// client create the verifier. It computes Argon2id with the configured
// cost, so limit how often it can be called.
func (srv *Server) NewVerifier(password []byte) (*Verifier, error) {
	return Client{KDFLimits: srv.s.KDFLimits}.NewVerifier(password, srv.NewRegistration())
}

// CheckVerifier reports whether a verifier received from a client may be
// stored: it must be well formed and use the configured group and KDF cost,
// with a salt at least [Config.SaltLength] bytes long. Otherwise it returns
// an error wrapping [ErrInvalidVerifier]. It cannot tell whether the
// verifier was derived from a good password, or any password at all.
func (srv *Server) CheckVerifier(v *Verifier) error {
	if err := v.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidVerifier, err)
	}
	if srv.NeedsUpgrade(v) {
		return fmt.Errorf("%w: group, KDF parameters or salt length do not match the server's", ErrInvalidVerifier)
	}
	return nil
}

// NeedsUpgrade reports whether v uses a group or KDF cost other than the
// configured ones, or a shorter salt. Such a verifier still works, but can
// only be replaced by the client, which knows the password; see
// [Result.VerifierOutdated].
func (srv *Server) NeedsUpgrade(v *Verifier) bool {
	return v.Group != srv.s.Group || v.KDF != srv.s.KDF || len(v.Salt) < srv.s.SaltLength
}

// sessionRecord is what the SessionStore holds.
type sessionRecord struct {
	Username string `json:"user"`
	Verifier string `json:"verifier"`
	// Decoy marks a login begun for an unknown user, which cannot succeed.
	Decoy     bool      `json:"decoy,omitempty"`
	Private   []byte    `json:"priv"`
	Public    []byte    `json:"pub"`
	ExpiresAt time.Time `json:"exp"`
}

// BeginLogin starts a login for username, returning the challenge to send
// to the client. Finish it with [Server.FinishLogin] or
// [Server.Authenticate].
//
// An unknown username gets a decoy challenge that looks like a real one,
// with a salt that stays the same for the username (see [WithDecoyKey]), so
// the response does not reveal whether the user exists. The login then
// fails as if the password were wrong. Errors are returned only for store
// failures and for a stored verifier that is malformed or exceeds
// [Config.KDFLimits].
func (srv *Server) BeginLogin(ctx context.Context, username string) (*Challenge, error) {
	encoded, err := srv.s.users.LookupVerifier(ctx, username)
	var v *Verifier
	decoy := errors.Is(err, auth.ErrUserNotFound)
	switch {
	case decoy:
		v = srv.decoyVerifier(username)
	case err != nil:
		return nil, fmt.Errorf("srp: looking up verifier: %w", err)
	default:
		if v, err = ParseVerifier(encoded); err != nil {
			return nil, fmt.Errorf("srp: stored verifier for %q: %w", username, err)
		}
		if err := v.KDF.within(srv.s.KDFLimits); err != nil {
			return nil, fmt.Errorf("srp: stored verifier for %q: %w: %w", username, ErrInvalidVerifier, err)
		}
	}

	p := groups[v.Group]
	vInt := new(big.Int).SetBytes(v.Value)
	var b, B *big.Int
	for {
		b = randomExponent()
		B = p.serverPublic(vInt, b)
		if p.validPublic(B) {
			break
		}
	}

	expires := srv.s.now().Add(srv.s.SessionTTL)
	data, err := json.Marshal(sessionRecord{
		Username:  username,
		Verifier:  v.String(),
		Decoy:     decoy,
		Private:   b.Bytes(),
		Public:    p.pad(B),
		ExpiresAt: expires,
	})
	if err != nil {
		return nil, fmt.Errorf("srp: encoding session: %w", err)
	}
	id := uuid.New()
	if err := srv.s.sessions.SaveSession(ctx, id, data, expires); err != nil {
		return nil, fmt.Errorf("srp: saving session: %w", err)
	}
	return &Challenge{
		SessionID:    id,
		Group:        v.Group,
		KDF:          v.KDF,
		Salt:         v.Salt,
		ServerPublic: p.pad(B),
		ExpiresAt:    expires,
	}, nil
}

// decoyVerifier returns a verifier for an unknown user. Its salt is derived
// from the decoy key and username, so it is stable; its value is random,
// which is indistinguishable from a real one since only B = k*v + g^b is
// revealed.
func (srv *Server) decoyVerifier(username string) *Verifier {
	salt, err := hkdf.Key(sha256.New, srv.s.decoyKey, nil, "srp decoy salt\x00"+username, srv.s.SaltLength)
	if err != nil {
		// Only possible for lengths over 255*32 bytes, which Validate rejects.
		panic(err)
	}
	p := groups[srv.s.Group]
	value := make([]byte, p.size)
	for {
		_, _ = rand.Read(value) // crypto/rand.Read never fails.
		if v := new(big.Int).SetBytes(value); v.Cmp(big.NewInt(1)) > 0 && v.Cmp(p.n) < 0 {
			break
		}
	}
	return &Verifier{Group: srv.s.Group, KDF: srv.s.KDF, Salt: salt, Value: value}
}

// Authenticate checks the client's response to a challenge. On success the
// returned [Result] holds the user and the server's proof, which should be
// sent back to the client.
//
// It returns [ErrInvalidSession] if the session cannot be used and
// [auth.ErrInvalidCredentials] if the proof is wrong (a wrong password or
// an unknown user) or the response is malformed. The reason is logged at
// debug level. Each session can be finished once, successfully or not, so
// each BeginLogin allows a single password guess.
func (srv *Server) Authenticate(ctx context.Context, resp LoginResponse) (*Result, error) {
	rec, err := srv.consumeSession(ctx, resp.SessionID)
	if err != nil {
		return nil, err
	}
	v, err := ParseVerifier(rec.Verifier)
	if err != nil {
		return nil, fmt.Errorf("srp: decoding session: %w", err)
	}
	p := groups[v.Group]
	A, ok := p.decodePublic(resp.ClientPublic)
	if !ok {
		return nil, srv.loginFailed(ctx, rec, "client public value out of range")
	}
	B := new(big.Int).SetBytes(rec.Public)
	u := p.scramble(A, B)
	if u.Sign() == 0 {
		return nil, srv.loginFailed(ctx, rec, "scrambling parameter is zero")
	}
	S := p.serverSecret(A, new(big.Int).SetBytes(v.Value), u, new(big.Int).SetBytes(rec.Private))
	K := p.sessionKey(S)
	m1 := p.clientProof(rec.Username, v.Salt, A, B, K)
	if rec.Decoy {
		// The proof was computed anyway, so that unknown users take as long
		// to reject as wrong passwords.
		return nil, srv.loginFailed(ctx, rec, "unknown user")
	}
	if subtle.ConstantTimeCompare(m1, resp.ClientProof) != 1 {
		return nil, srv.loginFailed(ctx, rec, "wrong client proof")
	}
	return &Result{
		Subject:          rec.Username,
		ServerProof:      p.serverProof(A, m1, K),
		SessionKey:       K,
		VerifierOutdated: srv.NeedsUpgrade(v),
	}, nil
}

// FinishLogin authenticates the response, as [Server.Authenticate] does, and
// issues a new token pair (a new refresh-token family) for the user through
// the [TokenIssuer], in [Result.Tokens]. Extra claims come from the
// [auth.ClaimsProvider] set with [WithClaimsProvider].
func (srv *Server) FinishLogin(ctx context.Context, resp LoginResponse) (*Result, error) {
	if srv.s.issuer == nil {
		return nil, fmt.Errorf("%w: no TokenIssuer", auth.ErrNotConfigured)
	}
	res, err := srv.Authenticate(ctx, resp)
	if err != nil {
		return nil, err
	}
	var extra map[string]any
	if srv.s.claimsProvider != nil {
		if extra, err = srv.s.claimsProvider(ctx, res.Subject); err != nil {
			return nil, fmt.Errorf("srp: claims provider: %w", err)
		}
	}
	if res.Tokens, err = srv.s.issuer.IssueTokenPair(ctx, res.Subject, extra); err != nil {
		return nil, fmt.Errorf("srp: issuing tokens: %w", err)
	}
	return res, nil
}

// consumeSession takes the session out of the store and checks it has not
// expired. The session is consumed even if the login then fails.
func (srv *Server) consumeSession(ctx context.Context, id uuid.UUID) (*sessionRecord, error) {
	now := srv.s.now()
	data, err := srv.s.sessions.ConsumeSession(ctx, id, now)
	if errors.Is(err, ErrSessionNotFound) {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, fmt.Errorf("srp: consuming session: %w", err)
	}
	var rec sessionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("srp: decoding session: %w", err)
	}
	// The store is trusted to expire sessions, but the time is checked again
	// so a store that ignores now cannot extend the window.
	if !now.Before(rec.ExpiresAt) {
		return nil, ErrInvalidSession
	}
	return &rec, nil
}

// loginFailed logs why a login was refused and returns the error callers see.
func (srv *Server) loginFailed(ctx context.Context, rec *sessionRecord, reason string) error {
	srv.s.logger.DebugContext(ctx, "srp: login refused", "username", rec.Username, "reason", reason)
	return auth.ErrInvalidCredentials
}

package srp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"time"

	"uuid"
)

// Registration is what a client needs to create a verifier: the server's
// current group, KDF cost and a fresh salt. Get one from
// [Server.NewRegistration] and pass it to [Client.NewVerifier].
type Registration struct {
	Group Group     `json:"group"`
	KDF   KDFParams `json:"kdf"`
	Salt  []byte    `json:"salt"`
}

// Challenge is the result of [Server.BeginLogin], to be sent to the client.
// Byte fields are standard base64 in JSON.
type Challenge struct {
	// SessionID identifies the login. The client sends it back in its
	// [LoginResponse].
	SessionID uuid.UUID `json:"sessionId"`
	// Group, KDF and Salt come from the user's verifier.
	Group Group     `json:"group"`
	KDF   KDFParams `json:"kdf"`
	Salt  []byte    `json:"salt"`
	// ServerPublic is B, big-endian and padded to the length of N.
	ServerPublic []byte `json:"serverPublic"`
	// ExpiresAt is when the login can no longer be finished.
	ExpiresAt time.Time `json:"expiresAt"`
}

// LoginResponse is the client's answer to a [Challenge]. Byte fields are
// standard base64 in JSON.
type LoginResponse struct {
	// SessionID is [Challenge.SessionID].
	SessionID uuid.UUID `json:"sessionId"`
	// ClientPublic is A, big-endian and padded to the length of N.
	ClientPublic []byte `json:"clientPublic"`
	// ClientProof is M1, which proves the client knows the password.
	ClientProof []byte `json:"clientProof"`
}

// Client implements the client side of the protocol in Go, for Go clients
// and tests. Browser clients implement the same steps in JavaScript (see
// the wiki). The zero value is ready to use.
type Client struct {
	// KDFLimits caps the Argon2id cost the client will compute, so a
	// malicious server cannot make it exhaust its memory. The zero value
	// means [DefaultKDFLimits].
	KDFLimits KDFParams
}

func (c Client) limits() KDFParams {
	if c.KDFLimits == (KDFParams{}) {
		return DefaultKDFLimits()
	}
	return c.KDFLimits
}

// NewVerifier derives a verifier for password with the group, cost and salt
// in reg. A nil reg, or one with no salt, uses [Group3072],
// [DefaultKDFParams] and a new 16-byte salt. The password is used as given;
// normalize it (for example to Unicode NFC) the same way before
// registration and every login.
//
// It returns an error wrapping [ErrInvalidVerifier] if reg asks for an
// unsupported group, invalid parameters or parameters over the limits.
func (c Client) NewVerifier(password []byte, reg *Registration) (*Verifier, error) {
	r := Registration{Group: Group3072, KDF: DefaultKDFParams()}
	if reg != nil {
		r = *reg
	}
	if len(r.Salt) == 0 {
		r.Salt = make([]byte, minSaltLength)
		_, _ = rand.Read(r.Salt) // crypto/rand.Read never fails.
	}
	p, ok := groups[r.Group]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported group %d", ErrInvalidVerifier, int(r.Group))
	}
	if err := r.KDF.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVerifier, err)
	}
	if err := r.KDF.within(c.limits()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVerifier, err)
	}
	v := &Verifier{Group: r.Group, KDF: r.KDF, Salt: bytes.Clone(r.Salt)}
	v.Value = p.pad(p.verifier(deriveX(password, v.Salt, v.KDF)))
	if err := v.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVerifier, err)
	}
	return v, nil
}

// Login answers a challenge for username and password. Send
// [ClientLogin.Response] to the server, then check the server's proof with
// [ClientLogin.VerifyServer]. username must be exactly the string the
// challenge was begun with.
//
// It returns an error wrapping [ErrInvalidChallenge] if the challenge is
// malformed, uses an unsupported group or exceeds the KDF limits, or if
// its public value is unsafe.
func (c Client) Login(username string, password []byte, ch *Challenge) (*ClientLogin, error) {
	p, ok := groups[ch.Group]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported group %d", ErrInvalidChallenge, int(ch.Group))
	}
	if err := ch.KDF.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidChallenge, err)
	}
	if err := ch.KDF.within(c.limits()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidChallenge, err)
	}
	if len(ch.Salt) == 0 {
		return nil, fmt.Errorf("%w: no salt", ErrInvalidChallenge)
	}
	B, ok := p.decodePublic(ch.ServerPublic)
	if !ok {
		return nil, fmt.Errorf("%w: server public value out of range", ErrInvalidChallenge)
	}

	x := deriveX(password, ch.Salt, ch.KDF)
	var a, A, u *big.Int
	for {
		a = randomExponent()
		A = p.clientPublic(a)
		u = p.scramble(A, B)
		// Retrying on u = 0 is what RFC 5054 asks of the server's B; doing it
		// here, where the random value is chosen, avoids aborting.
		if p.validPublic(A) && u.Sign() != 0 {
			break
		}
	}
	K := p.sessionKey(p.clientSecret(B, x, a, u))
	m1 := p.clientProof(username, ch.Salt, A, B, K)
	return &ClientLogin{
		resp: LoginResponse{SessionID: ch.SessionID, ClientPublic: p.pad(A), ClientProof: m1},
		m2:   p.serverProof(A, m1, K),
		key:  K,
	}, nil
}

// ClientLogin is a login in progress on the client.
type ClientLogin struct {
	resp     LoginResponse
	m2       []byte
	key      []byte
	verified bool
}

// Response returns the message to send to the server.
func (l *ClientLogin) Response() LoginResponse {
	r := l.resp
	r.ClientPublic = bytes.Clone(r.ClientPublic)
	r.ClientProof = bytes.Clone(r.ClientProof)
	return r
}

// VerifyServer checks the server's proof (M2, [Result.ServerProof]). Success
// shows the server holds the user's verifier, not just that it accepted the
// login. It returns [ErrInvalidServerProof] otherwise; the client should
// then distrust the response, including any tokens in it.
func (l *ClientLogin) VerifyServer(serverProof []byte) error {
	if subtle.ConstantTimeCompare(serverProof, l.m2) != 1 {
		return ErrInvalidServerProof
	}
	l.verified = true
	return nil
}

// SessionKey returns K, a 32-byte secret shared with the server, after
// [ClientLogin.VerifyServer] succeeds, and nil before.
func (l *ClientLogin) SessionKey() []byte {
	if !l.verified {
		return nil
	}
	return bytes.Clone(l.key)
}

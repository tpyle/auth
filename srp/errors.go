package srp

import "errors"

// Errors returned by the package. They may be wrapped, so compare them with
// [errors.Is]. Failed logins return [auth.ErrInvalidCredentials] from the
// core package.
var (
	// ErrInvalidSession means the session ID in a [LoginResponse] is unknown,
	// expired or already used. The client should start over.
	ErrInvalidSession = errors.New("srp: invalid or expired session")

	// ErrInvalidVerifier means a verifier is malformed, uses an unsupported
	// group, or does not meet the server's policy (see
	// [Server.CheckVerifier]).
	ErrInvalidVerifier = errors.New("srp: invalid verifier")

	// ErrInvalidChallenge is returned by [Client.Login] for a challenge it
	// refuses to answer.
	ErrInvalidChallenge = errors.New("srp: invalid challenge")

	// ErrInvalidServerProof is returned by [ClientLogin.VerifyServer] when
	// the server failed to prove it knows the user's verifier.
	ErrInvalidServerProof = errors.New("srp: invalid server proof")

	// ErrSessionNotFound must be returned (optionally wrapped) by
	// [SessionStore.ConsumeSession] when no unexpired session has the given
	// ID. Callers of this package see [ErrInvalidSession] instead.
	ErrSessionNotFound = errors.New("srp: session not found")
)

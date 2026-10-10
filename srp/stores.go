package srp

import (
	"context"
	"time"

	"uuid"
)

// UserStore looks up verifiers. Implement it on top of your user table.
type UserStore interface {
	// LookupVerifier returns the verifier for username, encoded by
	// [Verifier.String]. It must return an error wrapping
	// [auth.ErrUserNotFound] if the user does not exist or has no verifier.
	// Any other error is treated as an internal failure and returned to the
	// caller.
	LookupVerifier(ctx context.Context, username string) (string, error)
}

// SessionStore keeps login state between [Server.BeginLogin] and
// [Server.Authenticate]. Implementations must be safe for concurrent use.
//
// The data is opaque to the store and under 2 KiB, but it is secret: it
// contains the server's private value for the login and the user's
// verifier. Anyone who reads it before the login finishes can impersonate
// the server to that client and attempt to guess the user's password
// offline, so protect it as you would the verifiers themselves.
type SessionStore interface {
	// SaveSession stores data under id until expiresAt.
	SaveSession(ctx context.Context, id uuid.UUID, data []byte, expiresAt time.Time) error
	// ConsumeSession atomically deletes and returns the data stored under
	// id, so that a session can be finished at most once even when two
	// requests race. It must return an error wrapping [ErrSessionNotFound]
	// if there is no such session or it expired before now. Expired
	// sessions may be deleted at any time.
	ConsumeSession(ctx context.Context, id uuid.UUID, now time.Time) ([]byte, error)
}

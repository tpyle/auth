package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserStore looks up password hashes. Implement it on top of your user table.
type UserStore interface {
	// LookupPasswordHash returns the PHC-encoded hash for username, as
	// produced by [HashPassword]. It must return an error wrapping
	// [ErrUserNotFound] if the user does not exist. Any other error is
	// treated as an internal failure and returned to the caller.
	LookupPasswordHash(ctx context.Context, username string) (string, error)
}

// PasswordHashUpdater is an optional extension of [UserStore]. If the store
// implements it, a successful login whose stored hash used outdated
// [Argon2Params] automatically writes a new hash.
type PasswordHashUpdater interface {
	// UpdatePasswordHash replaces the user's hash with newHash only if it is
	// still oldHash, atomically (compare-and-swap). If the hash has changed,
	// for example because the password was changed while the login that
	// triggered the upgrade was in progress, it must do nothing and return
	// nil; overwriting would restore the old password.
	UpdatePasswordHash(ctx context.Context, username, oldHash, newHash string) error
}

// VerificationKey is the public half of a signing key, as stored in a
// [KeyStore].
type VerificationKey struct {
	// ID is placed in the "kid" header of every token the key signs.
	ID uuid.UUID
	// PublicKey is a P-256 public key.
	PublicKey *ecdsa.PublicKey
	// CreatedAt is when the key was generated.
	CreatedAt time.Time
	// ExpiresAt is when no token signed by this key can still be valid, so the
	// key may be deleted. The zero value means the key never expires.
	ExpiresAt time.Time
}

// MarshalPublicKey encodes the public key as PKIX DER, suitable for storing
// in a binary column. Decode it with [ParsePublicKey].
func (k *VerificationKey) MarshalPublicKey() ([]byte, error) {
	if k.PublicKey == nil {
		return nil, fmt.Errorf("auth: verification key %s has no public key", k.ID)
	}
	der, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("auth: marshaling public key: %w", err)
	}
	return der, nil
}

// expired reports whether the key may be discarded at time now.
func (k *VerificationKey) expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt)
}

// ParsePublicKey decodes a PKIX DER public key produced by
// [VerificationKey.MarshalPublicKey]. Only P-256 ECDSA keys are accepted.
func ParsePublicKey(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("auth: parsing public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("auth: public key is not a P-256 ECDSA key")
	}
	return ec, nil
}

// KeyStore persists the public halves of signing keys so that every instance
// of a service can verify tokens signed by any other instance. Private keys
// are never passed to the store.
//
// Each [Authorizer] keeps an in-memory copy of the key set, reloaded with
// ListKeys every [Config.KeyCacheTTL] and, at most once per second, when a
// token names a key it does not know.
//
// Implementations must be safe for concurrent use.
type KeyStore interface {
	// StoreKey saves a new key.
	StoreKey(ctx context.Context, key *VerificationKey) error
	// ListKeys returns all stored keys, including expired ones.
	ListKeys(ctx context.Context) ([]*VerificationKey, error)
	// DeleteKeys removes the given keys. Missing IDs must be ignored.
	DeleteKeys(ctx context.Context, ids []uuid.UUID) error
}

// RefreshTokenRecord is the server-side state of one refresh token. Records
// contain no secrets: a refresh token is a signed JWT, and the record only
// tracks whether it is still usable.
type RefreshTokenRecord struct {
	// ID is the token's "jti" claim.
	ID uuid.UUID
	// ParentID is the token this one replaced, or [uuid.Nil] for the first
	// token of a login, which starts a new family.
	ParentID uuid.UUID
	// FamilyID groups every token descended from one login. Revoking a
	// family logs that session out.
	FamilyID uuid.UUID
	// Subject is the user the token was issued to.
	Subject string
	// IssuedAt is when the token was created.
	IssuedAt time.Time
	// ExpiresAt is when the token can no longer be accepted: its "exp"
	// claim plus [Config.Leeway]. Stores may delete records after this time.
	ExpiresAt time.Time
	// UsedAt is when the token was first exchanged for a new one. The zero
	// value means it has not been used.
	UsedAt time.Time
}

// Used reports whether the token has been exchanged for a new one.
func (r RefreshTokenRecord) Used() bool {
	return !r.UsedAt.IsZero()
}

// RefreshTokenStore tracks refresh tokens so they can be rotated, revoked and
// checked for reuse.
//
// Used records must be kept until they expire: reuse detection works by
// finding a record whose UsedAt is set. If a used record is deleted early, a
// replayed token is reported as [ErrTokenRevoked] and its family is not
// revoked. Expired records may be purged at any time.
//
// Revocation applies to the family, not just its current records: a refresh
// can be in flight (its old token consumed, its replacement not yet created)
// at the moment a family is revoked, and the replacement must not survive.
// Stores therefore remember revoked families, and creating a token in a
// revoked family fails. The check in CreateRefreshToken and the marking in
// the revoke methods must be atomic with respect to each other: a token
// created concurrently with a revocation is either rejected or deleted by
// it. A revoked family may be forgotten once all of its tokens have expired.
//
// Implementations must be safe for concurrent use.
type RefreshTokenStore interface {
	// CreateRefreshToken saves a new, unused record. A record with no
	// ParentID starts a new family. Any other record continues an existing
	// family, and must fail with an error wrapping [ErrTokenRevoked] if the
	// family has been revoked or no longer exists (a refresh delayed until
	// after its family was revoked and forgotten must not revive it).
	CreateRefreshToken(ctx context.Context, rec RefreshTokenRecord) error
	// ConsumeRefreshToken atomically sets UsedAt to now if it is not already
	// set, and returns the record as it was *before* the call, so that two
	// concurrent calls cannot both observe an unused token. An existing UsedAt
	// must not be overwritten. It returns an error wrapping
	// [ErrRefreshTokenNotFound] if no record exists.
	ConsumeRefreshToken(ctx context.Context, id uuid.UUID, now time.Time) (RefreshTokenRecord, error)
	// RevokeRefreshTokenFamily marks the family revoked and deletes its
	// records. Revoking an unknown family is not an error.
	RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error
	// RevokeRefreshTokensForSubject revokes, as RevokeRefreshTokenFamily
	// does, every family belonging to subject. It must also be atomic with
	// respect to CreateRefreshToken calls that start a new family for the
	// subject: such a token is either revoked or created after this call
	// completes. Revoking a subject with no families is not an error.
	RevokeRefreshTokensForSubject(ctx context.Context, subject string) error
}

// RefreshTokenPurger is an optional extension of [RefreshTokenStore]. If the
// store implements it, each [Authorizer] calls it every
// [Config.RefreshPurgeInterval], and [Authorizer.PurgeExpiredRefreshTokens]
// calls it on demand.
//
// The Authorizer passes a time a few minutes in the past, so records
// outlive their expiry briefly and a refresh accepted just before expiry
// can still complete. Several instances may purge the same store at the
// same time, so implementations must tolerate concurrent calls.
type RefreshTokenPurger interface {
	// PurgeExpiredRefreshTokens deletes every record whose ExpiresAt is
	// before now, and forgets every family (revoked or not) whose tokens
	// have all expired by then. It returns how many records and families
	// were removed; the count is used only for logging.
	PurgeExpiredRefreshTokens(ctx context.Context, now time.Time) (int64, error)
}

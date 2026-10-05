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
	UpdatePasswordHash(ctx context.Context, username, encodedHash string) error
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
// Implementations must be safe for concurrent use.
type KeyStore interface {
	// StoreKey saves a new key.
	StoreKey(ctx context.Context, key *VerificationKey) error
	// GetKey returns the key with the given ID, or an error wrapping
	// [ErrKeyNotFound].
	GetKey(ctx context.Context, id uuid.UUID) (*VerificationKey, error)
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
	// FamilyID groups every token descended from one login. Revoking a
	// family logs that session out.
	FamilyID uuid.UUID
	// Subject is the user the token was issued to.
	Subject string
	// IssuedAt is when the token was created.
	IssuedAt time.Time
	// ExpiresAt is when the token expires. Stores may delete records after
	// this time.
	ExpiresAt time.Time
	// Used is true once the token has been exchanged for a new one.
	Used bool
}

// RefreshTokenStore tracks refresh tokens so they can be rotated, revoked and
// checked for reuse.
//
// Used records must be kept until they expire: reuse detection works by
// finding a record with Used set. If a used record is deleted early, a
// replayed token is reported as [ErrTokenRevoked] and its family is not
// revoked. Expired records may be purged at any time.
//
// Implementations must be safe for concurrent use.
type RefreshTokenStore interface {
	// CreateRefreshToken saves a new, unused record.
	CreateRefreshToken(ctx context.Context, rec RefreshTokenRecord) error
	// ConsumeRefreshToken atomically marks the record used and returns it as
	// it was *before* the call, so that two concurrent calls cannot both
	// observe Used == false. It returns an error wrapping
	// [ErrRefreshTokenNotFound] if no record exists.
	ConsumeRefreshToken(ctx context.Context, id uuid.UUID) (RefreshTokenRecord, error)
	// RevokeRefreshTokenFamily deletes every record in the family. Revoking
	// an unknown family is not an error.
	RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error
}

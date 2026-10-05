package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	// keyRetentionMargin is added to a key's expiry to absorb small delays in
	// rotation, so tokens signed just before a late rotation stay verifiable.
	keyRetentionMargin = 5 * time.Minute
	// rotationRetryDelay is how soon a failed rotation is retried.
	rotationRetryDelay = time.Minute
)

// signingKey is the private key currently used to sign tokens.
type signingKey struct {
	id      uuid.UUID
	private *ecdsa.PrivateKey
}

type cachedKey struct {
	key       *VerificationKey
	fetchedAt time.Time
}

// keyManager owns the current signing key, rotates it, and resolves
// verification keys through the KeyStore with a small cache.
type keyManager struct {
	s       *settings
	current atomic.Pointer[signingKey]

	mu    sync.Mutex
	cache map[uuid.UUID]cachedKey
}

// newKeyManager creates the first signing key and stores its public half.
func newKeyManager(ctx context.Context, s *settings) (*keyManager, error) {
	km := &keyManager{s: s, cache: map[uuid.UUID]cachedKey{}}
	if err := km.rotate(ctx); err != nil {
		return nil, err
	}
	if err := km.cleanup(ctx); err != nil {
		s.logger.WarnContext(ctx, "auth: removing expired signing keys", "error", err)
	}
	return km, nil
}

// rotate generates a new signing key, persists its public half, and then
// starts signing with it. Storing first guarantees that no token is issued
// before other instances can look up its key.
func (km *keyManager) rotate(ctx context.Context) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("auth: generating signing key: %w", err)
	}
	now := km.s.now()
	vk := &VerificationKey{
		ID:        uuid.New(),
		PublicKey: &priv.PublicKey,
		CreatedAt: now,
	}
	if km.s.KeyRotationInterval > 0 {
		vk.ExpiresAt = now.Add(km.s.KeyRotationInterval + km.s.maxTokenTTL() + keyRetentionMargin)
	}
	if err := km.s.keyStore.StoreKey(ctx, vk); err != nil {
		return fmt.Errorf("auth: storing signing key: %w", err)
	}
	km.remember(vk, now)
	km.current.Store(&signingKey{id: vk.ID, private: priv})
	return nil
}

// cleanup deletes expired keys from the store and the cache. The current key
// is never deleted.
func (km *keyManager) cleanup(ctx context.Context) error {
	keys, err := km.s.keyStore.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("auth: listing signing keys: %w", err)
	}
	now := km.s.now()
	cur := km.current.Load().id
	var expired []uuid.UUID
	for _, k := range keys {
		if k.ID != cur && k.expired(now) {
			expired = append(expired, k.ID)
		}
	}

	km.mu.Lock()
	for id, c := range km.cache {
		if c.key.expired(now) {
			delete(km.cache, id)
		}
	}
	km.mu.Unlock()

	if len(expired) == 0 {
		return nil
	}
	if err := km.s.keyStore.DeleteKeys(ctx, expired); err != nil {
		return fmt.Errorf("auth: deleting expired signing keys: %w", err)
	}
	return nil
}

// run rotates keys every KeyRotationInterval until ctx is cancelled. Failed
// rotations are retried after rotationRetryDelay; until one succeeds, the old
// key keeps signing, so tokens issued in that window may become unverifiable
// slightly before they expire.
func (km *keyManager) run(ctx context.Context) {
	interval := km.s.KeyRotationInterval
	if interval <= 0 {
		return
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		next := interval
		if err := km.rotate(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			km.s.logger.ErrorContext(ctx, "auth: rotating signing key", "error", err)
			next = min(rotationRetryDelay, interval)
		} else if err := km.cleanup(ctx); err != nil {
			km.s.logger.WarnContext(ctx, "auth: removing expired signing keys", "error", err)
		}
		timer.Reset(next)
	}
}

func (km *keyManager) remember(vk *VerificationKey, now time.Time) {
	km.mu.Lock()
	defer km.mu.Unlock()
	for id, c := range km.cache {
		if now.Sub(c.fetchedAt) >= km.s.KeyCacheTTL {
			delete(km.cache, id)
		}
	}
	km.cache[vk.ID] = cachedKey{key: vk, fetchedAt: now}
}

// lookup returns the public key for id. Unknown and expired keys return an
// error wrapping ErrInvalidToken; store failures are returned unchanged.
func (km *keyManager) lookup(ctx context.Context, id uuid.UUID) (*ecdsa.PublicKey, error) {
	if cur := km.current.Load(); cur.id == id {
		return &cur.private.PublicKey, nil
	}
	now := km.s.now()

	km.mu.Lock()
	c, ok := km.cache[id]
	km.mu.Unlock()

	vk := c.key
	if !ok || now.Sub(c.fetchedAt) >= km.s.KeyCacheTTL {
		var err error
		vk, err = km.s.keyStore.GetKey(ctx, id)
		if errors.Is(err, ErrKeyNotFound) {
			return nil, fmt.Errorf("%w: unknown signing key %s", ErrInvalidToken, id)
		}
		if err != nil {
			return nil, fmt.Errorf("auth: fetching signing key: %w", err)
		}
		if vk == nil || vk.PublicKey == nil {
			return nil, fmt.Errorf("auth: key store returned no key for %s", id)
		}
		if km.s.KeyCacheTTL > 0 {
			km.remember(vk, now)
		}
	}
	if vk.expired(now) {
		return nil, fmt.Errorf("%w: signing key %s has expired", ErrInvalidToken, id)
	}
	return vk.PublicKey, nil
}

// JWK is a JSON Web Key (RFC 7517) describing one ES256 verification key.
type JWK struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
}

// JWKSet is a JSON Web Key Set, as served from /.well-known/jwks.json.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// newJWK converts a P-256 public key to its JWK form.
func newJWK(id uuid.UUID, pub *ecdsa.PublicKey) (JWK, error) {
	ecdhKey, err := pub.ECDH()
	if err != nil {
		return JWK{}, fmt.Errorf("auth: converting key %s: %w", id, err)
	}
	// Uncompressed point encoding: 0x04 || X (32 bytes) || Y (32 bytes).
	b := ecdhKey.Bytes()
	if len(b) != 65 {
		return JWK{}, fmt.Errorf("auth: key %s is not a P-256 key", id)
	}
	return JWK{
		KeyType:   "EC",
		Curve:     "P-256",
		X:         base64.RawURLEncoding.EncodeToString(b[1:33]),
		Y:         base64.RawURLEncoding.EncodeToString(b[33:]),
		KeyID:     id.String(),
		Use:       "sig",
		Algorithm: "ES256",
	}, nil
}

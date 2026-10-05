package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
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
	// rotationRetryDelay is how soon a failed rotation step is retried.
	rotationRetryDelay = time.Minute
	// keyRefreshMinInterval rate-limits reloads of the key set, so tokens
	// with random unknown key IDs cannot flood the KeyStore.
	keyRefreshMinInterval = time.Second
)

// signingKey is a private key this process signs with, now or later.
type signingKey struct {
	id      uuid.UUID
	private *ecdsa.PrivateKey
}

// keyManager owns this process's signing keys and rotates them, and resolves
// verification keys from an in-memory copy of the KeyStore's key set.
//
// With rotation enabled, the key that will sign next is generated and stored
// one rotation interval before it is used, so other instances and JWKS
// consumers learn about it well before any token carries its ID.
type keyManager struct {
	s       *settings
	current atomic.Pointer[signingKey]

	rotMu sync.Mutex
	next  *signingKey // guarded by rotMu; nil if not yet generated

	refreshMu   sync.Mutex // serializes reloads of known
	mu          sync.RWMutex
	known       map[uuid.UUID]*VerificationKey // guarded by mu
	fetchedAt   time.Time                      // guarded by mu; zero = never
	lastAttempt time.Time                      // guarded by mu
	lastErr     error                          // guarded by mu; result of lastAttempt
}

// newKeyManager creates and stores the first signing key and, if rotation is
// enabled, the next one.
func newKeyManager(ctx context.Context, s *settings) (*keyManager, error) {
	km := &keyManager{s: s, known: map[uuid.UUID]*VerificationKey{}}
	now := s.now()
	cur, err := km.generate(ctx, now)
	if err != nil {
		return nil, err
	}
	km.current.Store(cur)
	if s.KeyRotationInterval > 0 {
		if err := km.ensureNext(ctx, now.Add(s.KeyRotationInterval)); err != nil {
			return nil, err
		}
	}
	if err := km.cleanup(ctx); err != nil {
		s.logger.WarnContext(ctx, "auth: removing expired signing keys", "error", err)
	}
	return km, nil
}

// generate creates a key that will start signing at activatesAt and stores
// its public half.
func (km *keyManager) generate(ctx context.Context, activatesAt time.Time) (*signingKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("auth: generating signing key: %w", err)
	}
	vk := &VerificationKey{
		ID:        uuid.New(),
		PublicKey: &priv.PublicKey,
		CreatedAt: km.s.now(),
	}
	if km.s.KeyRotationInterval > 0 {
		vk.ExpiresAt = activatesAt.Add(km.s.KeyRotationInterval + km.s.maxTokenTTL() + keyRetentionMargin)
	}
	if err := km.s.keyStore.StoreKey(ctx, vk); err != nil {
		return nil, fmt.Errorf("auth: storing signing key: %w", err)
	}
	km.mu.Lock()
	km.known[vk.ID] = vk
	km.mu.Unlock()
	return &signingKey{id: vk.ID, private: priv}, nil
}

// ensureNext generates and stores the next key if there is none yet.
func (km *keyManager) ensureNext(ctx context.Context, activatesAt time.Time) error {
	km.rotMu.Lock()
	defer km.rotMu.Unlock()
	if km.next != nil {
		return nil
	}
	k, err := km.generate(ctx, activatesAt)
	if err != nil {
		return err
	}
	km.next = k
	return nil
}

// rotate starts signing with the next key. If none was pre-generated (because
// storing it failed), one is generated and stored first. Storing always
// happens before signing, so no token is issued before other instances can
// look up its key.
func (km *keyManager) rotate(ctx context.Context) error {
	km.rotMu.Lock()
	defer km.rotMu.Unlock()
	next := km.next
	if next == nil {
		var err error
		if next, err = km.generate(ctx, km.s.now()); err != nil {
			return err
		}
	}
	km.current.Store(next)
	km.next = nil
	return nil
}

// cleanup deletes expired keys from the store and the in-memory set. Keys
// this process signs with, now or next, are never deleted.
func (km *keyManager) cleanup(ctx context.Context) error {
	keys, err := km.s.keyStore.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("auth: listing signing keys: %w", err)
	}
	now := km.s.now()
	keep := map[uuid.UUID]bool{km.current.Load().id: true}
	km.rotMu.Lock()
	if km.next != nil {
		keep[km.next.id] = true
	}
	km.rotMu.Unlock()

	var expired []uuid.UUID
	for _, k := range keys {
		if !keep[k.ID] && k.expired(now) {
			expired = append(expired, k.ID)
		}
	}

	km.mu.Lock()
	for id, k := range km.known {
		if !keep[id] && k.expired(now) {
			delete(km.known, id)
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

// run rotates keys every KeyRotationInterval until ctx is cancelled, keeps
// the next key pre-generated, and removes expired keys. Failed steps are
// retried after rotationRetryDelay. If a rotation cannot happen at all, the
// old key keeps signing, so tokens issued in that window may become
// unverifiable slightly before they expire.
func (km *keyManager) run(ctx context.Context) {
	interval := km.s.KeyRotationInterval
	if interval <= 0 {
		return
	}
	due := km.s.now().Add(interval)
	retry := min(rotationRetryDelay, interval)
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		now := km.s.now()
		if !now.Before(due) {
			if err := km.rotate(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				km.s.logger.ErrorContext(ctx, "auth: rotating signing key", "error", err)
				timer.Reset(retry)
				continue
			}
			due = now.Add(interval)
		}
		wait := due.Sub(now)
		if err := km.ensureNext(ctx, due); err != nil {
			if ctx.Err() != nil {
				return
			}
			km.s.logger.ErrorContext(ctx, "auth: pre-generating next signing key", "error", err)
			wait = min(wait, retry)
		}
		if err := km.cleanup(ctx); err != nil {
			km.s.logger.WarnContext(ctx, "auth: removing expired signing keys", "error", err)
		}
		timer.Reset(wait)
	}
}

// refresh reloads the key set from the store unless another goroutine has
// done so since seen, or a reload was attempted within keyRefreshMinInterval
// (in which case that attempt's error is returned).
func (km *keyManager) refresh(ctx context.Context, seen time.Time) error {
	km.refreshMu.Lock()
	defer km.refreshMu.Unlock()

	now := km.s.now()
	km.mu.RLock()
	fetchedAt, lastAttempt, lastErr := km.fetchedAt, km.lastAttempt, km.lastErr
	km.mu.RUnlock()
	if fetchedAt.After(seen) {
		return nil
	}
	if !lastAttempt.IsZero() && now.Sub(lastAttempt) < keyRefreshMinInterval {
		return lastErr
	}

	keys, err := km.s.keyStore.ListKeys(ctx)
	km.mu.Lock()
	defer km.mu.Unlock()
	km.lastAttempt = now
	if err != nil {
		km.lastErr = fmt.Errorf("auth: listing signing keys: %w", err)
		return km.lastErr
	}
	km.lastErr = nil
	known := make(map[uuid.UUID]*VerificationKey, len(keys))
	for _, k := range keys {
		if k != nil && k.PublicKey != nil {
			known[k.ID] = k
		}
	}
	km.known = known
	km.fetchedAt = now
	return nil
}

// lookup returns the public key for id. Unknown and expired keys return an
// error wrapping ErrInvalidToken. If the store cannot be reached, a key that
// is already known is still used; otherwise the store error is returned.
func (km *keyManager) lookup(ctx context.Context, id uuid.UUID) (*ecdsa.PublicKey, error) {
	if cur := km.current.Load(); cur.id == id {
		return &cur.private.PublicKey, nil
	}
	now := km.s.now()

	km.mu.RLock()
	vk, ok := km.known[id]
	fetchedAt := km.fetchedAt
	km.mu.RUnlock()

	stale := fetchedAt.IsZero() || now.Sub(fetchedAt) >= km.s.KeyCacheTTL
	if stale || !ok {
		if err := km.refresh(ctx, fetchedAt); err != nil {
			if !ok {
				return nil, err
			}
			km.s.logger.WarnContext(ctx, "auth: using cached signing key", "error", err)
		} else {
			km.mu.RLock()
			vk, ok = km.known[id]
			km.mu.RUnlock()
		}
	}
	if !ok {
		return nil, fmt.Errorf("%w: unknown signing key %s", ErrInvalidToken, id)
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

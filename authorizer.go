package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Authorizer hashes and checks passwords, issues and verifies tokens, and
// rotates signing keys. It is safe for concurrent use. Create it with [New]
// and release it with [Authorizer.Close].
type Authorizer struct {
	s    *settings
	keys *keyManager

	parser        *jwt.Parser
	lenientParser *jwt.Parser

	hashSem chan struct{}

	dummyOnce sync.Once
	dummyHash string

	closed    atomic.Bool
	closeOnce sync.Once
	cancel    context.CancelFunc
	done      chan struct{}
}

// New validates the options, creates and stores the first signing key, and
// starts background key rotation. ctx bounds only this initialization; the
// background work runs until [Authorizer.Close] is called.
func New(ctx context.Context, opts ...Option) (*Authorizer, error) {
	s, err := buildSettings(opts)
	if err != nil {
		return nil, err
	}
	km, err := newKeyManager(ctx, s)
	if err != nil {
		return nil, err
	}

	common := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithTimeFunc(s.now),
	}
	if s.Issuer != "" {
		common = append(common, jwt.WithIssuer(s.Issuer))
	}
	if len(s.Audience) > 0 {
		common = append(common, jwt.WithAudience(s.Audience...))
	}
	strict := append(common[:len(common):len(common)],
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(s.Leeway))

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a := &Authorizer{
		s:             s,
		keys:          km,
		parser:        jwt.NewParser(strict...),
		lenientParser: jwt.NewParser(append(common, jwt.WithoutClaimsValidation())...),
		hashSem:       make(chan struct{}, s.MaxConcurrentHashes),
		cancel:        cancel,
		done:          make(chan struct{}),
	}
	go func() {
		defer close(a.done)
		km.run(runCtx)
	}()
	return a, nil
}

// Close stops key rotation and waits for it to finish. Afterwards, tokens can
// still be verified but no new tokens are issued. Close is idempotent.
func (a *Authorizer) Close() error {
	a.closeOnce.Do(func() {
		a.closed.Store(true)
		a.cancel()
		<-a.done
	})
	return nil
}

func (a *Authorizer) checkOpen() error {
	if a.closed.Load() {
		return ErrClosed
	}
	return nil
}

func (a *Authorizer) acquireHashSlot(ctx context.Context) error {
	select {
	case a.hashSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Authorizer) releaseHashSlot() { <-a.hashSem }

// HashPassword hashes password with the configured [Argon2Params]. It waits
// for a free slot if [Config.MaxConcurrentHashes] hashes are already running.
func (a *Authorizer) HashPassword(ctx context.Context, password []byte) (string, error) {
	if err := a.acquireHashSlot(ctx); err != nil {
		return "", err
	}
	defer a.releaseHashSlot()
	return HashPassword(password, a.s.Argon2)
}

func (a *Authorizer) verifyPassword(ctx context.Context, password []byte, encodedHash string) (bool, error) {
	if err := a.acquireHashSlot(ctx); err != nil {
		return false, err
	}
	defer a.releaseHashSlot()
	return VerifyPassword(password, encodedHash)
}

// dummy returns a hash to verify against when a user does not exist, so that
// unknown users take as long to reject as wrong passwords.
func (a *Authorizer) dummy() string {
	a.dummyOnce.Do(func() {
		h, err := HashPassword([]byte(rand.Text()), a.s.Argon2)
		if err != nil {
			// Params were validated in New, so this means the system RNG
			// failed; fall back to an unverifiable hash rather than skipping
			// the work entirely.
			a.s.logger.Error("auth: creating dummy hash", "error", err)
			return
		}
		a.dummyHash = h
	})
	return a.dummyHash
}

// Authenticate checks username and password against the [UserStore]. It
// returns nil on success and [ErrInvalidCredentials] if the user does not
// exist or the password is wrong; both cases take similar time.
//
// If the store implements [PasswordHashUpdater] and the stored hash used
// different [Argon2Params] than currently configured, the password is
// re-hashed and saved. Failures to save are logged, not returned.
func (a *Authorizer) Authenticate(ctx context.Context, username string, password []byte) error {
	if err := a.s.requireUserStore(); err != nil {
		return err
	}
	stored, err := a.s.userStore.LookupPasswordHash(ctx, username)
	if errors.Is(err, ErrUserNotFound) {
		if d := a.dummy(); d != "" {
			_, _ = a.verifyPassword(ctx, password, d)
		}
		return ErrInvalidCredentials
	}
	if err != nil {
		return fmt.Errorf("auth: looking up user: %w", err)
	}

	ok, err := a.verifyPassword(ctx, password, stored)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}

	if updater, isUpdater := a.s.userStore.(PasswordHashUpdater); isUpdater {
		if stale, _ := NeedsRehash(stored, a.s.Argon2); stale {
			a.rehash(ctx, updater, username, password)
		}
	}
	return nil
}

func (a *Authorizer) rehash(ctx context.Context, updater PasswordHashUpdater, username string, password []byte) {
	h, err := a.HashPassword(ctx, password)
	if err == nil {
		err = updater.UpdatePasswordHash(ctx, username, h)
	}
	if err != nil {
		a.s.logger.WarnContext(ctx, "auth: upgrading password hash", "error", err)
	}
}

func (a *Authorizer) extraClaims(ctx context.Context, subject string) (map[string]any, error) {
	if a.s.claimsProvider == nil {
		return nil, nil
	}
	extra, err := a.s.claimsProvider(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("auth: claims provider: %w", err)
	}
	return extra, nil
}

// Login authenticates the user and issues a new token pair, starting a new
// refresh-token family. Extra access-token claims come from the
// [ClaimsProvider], if configured.
func (a *Authorizer) Login(ctx context.Context, username string, password []byte) (*TokenPair, error) {
	if err := a.checkOpen(); err != nil {
		return nil, err
	}
	if err := a.Authenticate(ctx, username, password); err != nil {
		return nil, err
	}
	extra, err := a.extraClaims(ctx, username)
	if err != nil {
		return nil, err
	}
	return a.issuePair(ctx, username, extra, uuid.New())
}

// IssueAccessToken signs an access token for subject without checking any
// credentials. Use it when authentication happens elsewhere. extra must not
// contain reserved claim names (see [IsReservedClaim]).
func (a *Authorizer) IssueAccessToken(subject string, extra map[string]any) (string, error) {
	if err := a.checkOpen(); err != nil {
		return "", err
	}
	tok, _, err := a.issueAccess(subject, extra)
	return tok, err
}

// IssueTokenPair is like [Authorizer.IssueAccessToken] but also issues a
// refresh token, starting a new refresh-token family, when a
// [RefreshTokenStore] is configured.
func (a *Authorizer) IssueTokenPair(ctx context.Context, subject string, extra map[string]any) (*TokenPair, error) {
	return a.issuePair(ctx, subject, extra, uuid.New())
}

// VerifyAccessToken checks an access token's signature, expiry, issuer,
// audience and type, and returns its claims. Client-side problems return
// errors wrapping [ErrInvalidToken] or [ErrTokenExpired]; any other error is
// an internal failure such as an unreachable [KeyStore].
func (a *Authorizer) VerifyAccessToken(ctx context.Context, token string) (*Claims, error) {
	return a.parse(ctx, token, TokenTypeAccess, true)
}

// Refresh exchanges a refresh token for a new token pair. The presented
// refresh token is consumed and cannot be used again: presenting it a second
// time revokes its whole family and returns [ErrRefreshTokenReused]. Note that
// a client sending two refresh requests concurrently will trigger this.
//
// A revoked or logged-out token returns [ErrTokenRevoked].
func (a *Authorizer) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	if err := a.s.requireRefreshStore(); err != nil {
		return nil, err
	}
	if err := a.checkOpen(); err != nil {
		return nil, err
	}
	c, family, err := a.parseRefresh(ctx, refreshToken, true)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(c.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed jti claim", ErrInvalidToken)
	}
	// Fetch claims before consuming, so a provider failure leaves the
	// refresh token usable for a retry.
	extra, err := a.extraClaims(ctx, c.Subject)
	if err != nil {
		return nil, err
	}

	rec, err := a.s.refreshStore.ConsumeRefreshToken(ctx, id)
	if errors.Is(err, ErrRefreshTokenNotFound) {
		return nil, ErrTokenRevoked
	}
	if err != nil {
		return nil, fmt.Errorf("auth: consuming refresh token: %w", err)
	}
	if rec.Used {
		if err := a.s.refreshStore.RevokeRefreshTokenFamily(ctx, family); err != nil {
			return nil, errors.Join(ErrRefreshTokenReused, fmt.Errorf("auth: revoking token family: %w", err))
		}
		return nil, ErrRefreshTokenReused
	}
	if rec.Subject != c.Subject || rec.FamilyID != family {
		return nil, fmt.Errorf("%w: refresh token does not match its record", ErrInvalidToken)
	}
	return a.issuePair(ctx, c.Subject, extra, family)
}

// Logout revokes the session the refresh token belongs to, including any
// refresh tokens issued from it. Expired tokens are accepted (their signature
// is still checked), and logging out twice is not an error.
func (a *Authorizer) Logout(ctx context.Context, refreshToken string) error {
	if err := a.s.requireRefreshStore(); err != nil {
		return err
	}
	_, family, err := a.parseRefresh(ctx, refreshToken, false)
	if err != nil {
		return err
	}
	if err := a.s.refreshStore.RevokeRefreshTokenFamily(ctx, family); err != nil {
		return fmt.Errorf("auth: revoking token family: %w", err)
	}
	return nil
}

func (a *Authorizer) parseRefresh(ctx context.Context, token string, validateTimes bool) (*Claims, uuid.UUID, error) {
	c, err := a.parse(ctx, token, TokenTypeRefresh, validateTimes)
	if err != nil {
		return nil, uuid.Nil, err
	}
	family, err := uuid.Parse(c.familyID)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("%w: malformed fam claim", ErrInvalidToken)
	}
	return c, family, nil
}

// JWKS returns the unexpired public keys from the [KeyStore] as a JSON Web
// Key Set, newest first, so other services can verify tokens with any
// standard JWT library. Verifiers that cache the set should refetch it when
// they see an unknown "kid", since rotation introduces new keys.
func (a *Authorizer) JWKS(ctx context.Context) (*JWKSet, error) {
	keys, err := a.s.keyStore.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: listing signing keys: %w", err)
	}
	now := a.s.now()
	slices.SortFunc(keys, func(x, y *VerificationKey) int { return y.CreatedAt.Compare(x.CreatedAt) })
	set := &JWKSet{Keys: []JWK{}}
	for _, k := range keys {
		if k.expired(now) {
			continue
		}
		jwk, err := newJWK(k.ID, k.PublicKey)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"slices"
	"time"
)

// Config holds the plain-data settings of an [Authorizer]. Start from
// [DefaultConfig], override fields, and pass it to [New] with [WithConfig].
//
// The mapstructure tags let Config be filled by configuration libraries such
// as Viper without this package depending on them:
//
//	cfg := auth.DefaultConfig()
//	if err := v.UnmarshalKey("auth", &cfg); err != nil { ... }
//	a, err := auth.New(ctx, auth.WithConfig(cfg), ...)
type Config struct {
	// Argon2 sets the cost of newly created password hashes.
	Argon2 Argon2Params `mapstructure:"argon2"`
	// Argon2Limits caps the parameters accepted from stored hashes, so a
	// corrupt or tampered hash cannot exhaust memory or CPU. Hashes over the
	// limits fail with [ErrInvalidHash]. Argon2 must be within these limits.
	Argon2Limits Argon2Params `mapstructure:"argon2_limits"`
	// MaxConcurrentHashes caps how many Argon2 computations run at once.
	// Hashing a new password uses Argon2.MemoryKiB, but verifying a stored
	// hash uses that hash's own memory cost, up to Argon2Limits.MemoryKiB, so
	// peak memory is roughly MaxConcurrentHashes * the larger of the two
	// (Argon2Limits.MemoryKiB if older or heavier hashes may exist). The
	// default is GOMAXPROCS (which respects container CPU limits) divided by
	// the default parallelism (at
	// least 1), so concurrent hashes do not oversubscribe the CPU.
	// Callers beyond the cap wait (respecting context cancellation).
	MaxConcurrentHashes int `mapstructure:"max_concurrent_hashes"`

	// AccessTokenTTL is how long access tokens are valid. Must be at least 1s.
	AccessTokenTTL time.Duration `mapstructure:"access_token_ttl"`
	// RefreshTokenTTL is how long each refresh token is valid. Refreshing
	// issues a new refresh token, so a session stays alive as long as it is
	// refreshed at least this often. Must be at least 1s.
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`

	// RefreshReuseGrace is how long after a refresh token's first use it may
	// be presented again without being treated as stolen. A reuse inside the
	// window gets a new token pair in the same session, which tolerates
	// clients (such as several browser tabs) that refresh concurrently or
	// retry after a lost response. A reuse after the window revokes the
	// session. Zero disables the grace period.
	RefreshReuseGrace time.Duration `mapstructure:"refresh_reuse_grace"`
	// RefreshPurgeInterval is roughly how often expired refresh-token
	// records are deleted in the background, if the [RefreshTokenStore]
	// implements [RefreshTokenPurger]. Each wait is randomized by up to 25%
	// either way, so instances sharing a store do not purge in lockstep.
	// Zero disables background purging; call
	// [Authorizer.PurgeExpiredRefreshTokens] or purge the store yourself.
	RefreshPurgeInterval time.Duration `mapstructure:"refresh_purge_interval"`

	// KeyRotationInterval is how often this process switches to a new
	// signing key. Each key is stored one interval before it starts signing,
	// so verifiers and JWKS consumers see it well in advance. Zero disables
	// rotation: the process signs with one key for its lifetime and stored
	// keys never expire, so they accumulate across restarts.
	KeyRotationInterval time.Duration `mapstructure:"key_rotation_interval"`
	// KeyCacheTTL is how often the in-memory copy of the [KeyStore]'s key
	// set is reloaded. Deleting a key from the store takes up to this long to
	// take effect. Unknown key IDs also trigger a reload, at most once per
	// second.
	KeyCacheTTL time.Duration `mapstructure:"key_cache_ttl"`

	// Issuer, when set, is written to the "iss" claim and required on
	// verification.
	Issuer string `mapstructure:"issuer"`
	// Audience, when set, is written to the "aud" claim, and verification
	// requires the token's audience to include at least one of these values.
	Audience []string `mapstructure:"audience"`
	// Leeway is the clock skew tolerated when checking time-based claims.
	Leeway time.Duration `mapstructure:"leeway"`

	// AuthHeader is the request header carrying "Bearer <token>". Empty
	// disables header authentication.
	AuthHeader string `mapstructure:"auth_header"`
	// AuthCookie is the cookie carrying a raw access token. Empty disables
	// cookie authentication. If both are enabled, the header wins.
	AuthCookie string `mapstructure:"auth_cookie"`
}

// DefaultConfig returns the configuration used when no options are given.
func DefaultConfig() Config {
	argon := DefaultArgon2Params()
	return Config{
		Argon2:               argon,
		Argon2Limits:         DefaultArgon2Limits(),
		MaxConcurrentHashes:  max(1, runtime.GOMAXPROCS(0)/int(argon.Parallelism)),
		AccessTokenTTL:       15 * time.Minute,
		RefreshTokenTTL:      7 * 24 * time.Hour,
		RefreshReuseGrace:    30 * time.Second,
		RefreshPurgeInterval: time.Hour,
		KeyRotationInterval:  24 * time.Hour,
		KeyCacheTTL:          5 * time.Minute,
		AuthHeader:           "Authorization",
	}
}

// Validate reports whether c can be used.
func (c Config) Validate() error {
	var errs []error
	if err := c.Argon2.Validate(); err != nil {
		errs = append(errs, err)
	} else if err := c.Argon2.within(c.Argon2Limits); err != nil {
		errs = append(errs, fmt.Errorf("auth: Argon2 is outside Argon2Limits: %w", err))
	}
	if c.Argon2Limits.SaltLength > maxPHCFieldBytes || c.Argon2Limits.KeyLength > maxPHCFieldBytes {
		errs = append(errs, fmt.Errorf("auth: Argon2Limits salt and key lengths must not exceed %d bytes", maxPHCFieldBytes))
	}
	if c.MaxConcurrentHashes < 1 {
		errs = append(errs, errors.New("auth: MaxConcurrentHashes must be at least 1"))
	}
	// Token timestamps have one-second resolution, so shorter lifetimes
	// would produce tokens that are already expired.
	if c.AccessTokenTTL < time.Second {
		errs = append(errs, errors.New("auth: AccessTokenTTL must be at least 1s"))
	}
	if c.RefreshTokenTTL < time.Second {
		errs = append(errs, errors.New("auth: RefreshTokenTTL must be at least 1s"))
	}
	if c.RefreshReuseGrace < 0 {
		errs = append(errs, errors.New("auth: RefreshReuseGrace must not be negative"))
	}
	if c.RefreshPurgeInterval < 0 {
		errs = append(errs, errors.New("auth: RefreshPurgeInterval must not be negative"))
	}
	if c.KeyRotationInterval < 0 {
		errs = append(errs, errors.New("auth: KeyRotationInterval must not be negative"))
	}
	if c.KeyCacheTTL < 0 {
		errs = append(errs, errors.New("auth: KeyCacheTTL must not be negative"))
	}
	if c.Leeway < 0 {
		errs = append(errs, errors.New("auth: Leeway must not be negative"))
	}
	return errors.Join(errs...)
}

// ClaimsProvider returns extra claims (such as roles) to embed in access
// tokens for subject. It is called by [Authorizer.Login] and
// [Authorizer.Refresh], so claims are refreshed whenever a token is.
type ClaimsProvider func(ctx context.Context, subject string) (map[string]any, error)

// UnauthorizedHandler writes the response when [Authorizer.RequireAuthHandler]
// rejects a request. err wraps [ErrNoToken], [ErrInvalidToken] or
// [ErrTokenExpired] for client errors; any other error is an internal failure
// such as an unreachable [KeyStore].
type UnauthorizedHandler func(w http.ResponseWriter, r *http.Request, err error)

// settings is the full internal configuration assembled from options.
type settings struct {
	Config
	userStore      UserStore
	keyStore       KeyStore
	refreshStore   RefreshTokenStore
	claimsProvider ClaimsProvider
	unauthorized   UnauthorizedHandler
	logger         *slog.Logger
	now            func() time.Time
}

// Option configures an [Authorizer].
type Option func(*settings)

// WithConfig replaces all plain-data settings with cfg. Options applied after
// it override individual fields.
func WithConfig(cfg Config) Option {
	return func(s *settings) { s.Config = cfg }
}

// WithUserStore sets the store used by [Authorizer.Authenticate] and
// [Authorizer.Login].
func WithUserStore(store UserStore) Option {
	return func(s *settings) { s.userStore = store }
}

// WithKeyStore sets where public signing keys are persisted. Without it, a
// private in-memory store is used.
func WithKeyStore(store KeyStore) Option {
	return func(s *settings) { s.keyStore = store }
}

// WithRefreshTokenStore enables refresh tokens.
func WithRefreshTokenStore(store RefreshTokenStore) Option {
	return func(s *settings) { s.refreshStore = store }
}

// WithClaimsProvider sets the source of extra access-token claims for
// [Authorizer.Login] and [Authorizer.Refresh].
func WithClaimsProvider(p ClaimsProvider) Option {
	return func(s *settings) { s.claimsProvider = p }
}

// WithArgon2Params sets the cost of newly created password hashes.
func WithArgon2Params(p Argon2Params) Option {
	return func(s *settings) { s.Argon2 = p }
}

// WithArgon2Limits sets [Config.Argon2Limits].
func WithArgon2Limits(p Argon2Params) Option {
	return func(s *settings) { s.Argon2Limits = p }
}

// WithMaxConcurrentHashes sets [Config.MaxConcurrentHashes].
func WithMaxConcurrentHashes(n int) Option {
	return func(s *settings) { s.MaxConcurrentHashes = n }
}

// WithAccessTokenTTL sets [Config.AccessTokenTTL].
func WithAccessTokenTTL(d time.Duration) Option {
	return func(s *settings) { s.AccessTokenTTL = d }
}

// WithRefreshTokenTTL sets [Config.RefreshTokenTTL].
func WithRefreshTokenTTL(d time.Duration) Option {
	return func(s *settings) { s.RefreshTokenTTL = d }
}

// WithRefreshReuseGrace sets [Config.RefreshReuseGrace].
func WithRefreshReuseGrace(d time.Duration) Option {
	return func(s *settings) { s.RefreshReuseGrace = d }
}

// WithRefreshPurgeInterval sets [Config.RefreshPurgeInterval]. Pass 0 to
// disable background purging.
func WithRefreshPurgeInterval(d time.Duration) Option {
	return func(s *settings) { s.RefreshPurgeInterval = d }
}

// WithKeyRotationInterval sets [Config.KeyRotationInterval].
func WithKeyRotationInterval(d time.Duration) Option {
	return func(s *settings) { s.KeyRotationInterval = d }
}

// WithKeyCacheTTL sets [Config.KeyCacheTTL].
func WithKeyCacheTTL(d time.Duration) Option {
	return func(s *settings) { s.KeyCacheTTL = d }
}

// WithIssuer sets [Config.Issuer].
func WithIssuer(iss string) Option {
	return func(s *settings) { s.Issuer = iss }
}

// WithAudience sets [Config.Audience].
func WithAudience(aud ...string) Option {
	return func(s *settings) { s.Audience = aud }
}

// WithLeeway sets [Config.Leeway].
func WithLeeway(d time.Duration) Option {
	return func(s *settings) { s.Leeway = d }
}

// WithAuthHeader sets [Config.AuthHeader]. Pass "" to disable header auth.
func WithAuthHeader(name string) Option {
	return func(s *settings) { s.AuthHeader = name }
}

// WithAuthCookie sets [Config.AuthCookie]. Pass "" to disable cookie auth.
func WithAuthCookie(name string) Option {
	return func(s *settings) { s.AuthCookie = name }
}

// WithUnauthorizedHandler customizes the 401 response written by
// [Authorizer.RequireAuthHandler].
func WithUnauthorizedHandler(h UnauthorizedHandler) Option {
	return func(s *settings) { s.unauthorized = h }
}

// WithLogger sets the logger used for errors in background work such as key
// rotation and refresh-token purging. Defaults to [slog.Default].
func WithLogger(l *slog.Logger) Option {
	return func(s *settings) { s.logger = l }
}

// WithClock overrides the time source. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(s *settings) { s.now = now }
}

func buildSettings(opts []Option) (*settings, error) {
	s := &settings{Config: DefaultConfig()}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	// Copy so later changes to the caller's slice cannot affect issued
	// tokens or race with them.
	s.Audience = slices.Clone(s.Audience)
	if s.keyStore == nil {
		s.keyStore = NewMemoryKeyStore()
	}
	if s.unauthorized == nil {
		s.unauthorized = defaultUnauthorized
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	clock := s.now
	if clock == nil {
		clock = time.Now
	}
	// Strip monotonic clock readings so every comparison uses wall time.
	// Go compares times by their monotonic readings when both have one, and
	// on Linux that clock does not advance while the machine is suspended;
	// this instance would then disagree with others, which compare stored
	// wall-clock timestamps.
	s.now = func() time.Time { return clock().Round(0) }
	return s, nil
}

// maxTokenTTL is the longest lifetime of any token this Authorizer signs.
func (s *settings) maxTokenTTL() time.Duration {
	return max(s.AccessTokenTTL, s.RefreshTokenTTL)
}

func (s *settings) requireUserStore() error {
	if s.userStore == nil {
		return fmt.Errorf("%w: no UserStore", ErrNotConfigured)
	}
	return nil
}

func (s *settings) requireRefreshStore() error {
	if s.refreshStore == nil {
		return fmt.Errorf("%w: no RefreshTokenStore", ErrNotConfigured)
	}
	return nil
}

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
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
	// MaxConcurrentHashes caps how many Argon2 computations run at once, which
	// bounds memory use to roughly MaxConcurrentHashes * Argon2.MemoryKiB. The
	// default is the number of CPUs divided by the default parallelism (at
	// least 1), so concurrent hashes do not oversubscribe the CPU.
	// Callers beyond the cap wait (respecting context cancellation).
	MaxConcurrentHashes int `mapstructure:"max_concurrent_hashes"`

	// AccessTokenTTL is how long access tokens are valid.
	AccessTokenTTL time.Duration `mapstructure:"access_token_ttl"`
	// RefreshTokenTTL is how long each refresh token is valid. Refreshing
	// issues a new refresh token, so a session stays alive as long as it is
	// refreshed at least this often.
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`

	// KeyRotationInterval is how often a new signing key is generated. Zero
	// disables rotation: the process signs with one key for its lifetime and
	// stored keys never expire, so they accumulate across restarts.
	KeyRotationInterval time.Duration `mapstructure:"key_rotation_interval"`
	// KeyCacheTTL is how long a verification key fetched from the [KeyStore]
	// is cached in memory. Deleting a key from the store takes up to this long
	// to take effect.
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
		Argon2:              argon,
		MaxConcurrentHashes: max(1, runtime.NumCPU()/int(argon.Parallelism)),
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     7 * 24 * time.Hour,
		KeyRotationInterval: 24 * time.Hour,
		KeyCacheTTL:         5 * time.Minute,
		AuthHeader:          "Authorization",
	}
}

// Validate reports whether c can be used.
func (c Config) Validate() error {
	var errs []error
	if err := c.Argon2.Validate(); err != nil {
		errs = append(errs, err)
	}
	if c.MaxConcurrentHashes < 1 {
		errs = append(errs, errors.New("auth: MaxConcurrentHashes must be at least 1"))
	}
	if c.AccessTokenTTL <= 0 {
		errs = append(errs, errors.New("auth: AccessTokenTTL must be positive"))
	}
	if c.RefreshTokenTTL <= 0 {
		errs = append(errs, errors.New("auth: RefreshTokenTTL must be positive"))
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
// rotation. Defaults to [slog.Default].
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
	if s.keyStore == nil {
		s.keyStore = NewMemoryKeyStore()
	}
	if s.unauthorized == nil {
		s.unauthorized = defaultUnauthorized
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
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

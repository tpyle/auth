package srp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tpyle/auth/v2"
)

// Config holds the plain-data settings of a [Server]. Start from
// [DefaultConfig], override fields, and pass it to [New] with [WithConfig].
type Config struct {
	// Group is the group new verifiers are created in. Verifiers in other
	// supported groups keep working.
	Group Group `mapstructure:"group"`
	// KDF is the Argon2id cost of new verifiers. Clients pay this cost on
	// every login, so it must suit the slowest device users log in from.
	KDF KDFParams `mapstructure:"kdf"`
	// KDFLimits caps the cost accepted in stored verifiers. KDF must be
	// within it. Keep it no higher than the limits of your clients (Go
	// clients default to [DefaultKDFLimits]).
	KDFLimits KDFParams `mapstructure:"kdf_limits"`
	// SaltLength is the length of new salts, from 16 to 64 bytes.
	SaltLength int `mapstructure:"salt_length"`
	// SessionTTL is how long the client has to answer a challenge,
	// including the time to compute Argon2id. Must be between 10s and 10m.
	SessionTTL time.Duration `mapstructure:"session_ttl"`
}

// Limits on [Config.SessionTTL].
const (
	minSessionTTL = 10 * time.Second
	maxSessionTTL = 10 * time.Minute
)

// DefaultConfig returns the configuration used when no options are given.
func DefaultConfig() Config {
	return Config{
		Group:      Group3072,
		KDF:        DefaultKDFParams(),
		KDFLimits:  DefaultKDFLimits(),
		SaltLength: 16,
		SessionTTL: 2 * time.Minute,
	}
}

// Validate reports whether c can be used.
func (c Config) Validate() error {
	var errs []error
	if !c.Group.valid() {
		errs = append(errs, fmt.Errorf("srp: unsupported Group %d", int(c.Group)))
	}
	if err := c.KDF.Validate(); err != nil {
		errs = append(errs, err)
	} else if err := c.KDF.within(c.KDFLimits); err != nil {
		errs = append(errs, fmt.Errorf("srp: KDF is outside KDFLimits: %w", err))
	}
	if c.SaltLength < minSaltLength || c.SaltLength > maxSaltLength {
		errs = append(errs, fmt.Errorf("srp: SaltLength must be between %d and %d", minSaltLength, maxSaltLength))
	}
	if c.SessionTTL < minSessionTTL || c.SessionTTL > maxSessionTTL {
		errs = append(errs, fmt.Errorf("srp: SessionTTL must be between %v and %v", minSessionTTL, maxSessionTTL))
	}
	return errors.Join(errs...)
}

// TokenIssuer issues tokens after a successful login. [*auth.Authorizer]
// implements it.
type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, subject string, extra map[string]any) (*auth.TokenPair, error)
}

// minDecoyKeyLength is the shortest key accepted by [WithDecoyKey].
const minDecoyKeyLength = 32

// settings is the full internal configuration assembled from options.
type settings struct {
	Config
	users          UserStore
	sessions       SessionStore
	issuer         TokenIssuer
	claimsProvider auth.ClaimsProvider
	decoyKey       []byte
	logger         *slog.Logger
	now            func() time.Time
}

// Option configures a [Server].
type Option func(*settings)

// WithConfig replaces all plain-data settings with cfg. Options applied after
// it override individual fields.
func WithConfig(cfg Config) Option {
	return func(s *settings) { s.Config = cfg }
}

// WithGroup sets [Config.Group].
func WithGroup(g Group) Option {
	return func(s *settings) { s.Group = g }
}

// WithKDFParams sets [Config.KDF].
func WithKDFParams(p KDFParams) Option {
	return func(s *settings) { s.KDF = p }
}

// WithKDFLimits sets [Config.KDFLimits].
func WithKDFLimits(p KDFParams) Option {
	return func(s *settings) { s.KDFLimits = p }
}

// WithSaltLength sets [Config.SaltLength].
func WithSaltLength(n int) Option {
	return func(s *settings) { s.SaltLength = n }
}

// WithSessionTTL sets [Config.SessionTTL].
func WithSessionTTL(d time.Duration) Option {
	return func(s *settings) { s.SessionTTL = d }
}

// WithUserStore sets the store verifiers are looked up in. Required.
func WithUserStore(store UserStore) Option {
	return func(s *settings) { s.users = store }
}

// WithSessionStore sets where logins are kept between [Server.BeginLogin]
// and [Server.Authenticate]. Without it, a private, unbounded
// [MemorySessionStore] is used, so a login must finish on the instance that
// began it; use a shared store with expiry in production.
//
// Every BeginLogin call stores a session and needs no authentication, so
// rate-limit the login endpoints whichever store is used.
func WithSessionStore(store SessionStore) Option {
	return func(s *settings) { s.sessions = store }
}

// WithTokenIssuer sets what [Server.FinishLogin] issues tokens with,
// normally the application's [*auth.Authorizer]. Without it, FinishLogin
// returns [auth.ErrNotConfigured], but [Server.Authenticate] still works.
func WithTokenIssuer(issuer TokenIssuer) Option {
	return func(s *settings) { s.issuer = issuer }
}

// WithClaimsProvider sets the source of extra access-token claims for
// [Server.FinishLogin]. Pass the same provider given to the
// [auth.Authorizer], so SRP and password logins produce the same claims.
func WithClaimsProvider(p auth.ClaimsProvider) Option {
	return func(s *settings) { s.claimsProvider = p }
}

// WithDecoyKey sets the secret used to derive the salts of decoy challenges
// for unknown users, which must stay the same for a given username so that
// repeated attempts cannot tell real users from unknown ones. It must be at
// least 32 random bytes and shared by every instance of the service.
//
// Without it, a random key is generated at startup. Decoy salts then change
// when the process restarts and differ between instances, which reveals
// which usernames do not exist to anyone who asks twice across a restart
// or two instances.
func WithDecoyKey(key []byte) Option {
	return func(s *settings) { s.decoyKey = key }
}

// WithLogger sets the logger used for the reasons logins fail (at debug
// level). Defaults to [slog.Default].
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
	errs := []error{s.Validate()}
	if s.users == nil {
		errs = append(errs, fmt.Errorf("%w: no UserStore", auth.ErrNotConfigured))
	}
	if s.decoyKey != nil && len(s.decoyKey) < minDecoyKeyLength {
		errs = append(errs, fmt.Errorf("srp: decoy key must be at least %d bytes", minDecoyKeyLength))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if s.decoyKey == nil {
		s.decoyKey = make([]byte, minDecoyKeyLength)
		_, _ = rand.Read(s.decoyKey) // crypto/rand.Read never fails.
	} else {
		s.decoyKey = append([]byte(nil), s.decoyKey...)
	}
	if s.sessions == nil {
		s.sessions = NewMemorySessionStore()
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	clock := s.now
	if clock == nil {
		clock = time.Now
	}
	// Wall time only, as in the core package: stored timestamps are compared
	// across instances.
	s.now = func() time.Time { return clock().Round(0) }
	return s, nil
}

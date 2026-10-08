package passkey

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"github.com/tpyle/auth/v2"
)

// Requirement is a WebAuthn requirement level.
type Requirement string

// Requirement levels.
const (
	Required    Requirement = "required"
	Preferred   Requirement = "preferred"
	Discouraged Requirement = "discouraged"
)

func (r Requirement) valid() bool {
	return r == Required || r == Preferred || r == Discouraged
}

// Config holds the plain-data settings of a [Passkeys] service. Start from
// [DefaultConfig], fill in the relying party fields, and pass it to [New]
// with [WithConfig].
type Config struct {
	// RPID is the relying party ID: the domain credentials are scoped to,
	// without scheme or port, such as "example.com". Every origin in
	// RPOrigins must be this domain or a subdomain of it. Changing it
	// invalidates every registered credential. Required.
	RPID string `mapstructure:"rp_id"`
	// RPDisplayName is the service name authenticators may show, such as
	// "Example Corp". Required.
	RPDisplayName string `mapstructure:"rp_display_name"`
	// RPOrigins are the origins ceremonies may run on, such as
	// "https://example.com". At least one is required.
	RPOrigins []string `mapstructure:"rp_origins"`

	// CeremonyTTL is how long the user has to complete a ceremony after it
	// begins. It is also sent to the browser as the ceremony timeout. Must be
	// between 30s and 10m.
	CeremonyTTL time.Duration `mapstructure:"ceremony_ttl"`

	// UserVerification is whether the authenticator must verify the user
	// with a PIN or biometric. Required (the default) makes a passkey on its
	// own a two-factor login; with Preferred or Discouraged, possession of
	// the authenticator may be enough.
	UserVerification Requirement `mapstructure:"user_verification"`
	// ResidentKey is whether registered credentials must be discoverable
	// (stored on the authenticator together with the user handle).
	// Discoverable credentials are what let [Passkeys.BeginLogin] work without
	// a username. Required is the default; use Preferred to also accept
	// security keys that are out of discoverable-credential slots, which can
	// then only be used through [Passkeys.BeginLoginFor].
	ResidentKey Requirement `mapstructure:"resident_key"`

	// AllowCloneWarning lets a credential keep logging in after its
	// signature counter goes backwards (see [ErrPossibleClone]). The warning
	// is still recorded in the [CredentialStore]. Most synced passkeys always
	// report a counter of zero and never trigger it.
	AllowCloneWarning bool `mapstructure:"allow_clone_warning"`
}

// Limits on [Config.CeremonyTTL].
const (
	minCeremonyTTL = 30 * time.Second
	maxCeremonyTTL = 10 * time.Minute
)

// DefaultConfig returns the defaults. The relying party fields are empty and
// must be set.
func DefaultConfig() Config {
	return Config{
		CeremonyTTL:      5 * time.Minute,
		UserVerification: Required,
		ResidentKey:      Required,
	}
}

// Validate reports whether c can be used.
func (c Config) Validate() error {
	var errs []error
	if c.RPID == "" {
		errs = append(errs, errors.New("passkey: RPID is required"))
	}
	if c.RPDisplayName == "" {
		errs = append(errs, errors.New("passkey: RPDisplayName is required"))
	}
	if len(c.RPOrigins) == 0 {
		errs = append(errs, errors.New("passkey: at least one RPOrigin is required"))
	}
	for _, o := range c.RPOrigins {
		if err := checkOrigin(o, c.RPID); err != nil {
			errs = append(errs, err)
		}
	}
	if c.CeremonyTTL < minCeremonyTTL || c.CeremonyTTL > maxCeremonyTTL {
		errs = append(errs, fmt.Errorf("passkey: CeremonyTTL must be between %v and %v", minCeremonyTTL, maxCeremonyTTL))
	}
	if !c.UserVerification.valid() {
		errs = append(errs, fmt.Errorf("passkey: invalid UserVerification %q", c.UserVerification))
	}
	if !c.ResidentKey.valid() {
		errs = append(errs, fmt.Errorf("passkey: invalid ResidentKey %q", c.ResidentKey))
	}
	return errors.Join(errs...)
}

// checkOrigin rejects origins that could never match a browser ceremony for
// rpID, so a misconfiguration fails at startup instead of on every login.
func checkOrigin(origin, rpID string) error {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("passkey: RPOrigin %q must be a scheme and host, such as https://example.com", origin)
	}
	host := u.Hostname()
	if u.Scheme == "http" && host != "localhost" {
		return fmt.Errorf("passkey: RPOrigin %q must use https (browsers allow http only for localhost)", origin)
	}
	if rpID != "" && host != rpID && !hasDomainSuffix(host, rpID) {
		return fmt.Errorf("passkey: RPOrigin %q is not on RPID %q or a subdomain of it", origin, rpID)
	}
	return nil
}

func hasDomainSuffix(host, domain string) bool {
	return len(host) > len(domain) && host[len(host)-len(domain)-1] == '.' && host[len(host)-len(domain):] == domain
}

// TokenIssuer issues tokens after a successful passkey login.
// [*auth.Authorizer] implements it.
type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, subject string, extra map[string]any) (*auth.TokenPair, error)
}

// settings is the full internal configuration assembled from options.
type settings struct {
	Config
	users          UserStore
	credentials    CredentialStore
	ceremonies     CeremonyStore
	issuer         TokenIssuer
	claimsProvider auth.ClaimsProvider
	logger         *slog.Logger
	now            func() time.Time
}

// Option configures a [Passkeys] service.
type Option func(*settings)

// WithConfig replaces all plain-data settings with cfg. Options applied after
// it override individual fields.
func WithConfig(cfg Config) Option {
	return func(s *settings) { s.Config = cfg }
}

// WithRelyingParty sets [Config.RPID], [Config.RPDisplayName] and
// [Config.RPOrigins].
func WithRelyingParty(id, displayName string, origins ...string) Option {
	return func(s *settings) {
		s.RPID = id
		s.RPDisplayName = displayName
		s.RPOrigins = origins
	}
}

// WithCeremonyTTL sets [Config.CeremonyTTL].
func WithCeremonyTTL(d time.Duration) Option {
	return func(s *settings) { s.CeremonyTTL = d }
}

// WithUserVerification sets [Config.UserVerification].
func WithUserVerification(r Requirement) Option {
	return func(s *settings) { s.UserVerification = r }
}

// WithResidentKey sets [Config.ResidentKey].
func WithResidentKey(r Requirement) Option {
	return func(s *settings) { s.ResidentKey = r }
}

// WithAllowCloneWarning sets [Config.AllowCloneWarning].
func WithAllowCloneWarning(allow bool) Option {
	return func(s *settings) { s.AllowCloneWarning = allow }
}

// WithUserStore sets the store that maps users to WebAuthn user handles.
// Required.
func WithUserStore(store UserStore) Option {
	return func(s *settings) { s.users = store }
}

// WithCredentialStore sets where registered credentials are kept. Required.
func WithCredentialStore(store CredentialStore) Option {
	return func(s *settings) { s.credentials = store }
}

// WithCeremonyStore sets where ceremonies are kept between their Begin and
// Finish steps. Without it, a private in-memory store is used, so a ceremony
// must finish on the instance that began it; use a shared store when running
// several instances behind a load balancer.
func WithCeremonyStore(store CeremonyStore) Option {
	return func(s *settings) { s.ceremonies = store }
}

// WithTokenIssuer sets what [Passkeys.FinishLogin] issues tokens with,
// normally the application's [*auth.Authorizer]. Without it, FinishLogin
// returns [auth.ErrNotConfigured], but [Passkeys.Authenticate] still works.
func WithTokenIssuer(issuer TokenIssuer) Option {
	return func(s *settings) { s.issuer = issuer }
}

// WithClaimsProvider sets the source of extra access-token claims for
// [Passkeys.FinishLogin]. Pass the same provider given to the
// [auth.Authorizer], so passkey and password logins produce the same claims.
func WithClaimsProvider(p auth.ClaimsProvider) Option {
	return func(s *settings) { s.claimsProvider = p }
}

// WithLogger sets the logger used for the reasons logins fail (at debug
// level) and for store errors that are not returned. Defaults to
// [slog.Default].
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
	var errs []error
	if s.users == nil {
		errs = append(errs, fmt.Errorf("%w: no UserStore", auth.ErrNotConfigured))
	}
	if s.credentials == nil {
		errs = append(errs, fmt.Errorf("%w: no CredentialStore", auth.ErrNotConfigured))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	s.RPOrigins = slices.Clone(s.RPOrigins)
	if s.ceremonies == nil {
		s.ceremonies = NewMemoryCeremonyStore()
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

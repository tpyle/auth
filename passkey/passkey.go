package passkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

// Passkeys registers WebAuthn credentials and logs users in with them. It is
// safe for concurrent use. Create it with [New].
type Passkeys struct {
	s  *settings
	wa *webauthn.WebAuthn
}

// New validates the options and returns a [Passkeys] service.
// [WithRelyingParty] (or [WithConfig]), [WithUserStore] and
// [WithCredentialStore] are required.
func New(opts ...Option) (*Passkeys, error) {
	s, err := buildSettings(opts)
	if err != nil {
		return nil, err
	}
	requireRK := s.ResidentKey == Required
	timeouts := webauthn.TimeoutConfig{Timeout: s.CeremonyTTL, TimeoutUVD: s.CeremonyTTL}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  s.RPID,
		RPDisplayName:         s.RPDisplayName,
		RPOrigins:             s.RPOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirement(s.ResidentKey),
			RequireResidentKey: &requireRK,
			UserVerification:   protocol.UserVerificationRequirement(s.UserVerification),
		},
		// Expiry is enforced through the CeremonyStore with the configured
		// clock; these only set the timeout sent to the browser.
		Timeouts: webauthn.TimeoutsConfig{Login: timeouts, Registration: timeouts},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Passkeys{s: s, wa: wa}, nil
}

// BeginRegistration starts adding a credential for subject, who must already
// be authenticated (for example, by [auth.Authorizer.RequireAuthHandler]).
// Credentials the user already has are excluded, so the same authenticator
// cannot be registered twice.
//
// It returns an error wrapping [auth.ErrUserNotFound] if the [UserStore] does
// not know subject.
func (p *Passkeys) BeginRegistration(ctx context.Context, subject string) (*Challenge, error) {
	user, err := p.lookupUser(ctx, subject)
	if err != nil {
		return nil, err
	}
	creation, session, err := p.wa.BeginRegistration(user,
		webauthn.WithExclusions(webauthn.Credentials(user.creds).CredentialDescriptors()))
	if err != nil {
		return nil, fmt.Errorf("passkey: beginning registration: %w", err)
	}
	return p.newChallenge(ctx, kindRegistration, subject, session, creation)
}

// FinishRegistration verifies the browser's response to a registration
// begun for the same subject, and saves the new credential with the given
// label. response is the JSON-serialized PublicKeyCredential. The label is
// stored as given, so limit its length if it comes from the client.
//
// It returns [ErrInvalidCeremony] if the ceremony cannot be used,
// [ErrInvalidResponse] if the response fails verification, and an error
// wrapping [ErrCredentialExists] if the credential is already registered.
// Each ceremony can be finished once, successfully or not. A ceremony begun
// for another subject is not found, and stays usable by its own subject.
func (p *Passkeys) FinishRegistration(ctx context.Context, subject string, ceremonyID uuid.UUID, response []byte, label string) (*Credential, error) {
	rec, err := p.consumeCeremony(ctx, ceremonyID, kindRegistration, subject)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidResponse, describe(err))
	}
	user, err := p.lookupUser(ctx, subject)
	if err != nil {
		return nil, err
	}
	wc, err := p.wa.CreateCredential(user, rec.Session, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidResponse, describe(err))
	}
	cred := fromWebAuthn(wc, subject)
	cred.Label = label
	cred.CreatedAt = p.s.now()
	if err := p.s.credentials.CreateCredential(ctx, cred); err != nil {
		return nil, fmt.Errorf("passkey: saving credential: %w", err)
	}
	return &cred, nil
}

// BeginLogin starts a login in which the authenticator says who the user is,
// so no username is needed. The browser offers the user's discoverable
// credentials (passkeys) for this relying party. Finish it with
// [Passkeys.FinishLogin], [Passkeys.Authenticate] or [Passkeys.AuthenticateFor].
func (p *Passkeys) BeginLogin(ctx context.Context) (*Challenge, error) {
	assertion, session, err := p.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, fmt.Errorf("passkey: beginning login: %w", err)
	}
	return p.newChallenge(ctx, kindLogin, "", session, assertion)
}

// BeginLoginFor starts a login restricted to subject's credentials. Unlike
// [Passkeys.BeginLogin] this also works with security keys that registered a
// non-discoverable credential, and with [Passkeys.AuthenticateFor] it
// re-authenticates a signed-in user.
//
// The returned options list the user's credential IDs, and the error tells
// whether the user exists and has credentials ([auth.ErrUserNotFound],
// [ErrNoCredentials]). Do not expose it to unauthenticated clients where
// revealing that is a concern; prefer BeginLogin there.
func (p *Passkeys) BeginLoginFor(ctx context.Context, subject string) (*Challenge, error) {
	user, err := p.lookupUser(ctx, subject)
	if err != nil {
		return nil, err
	}
	if len(user.creds) == 0 {
		return nil, ErrNoCredentials
	}
	assertion, session, err := p.wa.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("passkey: beginning login: %w", err)
	}
	return p.newChallenge(ctx, kindLogin, subject, session, assertion)
}

// FinishLogin verifies a login response, as [Passkeys.Authenticate] does,
// and issues a new token pair (a new refresh-token family) for the
// credential's owner through the [TokenIssuer]. Extra claims come from the
// [auth.ClaimsProvider] set with [WithClaimsProvider].
func (p *Passkeys) FinishLogin(ctx context.Context, ceremonyID uuid.UUID, response []byte) (*auth.TokenPair, error) {
	if p.s.issuer == nil {
		return nil, fmt.Errorf("%w: no TokenIssuer", auth.ErrNotConfigured)
	}
	cred, err := p.Authenticate(ctx, ceremonyID, response)
	if err != nil {
		return nil, err
	}
	var extra map[string]any
	if p.s.claimsProvider != nil {
		if extra, err = p.s.claimsProvider(ctx, cred.Subject); err != nil {
			return nil, fmt.Errorf("passkey: claims provider: %w", err)
		}
	}
	pair, err := p.s.issuer.IssueTokenPair(ctx, cred.Subject, extra)
	if err != nil {
		return nil, fmt.Errorf("passkey: issuing tokens: %w", err)
	}
	return pair, nil
}

// Authenticate verifies the browser's response to a login ceremony, records
// the credential's use, and returns the updated credential; its Subject is
// the authenticated user. response is the JSON-serialized PublicKeyCredential.
//
// After a [Passkeys.BeginLogin] ceremony, any registered user's passkey is
// accepted. To confirm that a signed-in user is present, for example before
// a sensitive action, use [Passkeys.AuthenticateFor] instead.
//
// It returns [ErrInvalidCeremony] if the ceremony cannot be used and
// [auth.ErrInvalidCredentials] if the response is not a valid assertion from
// a registered credential of the expected user. The reason is logged at
// debug level. A credential that may have been cloned fails with an error
// wrapping both [auth.ErrInvalidCredentials] and [ErrPossibleClone] unless
// [Config.AllowCloneWarning] is set. Each ceremony can be finished once,
// successfully or not.
func (p *Passkeys) Authenticate(ctx context.Context, ceremonyID uuid.UUID, response []byte) (*Credential, error) {
	return p.authenticate(ctx, "", ceremonyID, response)
}

// AuthenticateFor is like [Passkeys.Authenticate] but only accepts a
// credential belonging to subject, so it can confirm that a signed-in user
// is present (re-authentication) without the session's user being swapped
// for whoever's passkey answered. The ceremony may come from
// [Passkeys.BeginLoginFor] for the same subject (recommended: the browser
// then offers only that user's credentials) or from [Passkeys.BeginLogin].
//
// A credential belonging to someone else fails with
// [auth.ErrInvalidCredentials] and its use is not recorded. A ceremony begun
// with BeginLoginFor for another subject fails with [ErrInvalidCeremony].
func (p *Passkeys) AuthenticateFor(ctx context.Context, subject string, ceremonyID uuid.UUID, response []byte) (*Credential, error) {
	if subject == "" {
		return nil, errors.New("passkey: subject must not be empty")
	}
	return p.authenticate(ctx, subject, ceremonyID, response)
}

// authenticate implements Authenticate and AuthenticateFor. An empty subject
// accepts any user.
func (p *Passkeys) authenticate(ctx context.Context, subject string, ceremonyID uuid.UUID, response []byte) (*Credential, error) {
	rec, err := p.consumeCeremony(ctx, ceremonyID, kindLogin, "")
	if err != nil {
		return nil, err
	}
	if subject != "" && rec.Subject != "" && rec.Subject != subject {
		return nil, ErrInvalidCeremony
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, p.loginFailed(ctx, err)
	}

	var (
		user *waUser
		wc   *webauthn.Credential
	)
	if rec.Subject != "" {
		user, err = p.lookupUser(ctx, rec.Subject)
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, p.loginFailed(ctx, err)
		}
		if err != nil {
			return nil, err
		}
		wc, err = p.wa.ValidateLogin(user, rec.Session, parsed)
	} else {
		// Store failures inside the handler would otherwise be reported as
		// a bad response, so they are kept aside.
		var lookupErr error
		handler := func(_, handle []byte) (webauthn.User, error) {
			user, lookupErr = p.lookupUserByHandle(ctx, handle)
			if lookupErr != nil {
				return nil, lookupErr
			}
			return user, nil
		}
		_, wc, err = p.wa.ValidatePasskeyLogin(handler, rec.Session, parsed)
		if lookupErr != nil && !errors.Is(lookupErr, auth.ErrUserNotFound) {
			return nil, lookupErr
		}
	}
	if err != nil {
		return nil, p.loginFailed(ctx, err)
	}
	if subject != "" && user.user.Subject != subject {
		return nil, p.loginFailed(ctx, fmt.Errorf("credential belongs to %q, not %q", user.user.Subject, subject))
	}
	return p.recordUse(ctx, user, wc)
}

// recordUse applies the clone policy to a verified assertion and saves the
// counter and flags, or only the clone warning if the login is refused.
func (p *Passkeys) recordUse(ctx context.Context, user *waUser, wc *webauthn.Credential) (*Credential, error) {
	i := slices.IndexFunc(user.stored, func(c Credential) bool { return bytes.Equal(c.ID, wc.ID) })
	if i < 0 {
		// The library only verifies against credentials it was given.
		return nil, errors.New("passkey: verified credential is not in the user's credential list")
	}
	cred := user.stored[i]
	clone := cred.CloneWarning || wc.Authenticator.CloneWarning
	if clone {
		p.s.logger.WarnContext(ctx, "passkey: signature counter regressed; credential may be cloned",
			"subject", cred.Subject, "refused", !p.s.AllowCloneWarning)
	}
	if clone && !p.s.AllowCloneWarning {
		// Refused: save only the warning, so the attempt does not look
		// like a use of the credential.
		if !cred.CloneWarning {
			use := CredentialUse{ID: cred.ID, SignCount: cred.SignCount, BackupState: cred.BackupState,
				UserVerified: cred.UserVerified, CloneWarning: true}
			if err := p.s.credentials.RecordCredentialUse(ctx, use); err != nil {
				return nil, fmt.Errorf("passkey: recording clone warning: %w", err)
			}
		}
		return nil, fmt.Errorf("%w: %w", auth.ErrInvalidCredentials, ErrPossibleClone)
	}
	use := CredentialUse{
		ID:           cred.ID,
		SignCount:    wc.Authenticator.SignCount,
		BackupState:  wc.Flags.BackupState,
		UserVerified: wc.Flags.UserVerified,
		CloneWarning: wc.Authenticator.CloneWarning,
		UsedAt:       p.s.now(),
	}
	if err := p.s.credentials.RecordCredentialUse(ctx, use); err != nil {
		return nil, fmt.Errorf("passkey: recording credential use: %w", err)
	}
	cred.SignCount = max(cred.SignCount, use.SignCount)
	cred.BackupState = use.BackupState
	cred.UserVerified = cred.UserVerified || use.UserVerified
	cred.CloneWarning = clone
	cred.LastUsedAt = use.UsedAt
	return &cred, nil
}

// loginFailed logs why a login was refused and returns the error callers see.
func (p *Passkeys) loginFailed(ctx context.Context, cause error) error {
	p.s.logger.DebugContext(ctx, "passkey: login refused", "reason", describe(cause))
	return auth.ErrInvalidCredentials
}

// ListCredentials returns subject's registered credentials, for example to
// let the user review and remove them.
func (p *Passkeys) ListCredentials(ctx context.Context, subject string) ([]Credential, error) {
	creds, err := p.s.credentials.ListCredentials(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("passkey: listing credentials: %w", err)
	}
	return creds, nil
}

// DeleteCredential removes one of subject's credentials. It returns an error
// wrapping [ErrCredentialNotFound] if subject has no credential with that ID.
// The authenticator keeps its copy, which can no longer log in.
func (p *Passkeys) DeleteCredential(ctx context.Context, subject string, id []byte) error {
	if err := p.s.credentials.DeleteCredential(ctx, subject, id); err != nil {
		return fmt.Errorf("passkey: deleting credential: %w", err)
	}
	return nil
}

func (p *Passkeys) lookupUser(ctx context.Context, subject string) (*waUser, error) {
	u, err := p.s.users.LookupUser(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("passkey: looking up user: %w", err)
	}
	return p.withCredentials(ctx, u)
}

func (p *Passkeys) lookupUserByHandle(ctx context.Context, handle []byte) (*waUser, error) {
	u, err := p.s.users.LookupUserByHandle(ctx, handle)
	if err != nil {
		return nil, fmt.Errorf("passkey: looking up user by handle: %w", err)
	}
	// The handle comes from the client; make sure the store matched it
	// exactly rather than, say, by a case-insensitive or prefix comparison.
	if !bytes.Equal(u.Handle, handle) {
		return nil, fmt.Errorf("passkey: UserStore returned a user with a different handle: %w", auth.ErrUserNotFound)
	}
	return p.withCredentials(ctx, u)
}

func (p *Passkeys) withCredentials(ctx context.Context, u User) (*waUser, error) {
	creds, err := p.s.credentials.ListCredentials(ctx, u.Subject)
	if err != nil {
		return nil, fmt.Errorf("passkey: listing credentials: %w", err)
	}
	// Defend against a store that returns other users' credentials.
	creds = slices.DeleteFunc(creds, func(c Credential) bool { return c.Subject != u.Subject })
	w := &waUser{user: u, stored: creds, creds: make([]webauthn.Credential, len(creds))}
	for i, c := range creds {
		w.creds[i] = toWebAuthn(c)
	}
	return w, nil
}

// describe returns the most useful text from a go-webauthn error.
func describe(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		if pe.DevInfo != "" {
			return pe.Details + ": " + pe.DevInfo
		}
		return pe.Details
	}
	return err.Error()
}

// waUser adapts a User and its credentials to go-webauthn.
type waUser struct {
	user   User
	stored []Credential
	creds  []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.user.Handle }
func (u *waUser) WebAuthnName() string                       { return u.user.Name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (u *waUser) WebAuthnDisplayName() string {
	if u.user.DisplayName == "" {
		return u.user.Name
	}
	return u.user.DisplayName
}

func toWebAuthn(c Credential) webauthn.Credential {
	flags := protocol.FlagUserPresent
	if c.UserVerified {
		flags |= protocol.FlagUserVerified
	}
	if c.BackupEligible {
		flags |= protocol.FlagBackupEligible
	}
	if c.BackupState {
		flags |= protocol.FlagBackupState
	}
	transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{
		ID:                c.ID,
		PublicKey:         c.PublicKey,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		Transport:         transports,
		Flags:             webauthn.NewCredentialFlags(flags),
		// CloneWarning starts false so a regression is detected per login;
		// the stored flag is combined with it in recordUse.
		Authenticator: webauthn.Authenticator{AAGUID: c.AAGUID, SignCount: c.SignCount},
	}
}

func fromWebAuthn(wc *webauthn.Credential, subject string) Credential {
	transports := make([]string, len(wc.Transport))
	for i, t := range wc.Transport {
		transports[i] = string(t)
	}
	return Credential{
		ID:                wc.ID,
		Subject:           subject,
		PublicKey:         wc.PublicKey,
		SignCount:         wc.Authenticator.SignCount,
		AAGUID:            wc.Authenticator.AAGUID,
		Transports:        transports,
		AttestationType:   wc.AttestationType,
		AttestationFormat: wc.AttestationFormat,
		UserVerified:      wc.Flags.UserVerified,
		BackupEligible:    wc.Flags.BackupEligible,
		BackupState:       wc.Flags.BackupState,
	}
}

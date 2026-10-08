package passkey

import "errors"

// Errors returned by the package. They may be wrapped, so compare them with
// [errors.Is]. Failed logins return [auth.ErrInvalidCredentials] from the core
// package, and unknown users [auth.ErrUserNotFound].
var (
	// ErrInvalidCeremony means the ceremony ID passed to a Finish method is
	// unknown, expired, already used, of the other kind (a registration
	// ceremony finished as a login or vice versa) or begun for another user.
	// The client should start over.
	ErrInvalidCeremony = errors.New("passkey: invalid or expired ceremony")

	// ErrInvalidResponse means a registration response was malformed or
	// failed verification (wrong challenge, origin or relying party ID, a bad
	// signature, or missing user verification).
	ErrInvalidResponse = errors.New("passkey: invalid authenticator response")

	// ErrPossibleClone means an authenticator's signature counter went
	// backwards, which suggests its private key has been copied. Login is
	// refused while [Config.AllowCloneWarning] is false. The error also wraps
	// [auth.ErrInvalidCredentials].
	ErrPossibleClone = errors.New("passkey: signature counter regressed; authenticator may be cloned")

	// ErrNoCredentials means the user has no registered credentials, so
	// [Passkeys.BeginLoginFor] cannot start a login.
	ErrNoCredentials = errors.New("passkey: user has no credentials")

	// ErrCredentialExists must be returned (optionally wrapped) by
	// [CredentialStore.CreateCredential] when a credential with the same ID
	// is already registered, to any user.
	ErrCredentialExists = errors.New("passkey: credential already registered")

	// ErrCredentialNotFound must be returned (optionally wrapped) by
	// [CredentialStore.DeleteCredential] when the user has no credential with
	// the given ID.
	ErrCredentialNotFound = errors.New("passkey: credential not found")

	// ErrCeremonyNotFound must be returned (optionally wrapped) by
	// [CeremonyStore.ConsumeCeremony] when no unexpired ceremony has the
	// given ID. Callers of this package see [ErrInvalidCeremony] instead.
	ErrCeremonyNotFound = errors.New("passkey: ceremony not found")
)

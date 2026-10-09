package passkey

import (
	"context"
	"crypto/rand"
	"time"

	"uuid"
)

// UserHandleLength is the length of handles made by [NewUserHandle].
const UserHandleLength = 32

// NewUserHandle returns a new random WebAuthn user handle. Store one per user
// when the user is created (or the first time they register a passkey) and
// never change it: authenticators keep at most one discoverable credential
// per relying party and handle, and return the handle on login.
func NewUserHandle() []byte {
	h := make([]byte, UserHandleLength)
	_, _ = rand.Read(h) // crypto/rand.Read never fails.
	return h
}

// User is the WebAuthn view of an account.
type User struct {
	// Subject identifies the user to the rest of the application. It becomes
	// the "sub" claim of tokens issued by [Passkeys.FinishLogin].
	Subject string
	// Handle is the WebAuthn user handle: 1 to 64 opaque bytes, unique per
	// user and stable for the user's lifetime. It is stored on authenticators
	// and returned on every login, so it must not contain personal data such
	// as an email address. Create it with [NewUserHandle].
	Handle []byte
	// Name is the account name authenticators show when the user picks a
	// passkey, such as a username or email address.
	Name string
	// DisplayName is a friendlier name, such as "Alex Müller". Defaults to
	// Name.
	DisplayName string
}

// UserStore maps users to their WebAuthn identity. Implement it on top of
// your user table, with an indexed column for the handle.
type UserStore interface {
	// LookupUser returns the user identified by subject. It must return an
	// error wrapping [auth.ErrUserNotFound] if there is no such user.
	LookupUser(ctx context.Context, subject string) (User, error)
	// LookupUserByHandle returns the user with the given handle, for logins
	// where the authenticator, not the user, said who is logging in. It must
	// return an error wrapping [auth.ErrUserNotFound] if no user has it.
	LookupUserByHandle(ctx context.Context, handle []byte) (User, error)
}

// Credential is a registered public key credential.
type Credential struct {
	// ID is the credential ID chosen by the authenticator, up to 1023 bytes.
	// It is unique across all users.
	ID []byte
	// Subject is the user the credential belongs to.
	Subject string
	// PublicKey is the credential public key in COSE_Key format.
	PublicKey []byte
	// SignCount is the last signature counter value seen. Many authenticators
	// always report 0.
	SignCount uint32
	// AAGUID identifies the authenticator model (16 bytes, often all zero).
	AAGUID []byte
	// Transports are the ways the browser can reach the authenticator, such
	// as "internal", "hybrid" or "usb". They are sent back to the browser as
	// hints by [Passkeys.BeginLoginFor].
	Transports []string
	// AttestationType and AttestationFormat are as reported at registration.
	AttestationType   string
	AttestationFormat string
	// UserVerified records that the user was verified (with a PIN or
	// biometric) when the credential was registered. Later logins do not
	// change it (WebAuthn's uvInitialized).
	UserVerified bool
	// BackupEligible means the credential can be synced to other devices,
	// as passkeys in a password manager or platform keychain are. It never
	// changes.
	BackupEligible bool
	// BackupState means the credential is currently backed up or synced.
	BackupState bool
	// CloneWarning is set once the signature counter has gone backwards. It
	// is never cleared; delete the credential if it is no longer trusted.
	CloneWarning bool
	// Label is a user-facing name, such as "Work laptop".
	Label string
	// CreatedAt is when the credential was registered.
	CreatedAt time.Time
	// LastUsedAt is when the credential last logged in. The zero value means
	// never.
	LastUsedAt time.Time
}

// CredentialUse is the change to a credential after a successful login.
type CredentialUse struct {
	// ID is the credential that was used.
	ID []byte
	// SignCount is the counter value reported by the authenticator.
	SignCount uint32
	// BackupState is the backup state reported by the authenticator.
	BackupState bool
	// UserVerified is the credential's UserVerified value after the login.
	UserVerified bool
	// CloneWarning is true if the counter went backwards on this login.
	CloneWarning bool
	// UsedAt is when the login happened. It is zero when a refused login
	// only records CloneWarning, and LastUsedAt must then be left unchanged.
	UsedAt time.Time
}

// CredentialStore persists registered credentials. Implementations must be
// safe for concurrent use.
type CredentialStore interface {
	// ListCredentials returns every credential belonging to subject, in any
	// order. A subject with none is not an error.
	ListCredentials(ctx context.Context, subject string) ([]Credential, error)
	// CreateCredential saves a newly registered credential. It must fail with
	// an error wrapping [ErrCredentialExists] if a credential with the same
	// ID exists, for any user (use a unique index on the ID).
	CreateCredential(ctx context.Context, c Credential) error
	// RecordCredentialUse applies u to the credential with ID u.ID. To stay
	// correct when two logins race, SignCount must only ever increase (store
	// the larger of the old and new values), and UserVerified and
	// CloneWarning, once true, must stay true. A missing credential (deleted
	// during the login) is not an error.
	RecordCredentialUse(ctx context.Context, u CredentialUse) error
	// DeleteCredential removes the credential with the given ID if it belongs
	// to subject. It must return an error wrapping [ErrCredentialNotFound]
	// otherwise, so one user cannot delete another's credential.
	DeleteCredential(ctx context.Context, subject string, id []byte) error
}

// CeremonyStore keeps ceremony state between the Begin and Finish steps.
// The data is opaque to the store, contains no secrets, and is a few hundred
// bytes. Implementations must be safe for concurrent use.
type CeremonyStore interface {
	// SaveCeremony stores data under id until expiresAt.
	SaveCeremony(ctx context.Context, id uuid.UUID, data []byte, expiresAt time.Time) error
	// ConsumeCeremony atomically deletes and returns the data stored under
	// id, so that a ceremony can be finished at most once even when two
	// requests race. It must return an error wrapping [ErrCeremonyNotFound]
	// if there is no such ceremony or it expired before now. Expired
	// ceremonies may be deleted at any time.
	ConsumeCeremony(ctx context.Context, id uuid.UUID, now time.Time) ([]byte, error)
}

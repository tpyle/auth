# Passkeys

`github.com/tpyle/auth/passkey` adds passwordless login with passkeys and FIDO2 security keys (W3C WebAuthn). A successful passkey login issues the same access and refresh tokens as a password login, through your existing `auth.Authorizer`.

```bash
go get github.com/tpyle/auth/passkey
```

It's a **separate Go module**, so services that don't use passkeys don't pick up its dependencies. It requires Go 1.27 or later and uses the standard library's `uuid.UUID` for ceremony IDs. The core module uses `github.com/google/uuid`, which has the same `[16]byte` layout, so you can convert between them with `uuid.UUID(id)`. Verification is done by [`go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn) (BSD-3-Clause).

> FIDO2 is made of two protocols. CTAP runs between the browser or OS and the authenticator (phone, laptop, USB key) and never reaches your server. WebAuthn runs between the page and your server, and that's what this package implements.

## Concepts

| Term | Meaning |
|---|---|
| **Ceremony** | A two-step exchange. *Begin* creates a random challenge, the browser has the authenticator sign it, and *Finish* verifies the result. Registration ceremonies add a credential. Login ceremonies use one. |
| **Credential** | A key pair created by the authenticator for your site. The server stores only the public key. |
| **Passkey** | A *discoverable* credential. The authenticator also stores the user's handle, so the user can log in without typing a username. Passkeys in platform keychains and password managers are usually *synced* across devices. |
| **RP ID** | The relying party ID: the domain credentials are scoped to, such as `example.com`. A credential works on that domain and its subdomains. **Changing it invalidates every credential.** |
| **Origin** | The exact scheme, host and port a page runs on, such as `https://login.example.com`. Every origin in `RPOrigins` must be on the RP ID. |
| **User handle** | An opaque, random ID per user (up to 64 bytes) that's stored on the authenticator. It must not contain personal data. Create it with `passkey.NewUserHandle()` and never change it. |

Browsers allow WebAuthn only in secure contexts: HTTPS, or `http://localhost` during development.

## Setup

```go
a, _ := auth.New(ctx, auth.WithUserStore(users), auth.WithRefreshTokenStore(refresh),
	auth.WithClaimsProvider(claims))

pk, err := passkey.New(
	passkey.WithRelyingParty("example.com", "Example Corp", "https://example.com"),
	passkey.WithUserStore(passkeyUsers),       // implements passkey.UserStore
	passkey.WithCredentialStore(credentials), // implements passkey.CredentialStore
	passkey.WithCeremonyStore(ceremonies),    // shared store for multi-instance deployments
	passkey.WithTokenIssuer(a),               // *auth.Authorizer
	passkey.WithClaimsProvider(claims),       // same provider, same claims as password logins
)
```

### Config

| Field | Default | Meaning |
|---|---|---|
| `RPID` | (required) | Relying party ID. |
| `RPDisplayName` | (required) | Name authenticators may show. |
| `RPOrigins` | (required) | Allowed origins. `https` only, except `http://localhost`. |
| `CeremonyTTL` | `5m` | Time allowed to finish a ceremony. It's also sent to the browser as the timeout. Must be between 30s and 10m. |
| `UserVerification` | `required` | Whether the authenticator must check a PIN or biometric. With `required`, a passkey alone is a two-factor login. With `preferred` or `discouraged`, holding the device can be enough. |
| `ResidentKey` | `required` | Whether new credentials must be discoverable. With `preferred`, security keys that have run out of slots can still register, but those keys can then only log in through `BeginLoginFor`. |
| `AllowCloneWarning` | `false` | Keep accepting a credential after its signature counter goes backwards (see [Security](#security)). |

`Config` has `mapstructure` tags (`rp_id`, `rp_origins`, `ceremony_ttl`, ...), so it can be loaded the same way as [the core config](Configuration.md#loading-configuration-with-viper).

## Flows

### Registration (user is signed in)

```go
// POST /passkey/register/begin, behind a.RequireAuthHandler
subject, _ := auth.SubjectFromContext(r.Context())
ch, err := pk.BeginRegistration(r.Context(), subject) // -> JSON to the browser

// POST /passkey/register/finish, behind a.RequireAuthHandler
cred, err := pk.FinishRegistration(r.Context(), subject, req.CeremonyID, req.Credential, req.Label)
```

Registration always adds a passkey to an account that already exists. To let someone **sign up with a passkey**, create the user (with a new handle), issue a session with `a.IssueTokenPair`, then run registration with that token.

### Login (no username)

```go
// POST /passkey/login/begin
ch, err := pk.BeginLogin(r.Context())

// POST /passkey/login/finish
pair, err := pk.FinishLogin(r.Context(), req.CeremonyID, req.Credential) // *auth.TokenPair
```

To verify a passkey without issuing tokens, use `pk.Authenticate`. It returns the verified `*Credential`, and `Credential.Subject` is the user. After `BeginLogin`, **any** registered user's passkey passes, so don't use `Authenticate` on its own to confirm that the signed-in user is present.

To **re-authenticate a signed-in user**, for example before a sensitive action, use `AuthenticateFor`. It only accepts that user's credentials:

```go
subject, _ := auth.SubjectFromContext(r.Context())
ch, err := pk.BeginLoginFor(r.Context(), subject)                           // the browser offers only this user's passkeys
cred, err := pk.AuthenticateFor(r.Context(), subject, req.CeremonyID, req.Credential) // someone else's passkey -> ErrInvalidCredentials
```

`BeginLoginFor(ctx, subject)` restricts a login to one user's credentials. Besides re-authentication, it works with non-discoverable security keys. It reveals whether that user has passkeys, though, so prefer `BeginLogin` on public endpoints.

### Browser side

`Challenge` serializes as `{"ceremonyId": "...", "options": {"publicKey": {...}}, "expiresAt": "..."}`.

```js
const ch = await (await fetch("/passkey/login/begin", { method: "POST" })).json();
const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(ch.options.publicKey);
const cred = await navigator.credentials.get({ publicKey });
await fetch("/passkey/login/finish", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ ceremonyId: ch.ceremonyId, credential: cred.toJSON() }),
});
```

Registration works the same way with `parseCreationOptionsFromJSON` and `navigator.credentials.create`. The browser JSON helpers need Chrome 129+, Safari 18+ or Firefox 119+. For older browsers, use a library such as `@simplewebauthn/browser`.

[`passkey/examples/server`](../passkey/examples/server) is a complete, runnable version: `cd passkey && go run ./examples/server`, then open http://localhost:8080.

## Storage

| Interface | Purpose | Option |
|---|---|---|
| `UserStore` | Look up a user's handle and names by subject, or a user by handle | `WithUserStore` (required) |
| `CredentialStore` | Registered public keys | `WithCredentialStore` (required) |
| `CeremonyStore` | Challenges between Begin and Finish | `WithCeremonyStore` (default: in-memory and unbounded, for development and single instances) |

All three are called concurrently and must be safe for concurrent use.

Every Begin call stores a ceremony until it expires, and `BeginLogin` needs no authentication. **Rate-limit the Begin endpoints** whichever `CeremonyStore` you use, so anonymous clients can't fill it.

### Contracts

- `UserStore.LookupUser` and `LookupUserByHandle` return an error wrapping `auth.ErrUserNotFound` for unknown users. Handles must be compared byte for byte.
- `CredentialStore.CreateCredential` fails with `ErrCredentialExists` if **any** user already has that credential ID. Use a unique index.
- `CredentialStore.RecordCredentialUse` must never lower `SignCount` (use `GREATEST`). `CloneWarning`, once true, must stay true. A zero `UsedAt` means a refused login is only recording a clone warning: leave `LastUsedAt` unchanged. A missing credential isn't an error.
- `CredentialStore.DeleteCredential` deletes only if the credential belongs to the given subject. Otherwise it returns `ErrCredentialNotFound`.
- `CeremonyStore.ConsumeCeremony` **atomically deletes and returns** the ceremony, so it can be finished only once. It returns `ErrCeremonyNotFound` if the ceremony is missing or expired.

### PostgreSQL schema

```sql
ALTER TABLE users ADD COLUMN webauthn_handle bytea UNIQUE; -- set to NewUserHandle() for each user

CREATE TABLE webauthn_credentials (
    id                 bytea PRIMARY KEY,
    subject            text NOT NULL,
    public_key         bytea NOT NULL,
    sign_count         bigint NOT NULL,
    aaguid             bytea,
    transports         text[] NOT NULL DEFAULT '{}',
    attestation_type   text NOT NULL DEFAULT '',
    attestation_format text NOT NULL DEFAULT '',
    user_verified      boolean NOT NULL,
    backup_eligible    boolean NOT NULL,
    backup_state       boolean NOT NULL,
    clone_warning      boolean NOT NULL DEFAULT false,
    label              text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL,
    last_used_at       timestamptz
);
CREATE INDEX ON webauthn_credentials (subject);

CREATE TABLE webauthn_ceremonies (
    id         uuid PRIMARY KEY,
    data       bytea NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX ON webauthn_ceremonies (expires_at);
```

The two statements that matter for correctness:

```sql
-- RecordCredentialUse
UPDATE webauthn_credentials
   SET sign_count    = GREATEST(sign_count, $2),
       backup_state  = $3,
       user_verified = user_verified OR $4,
       clone_warning = clone_warning OR $5,
       last_used_at  = COALESCE($6, last_used_at) -- pass NULL when UsedAt is zero
 WHERE id = $1;

-- ConsumeCeremony: atomic, single use
DELETE FROM webauthn_ceremonies WHERE id = $1 AND expires_at > $2 RETURNING data;
```

Delete expired ceremonies now and then (`DELETE FROM webauthn_ceremonies WHERE expires_at < now()`), or use a store with TTLs such as Redis (`SET ... PX`, then `GETDEL`).

## Errors

| Error | Returned by | Suggested HTTP status |
|---|---|---|
| `auth.ErrInvalidCredentials` | `FinishLogin`, `Authenticate`, `AuthenticateFor`: the assertion is invalid, or the credential is unknown or belongs to someone else | 401 |
| `passkey.ErrPossibleClone` (also wraps `ErrInvalidCredentials`) | Login with a credential whose counter went backwards | 401. Consider alerting the user. |
| `passkey.ErrInvalidCeremony` | Finish methods: the ceremony is unknown, expired, already used, the wrong kind, or belongs to another user | 400. Start over. |
| `passkey.ErrInvalidResponse` | `FinishRegistration`: the response is malformed or failed verification | 400 |
| `passkey.ErrCredentialExists` | `FinishRegistration`: the credential is already registered | 409 |
| `passkey.ErrNoCredentials` | `BeginLoginFor`: the user has no credentials | 404 or 400 |
| `auth.ErrUserNotFound` | `BeginRegistration`, `BeginLoginFor` | 404, or 401 to hide it |
| `passkey.ErrCredentialNotFound` | `DeleteCredential` | 404 |
| `auth.ErrNotConfigured` | `FinishLogin` without `WithTokenIssuer` | 500 |

To keep login failures from revealing anything, they all collapse to `ErrInvalidCredentials`. The specific reason (wrong origin, bad signature, and so on) is logged at debug level through `WithLogger`. Store failures are returned as internal errors, not as `ErrInvalidCredentials`.

## Security

- **Challenges are stored server-side and single-use.** Each Finish call consumes its ceremony, even if it fails, so a captured response can't be replayed. Ceremonies are bound to their kind (registration or login). Registration ceremonies are also stored under a key derived from the user who began them, so another user's Finish can't find them, and so can't cancel them.
- **Origin and RP ID** are checked on every response, so a phishing site on another domain can't use your users' passkeys.
- **Attestation isn't requested** (`attestation: "none"`). The server trusts the public key it was given at registration, not a particular authenticator make. Registration is only allowed for signed-in users.
- **Signature counters:** when an authenticator reports a counter that isn't higher than the stored one (and isn't 0), the credential gets a permanent `CloneWarning` and is refused unless `AllowCloneWarning` is set. A refused attempt records only the warning; it doesn't update `LastUsedAt` or the counter. Synced passkeys always report 0 and never trigger this.
- **User verification** defaults to `required`, so a stolen, locked device isn't enough to log in.
- Deleting a credential stops it from logging in, but the copy on the authenticator stays until the user removes it.

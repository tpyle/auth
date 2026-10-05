# Storage

The library has no database code of its own. You supply persistence through these interfaces:

| Interface | Needed for | Option |
|---|---|---|
| `UserStore` | `Authenticate`, `Login` | `WithUserStore` |
| `PasswordHashUpdater` (optional, on the same value as `UserStore`) | Upgrading outdated hashes automatically | (detected on the `UserStore`) |
| `KeyStore` | Verifying tokens across instances and restarts | `WithKeyStore` (default: in-memory) |
| `RefreshTokenStore` | Refresh tokens, `Refresh`, `Logout`, `RevokeAllSessions` | `WithRefreshTokenStore` |

`KeyStore` and `RefreshTokenStore` implementations **must be safe for concurrent use**. An `Authorizer` calls them from many request goroutines and from its background rotation goroutine. A `UserStore` is called concurrently too, so make it safe for concurrent use as well. Any `database/sql`-based implementation already is.

Every method receives the request's `ctx`. Pass it on to your database calls.

## UserStore

```go
type UserStore interface {
	LookupPasswordHash(ctx context.Context, username string) (string, error)
}
```

- Return the PHC string produced by `HashPassword` / `Authorizer.HashPassword`.
- If the user does not exist, return an error that **wraps `auth.ErrUserNotFound`**, e.g. `fmt.Errorf("%w: %s", auth.ErrUserNotFound, username)`. The `Authorizer` then checks a dummy hash, so the response takes as long as a wrong password, and returns `ErrInvalidCredentials`.
- Any other error counts as an internal failure and is returned to the caller wrapped as `auth: looking up user: ...`. **Do not** return a generic "not found" error. It would become a 500 instead of a 401, and the fast response would reveal which usernames exist.
- If a stored hash cannot be parsed, `Authenticate` returns an error wrapping `ErrInvalidHash`.

### PasswordHashUpdater

```go
type PasswordHashUpdater interface {
	UpdatePasswordHash(ctx context.Context, username, encodedHash string) error
}
```

If your `UserStore` also implements this interface, then after a **successful** login whose stored hash used different Argon2 parameters (including salt or key length) than the current config, the password is hashed again with the current parameters and saved. This happens synchronously, before `Authenticate`/`Login` returns. If the update fails, the error is logged at warn level and the login still succeeds.

## KeyStore

```go
type KeyStore interface {
	StoreKey(ctx context.Context, key *VerificationKey) error
	ListKeys(ctx context.Context) ([]*VerificationKey, error)
	DeleteKeys(ctx context.Context, ids []uuid.UUID) error
}

type VerificationKey struct {
	ID        uuid.UUID        // the token's "kid" header
	PublicKey *ecdsa.PublicKey // P-256
	CreatedAt time.Time
	ExpiresAt time.Time        // zero = never expires
}
```

Contract:

- `StoreKey` saves a new key. `New` calls it once, or twice with rotation on (the current key and the [next key](Tokens-and-Keys.md#lifecycle)). Each rotation cycle calls it once more, to store the following next key. If it fails during `New`, `New` fails. If it fails in the background, the error is logged and the call is retried a minute later.
- `ListKeys` returns **all** keys, including expired ones. Each `Authorizer` uses it to load its in-memory copy of the key set: every `KeyCacheTTL`, and at most once per second when a token names an unknown `kid`. Cleanup and `JWKS` use it too. Its cost therefore does not depend on how many tokens you verify. If it fails, keys the instance already knows keep verifying, and tokens with unknown `kid`s get an internal error. Entries with a nil `PublicKey` are ignored.
- `DeleteKeys` removes the given IDs. It **must ignore IDs that do not exist**, because several instances may clean up the same keys at the same time.
- Only public keys are passed to the store. Private keys never leave the process.

Every instance shares the key table. Each instance stores its own keys and deletes expired keys from any instance. See [Tokens and Keys](Tokens-and-Keys.md#signing-key-rotation).

### Storing keys

To save the public key in a binary column, encode it with `MarshalPublicKey` (PKIX DER). To read it back, decode with `ParsePublicKey`, which accepts only P-256 ECDSA keys:

```go
der, err := key.MarshalPublicKey()  // []byte, store as BYTEA
pub, err := auth.ParsePublicKey(der) // *ecdsa.PublicKey
```

Store `ExpiresAt` as `NULL` when it is the zero value (this happens when `KeyRotationInterval` is 0), and turn `NULL` back into `time.Time{}` when you read it.

## RefreshTokenStore

```go
type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, rec RefreshTokenRecord) error
	ConsumeRefreshToken(ctx context.Context, id uuid.UUID, now time.Time) (RefreshTokenRecord, error)
	RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error
	RevokeRefreshTokensForSubject(ctx context.Context, subject string) error
}

type RefreshTokenRecord struct {
	ID        uuid.UUID // the token's "jti"
	FamilyID  uuid.UUID // one per login session
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	UsedAt    time.Time // first use; zero = unused
}

func (r RefreshTokenRecord) Used() bool // !r.UsedAt.IsZero()
```

A refresh token is a signed JWT. The record holds no secrets. It only tracks whether the token can still be used, and when it was first used.

Contract:

- `CreateRefreshToken` saves a new record with a zero `UsedAt`.
- `ConsumeRefreshToken(ctx, id, now)` must **atomically** set `UsedAt = now` **only if it is unset**, and return the record **as it was before the call**:
  - If the token was unused, the returned record has a zero `UsedAt`. Exactly one of any number of concurrent callers may get this result. If two callers both see an unused token, one stolen token can be refreshed twice and reuse detection is bypassed. Use a conditional `UPDATE` or a row lock, never a separate read and then write.
  - If the token was already used, return the record with its existing `UsedAt`, and **never overwrite it**. The [reuse grace window](Tokens-and-Keys.md#grace-period) is measured from the first use, so overwriting it would let the window slide forward.
  - If the record does not exist, return an error **wrapping `auth.ErrRefreshTokenNotFound`**. `Refresh` turns that into `ErrTokenRevoked`.
- `RevokeRefreshTokenFamily` deletes every record with that `FamilyID`. An unknown family is not an error. `Logout` and reuse detection both call it.
- `RevokeRefreshTokensForSubject` deletes every record for that subject, across all families. A subject with no records is not an error. `RevokeAllSessions` calls it.
- Keep used records until they expire. Reuse detection works only while the spent record exists. If used records are deleted early, a replayed token gets `ErrTokenRevoked` and its family is **not** revoked.

### Purging expired records

The library never deletes a record just because it expired. Logout and reuse detection delete whole families, but a session that is simply abandoned leaves its last record (and any used ones) in the table for good. Delete records whose `expires_at` has passed on a schedule, for example hourly:

```sql
DELETE FROM refresh_tokens WHERE expires_at < now();
```

This is safe. An expired refresh token is rejected by its `exp` claim before the store is consulted, so its record is no longer needed. `MemoryRefreshTokenStore` purges on every `CreateRefreshToken`.

## PostgreSQL

### Schema

```sql
CREATE TABLE users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
    -- ... your other columns
);

CREATE TABLE signing_keys (
    id         UUID PRIMARY KEY,
    public_key BYTEA       NOT NULL,  -- PKIX DER from MarshalPublicKey
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ            -- NULL = never expires
);

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY,
    family_id  UUID        NOT NULL,
    subject    TEXT        NOT NULL,
    issued_at  TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ            -- NULL = unused
);
CREATE INDEX ON refresh_tokens (family_id);   -- RevokeRefreshTokenFamily
CREATE INDEX ON refresh_tokens (subject);     -- RevokeRefreshTokensForSubject
CREATE INDEX ON refresh_tokens (expires_at);  -- purging
```

### Implementation

A complete implementation of all four interfaces lives in [`examples/sqlstore/sqlstore.go`](../examples/sqlstore/sqlstore.go) (package `github.com/tpyle/auth/v2/examples/sqlstore`). One `sqlstore.Store` value implements `UserStore`, `PasswordHashUpdater`, `KeyStore` and `RefreshTokenStore` using only `database/sql`. Bring your own PostgreSQL driver, for example `github.com/jackc/pgx/v5/stdlib`. Copy it into your project and adapt it. `uuid.UUID` implements `sql.Scanner` and `driver.Valuer`, so it maps straight onto `UUID` columns.

The part that matters most is the atomic consume. A conditional `UPDATE` claims the token only if `used_at IS NULL`. A concurrent caller blocks on the row lock, and PostgreSQL then re-checks the `WHERE` clause against the committed row, so exactly one caller wins. Everyone else falls back to a plain `SELECT`, which returns the already-used record (with its original `used_at`) or reports that it is missing:

```go
func (s *Store) ConsumeRefreshToken(ctx context.Context, id uuid.UUID, now time.Time) (auth.RefreshTokenRecord, error) {
	var r auth.RefreshTokenRecord
	err := s.DB.QueryRowContext(ctx, `
		UPDATE refresh_tokens SET used_at = $2
		WHERE id = $1 AND used_at IS NULL
		RETURNING id, family_id, subject, issued_at, expires_at`, id, now,
	).Scan(&r.ID, &r.FamilyID, &r.Subject, &r.IssuedAt, &r.ExpiresAt)
	if err == nil {
		return r, nil // was unused; UsedAt stays zero in the returned record
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}

	var usedAt sql.NullTime
	err = s.DB.QueryRowContext(ctx, `
		SELECT id, family_id, subject, issued_at, expires_at, used_at
		FROM refresh_tokens WHERE id = $1`, id,
	).Scan(&r.ID, &r.FamilyID, &r.Subject, &r.IssuedAt, &r.ExpiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return r, auth.ErrRefreshTokenNotFound
	}
	r.UsedAt = usedAt.Time
	return r, err
}
```

This relies on PostgreSQL's default `READ COMMITTED` isolation. Under `REPEATABLE READ` or `SERIALIZABLE`, the losing caller gets a serialization error instead, which `Refresh` reports as an internal error.

Wiring:

```go
store := &sqlstore.Store{DB: db}
a, err := auth.New(ctx,
	auth.WithUserStore(store),
	auth.WithKeyStore(store),
	auth.WithRefreshTokenStore(store),
)
```

The example also has `PurgeExpiredRefreshTokens(ctx, now)` for the periodic purge.


## In-memory implementations

| Type | Implements | Notes |
|---|---|---|
| `MemoryUserStore` (`NewMemoryUserStore()`) | `UserStore`, `PasswordHashUpdater` | `SetPasswordHash(username, hash)` adds a user or replaces one. |
| `MemoryKeyStore` (`NewMemoryKeyStore()`) | `KeyStore` | Used automatically when no `KeyStore` is given. |
| `MemoryRefreshTokenStore` (`NewMemoryRefreshTokenStore()`) | `RefreshTokenStore` | Purges expired records on every `CreateRefreshToken`. `Len()` reports how many records it holds, including used ones. |

All of them are safe for concurrent use. They store copies, not caller-owned pointers.

Limits:

- **Nothing survives a restart.** With the default `MemoryKeyStore`, every token issued before a restart fails verification after it, because the new process cannot find the old keys. Every user has to log in again.
- **The default `MemoryKeyStore` works for one instance only.** Each process gets its own private store, so a token issued by instance A fails with `ErrInvalidToken` on instance B. Behind a load balancer, use a shared `KeyStore` (and a shared `RefreshTokenStore`).
- `MemoryRefreshTokenStore` uses the real wall clock to purge records. It ignores `WithClock`.
- They are meant for tests, examples, prototypes and single-instance services that can accept losing every session on restart.

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
- If a stored hash cannot be parsed, or its parameters exceed `Config.Argon2Limits`, `Authenticate` returns an error wrapping `ErrInvalidHash`.

### PasswordHashUpdater

```go
type PasswordHashUpdater interface {
	UpdatePasswordHash(ctx context.Context, username, oldHash, newHash string) error
}
```

If your `UserStore` also implements this interface, then after a **successful** login whose stored hash used different Argon2 parameters (including salt or key length) than the current config, the password is hashed again with the current parameters and saved. This happens synchronously, before `Authenticate`/`Login` returns. If the update fails, the error is logged at warn level and the login still succeeds.

`UpdatePasswordHash` must be a **compare-and-swap**. Replace the hash with `newHash` only if it is still `oldHash` (the hash the login just verified), and do it atomically. If the hash has changed in the meantime, do nothing and return nil. That happens, for example, when a password change lands while the login that triggered the upgrade is still running. Without the check, the upgrade would write a hash of the **old** password and silently undo the change. In SQL, put the old hash in the `WHERE` clause (from [`examples/sqlstore/sqlstore.go`](../examples/sqlstore/sqlstore.go)):

```go
// UpdatePasswordHash implements auth.PasswordHashUpdater. The WHERE clause
// makes it a compare-and-swap: if the password was changed since oldHash was
// read, nothing is updated.
func (s *Store) UpdatePasswordHash(ctx context.Context, username, oldHash, newHash string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET password_hash = $3 WHERE username = $1 AND password_hash = $2`,
		username, oldHash, newHash)
	return err
}
```

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
	ParentID  uuid.UUID // the consumed token this one replaced; uuid.Nil for a login's first token
	FamilyID  uuid.UUID // one per login session
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time // token's exp + Config.Leeway: when it can no longer be accepted
	UsedAt    time.Time // first use; zero = unused
}

func (r RefreshTokenRecord) Used() bool // !r.UsedAt.IsZero()
```

A refresh token is a signed JWT. The record holds no secrets. It only tracks whether the token can still be used, and when it was first used.

Besides individual records, a store must remember **families** (one per login session) and whether each has been revoked. Deleting a family's records is not enough. A refresh can be in flight at the moment a family is revoked: its old token is already consumed, but its replacement is not yet created. That replacement must not survive the revocation.

Contract:

- `CreateRefreshToken` saves a new record with a zero `UsedAt`.
  - A record with `ParentID == uuid.Nil` is the first token of a login (`Login` or `IssueTokenPair`) and **starts a new family**.
  - Any other record comes from a `Refresh` (`ParentID` is the consumed token it replaces) and **continues an existing family**. If that family has been revoked **or no longer exists**, return an error **wrapping `auth.ErrTokenRevoked`** and save nothing. Never create the family on this path. A refresh that stalls until after its family was revoked and then purged must not bring the family back.
  - This check and the revoke methods' marking must be **atomic with respect to each other**. A token created at the same time as a revocation must be either rejected or deleted by that revocation. In SQL, lock the family row in both operations (see below).
- `ConsumeRefreshToken(ctx, id, now)` must **atomically** set `UsedAt = now` **only if it is unset**, and return the record **as it was before the call**:
  - If the token was unused, the returned record has a zero `UsedAt`. Exactly one of any number of concurrent callers may get this result. If two callers both see an unused token, one stolen token can be refreshed twice and reuse detection is bypassed. Use a conditional `UPDATE` or a row lock, never a separate read and then write.
  - If the token was already used, return the record with its existing `UsedAt`, and **never overwrite it**. The [reuse grace window](Tokens-and-Keys.md#grace-period) is measured from the first use, so overwriting it would let the window slide forward.
  - If the record does not exist, return an error **wrapping `auth.ErrRefreshTokenNotFound`**. `Refresh` turns that into `ErrTokenRevoked`.
- `RevokeRefreshTokenFamily` **marks the family revoked** and deletes its records. An unknown family is not an error. `Logout` and reuse detection both call it.
- `RevokeRefreshTokensForSubject` revokes every family of that subject in the same way. It must **also** be atomic with `CreateRefreshToken` calls that **start a new family** for the subject (logins). Such a token must either be revoked, or be created only after this call completes, in which case it counts as a new session. Locking existing family rows does not cover this, because a new family has no row yet. The SQL example uses a per-subject advisory lock. A subject with no families is not an error. `RevokeAllSessions` calls it.
- Keep used records until they expire. Reuse detection works only while the spent record exists. If used records are deleted early, a replayed token gets `ErrTokenRevoked` and its family is **not** revoked.
- Keep revoked families until all of their tokens have expired. After that they can be forgotten.

### Purging expired records

Logout and reuse detection delete a family's records, but the family row stays (marked revoked). A session that is simply abandoned leaves its last record, any used ones, and its family in the store until they are purged.

The easiest way to purge is to implement the optional `RefreshTokenPurger` interface on your store:

```go
type RefreshTokenPurger interface {
	// Delete records whose ExpiresAt is before now, and forget families whose
	// tokens have all expired by then. The count is only used for logging.
	PurgeExpiredRefreshTokens(ctx context.Context, now time.Time) (int64, error)
}
```

If the store implements it, every `Authorizer` calls it in the background about every `RefreshPurgeInterval` (default `1h`, randomized by ±25%), with `now` set to 5 minutes before the `Authorizer`'s clock. That margin protects a refresh accepted just before expiry: between consuming the old token and storing the new one, a purge on another instance (perhaps one whose clock runs ahead) must not delete the family. Several instances may purge the same store at once, so the method must tolerate concurrent calls. Deleting by expiry time already does. On a large table, delete in batches so a backlog (for example the first purge after upgrading) does not hold locks for long. Failures are logged as warnings and retried on the next run. The number of removed rows is logged at debug level. `Close` stops the loop and cancels a purge that is in progress.

To purge on your own schedule instead, for example from a cron job, set `RefreshPurgeInterval` to `0` and call `Authorizer.PurgeExpiredRefreshTokens(ctx)`. It returns `ErrNotConfigured` if the store does not implement `RefreshTokenPurger`, and it still works after `Close`.

If your store does not implement the interface, purge it yourself, either with a scheduled job or with your database's TTL feature (Redis `EXPIREAT`, MongoDB TTL indexes, DynamoDB TTL, and so on). Expire records a few minutes after `ExpiresAt` (not at the token's `exp`), and never expire a family before its last token. With the schema below:

```sql
DELETE FROM refresh_families WHERE expires_at < now() - interval '5 minutes';  -- cascades to their tokens
DELETE FROM refresh_tokens   WHERE expires_at < now() - interval '5 minutes';
```

This is safe. A record's `ExpiresAt` is the token's `exp` **plus `Leeway`**, the moment the token can no longer be accepted, so after it the record is not needed. Purging on `ExpiresAt` keeps records, and the tombstones of revoked families, through the leeway window. A family's `expires_at` is the latest `ExpiresAt` of any of its tokens, so once it has passed no token of that family can be presented, and its revoked flag is no longer needed either. A refresh that was stalled past that point cannot recreate the purged family, because continuing a missing family fails (see `ParentID` above). `MemoryRefreshTokenStore` implements `RefreshTokenPurger`. It also purges when a token is created, at most once a minute, with the same 5-minute margin.

## PostgreSQL

### Schema

This is the schema from [`examples/sqlstore/sqlstore.go`](../examples/sqlstore/sqlstore.go):

```sql
CREATE TABLE users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
);

CREATE TABLE signing_keys (
    id         UUID PRIMARY KEY,
    public_key BYTEA NOT NULL,      -- PKIX DER
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ          -- NULL = never
);

-- One row per login session. Revoked rows are kept until expires_at so
-- an in-flight refresh cannot add a token to a revoked session.
CREATE TABLE refresh_families (
    id         UUID PRIMARY KEY,
    subject    TEXT NOT NULL,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL -- latest expiry of any token in it
);
CREATE INDEX ON refresh_families (subject);
CREATE INDEX ON refresh_families (expires_at);

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY,
    family_id  UUID NOT NULL REFERENCES refresh_families ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    issued_at  TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ          -- NULL = unused
);
CREATE INDEX ON refresh_tokens (family_id);
CREATE INDEX ON refresh_tokens (subject);
CREATE INDEX ON refresh_tokens (expires_at);
```

### Implementation

A complete implementation of all four interfaces lives in [`examples/sqlstore/sqlstore.go`](../examples/sqlstore/sqlstore.go) (package `github.com/tpyle/auth/v2/examples/sqlstore`). One `sqlstore.Store` value implements `UserStore`, `PasswordHashUpdater`, `KeyStore` and `RefreshTokenStore` using only `database/sql`. Bring your own PostgreSQL driver, for example `github.com/jackc/pgx/v5/stdlib`. Copy it into your project and adapt it. `uuid.UUID` implements `sql.Scanner` and `driver.Valuer`, so it maps straight onto `UUID` columns.

The refresh-token methods rely on PostgreSQL's default **`READ COMMITTED`** isolation level. Under `REPEATABLE READ` or `SERIALIZABLE`, the races below end in serialization errors, which `Refresh` reports as internal errors. Two parts carry the concurrency guarantees.

**Create vs. revoke.** `CreateRefreshToken` runs in a transaction that holds two locks until commit:

- a **shared** advisory lock on the subject, which `RevokeRefreshTokensForSubject` takes **exclusively**. This covers a brand-new family (a login), which has no row yet for revocation to lock.
- the family row, which `RevokeRefreshTokenFamily` updates. A login **inserts** it, which locks the new row. A refresh **updates** it (extending `expires_at`) with `RETURNING revoked`, which locks the existing row. If the update finds no row (the family was purged) or a revoked one, the create fails with `ErrTokenRevoked`.

Locks are always taken subject first, then family, so the two cannot deadlock. Each create therefore serializes with any revocation that could affect it:

```go
// CreateRefreshToken implements auth.RefreshTokenStore.
//
// Two locks make this atomic with revocation, both held until commit:
//   - A shared advisory lock on the subject, which RevokeRefreshTokensForSubject
//     takes exclusively. This covers a brand-new family, which has no row for
//     revocation to lock yet.
//   - The family row, inserted (login) or updated (refresh), which
//     RevokeRefreshTokenFamily updates.
//
// Either revocation commits first and this sees revoked = TRUE (or, for a new
// family, starts after revocation, as a later login), or this commits first
// and revocation's later statements, with fresh snapshots, revoke the new
// token. Locks are always taken subject first, then family. A refresh whose
// family row is gone (revoked and purged while the request was stalled) is
// rejected rather than recreating the family.
func (s *Store) CreateRefreshToken(ctx context.Context, r auth.RefreshTokenRecord) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, r.Subject); err != nil {
			return err
		}
		if r.ParentID == uuid.Nil {
			// A login: start a new family.
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO refresh_families (id, subject, expires_at) VALUES ($1, $2, $3)`,
				r.FamilyID, r.Subject, r.ExpiresAt); err != nil {
				return err
			}
		} else {
			// A refresh: the family must still exist and not be revoked.
			// The UPDATE locks its row until commit.
			var revoked bool
			err := tx.QueryRowContext(ctx, `
				UPDATE refresh_families SET expires_at = GREATEST(expires_at, $2)
				WHERE id = $1 RETURNING revoked`, r.FamilyID, r.ExpiresAt).Scan(&revoked)
			if errors.Is(err, sql.ErrNoRows) || (err == nil && revoked) {
				return fmt.Errorf("%w: family %s", auth.ErrTokenRevoked, r.FamilyID)
			}
			if err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO refresh_tokens (id, family_id, subject, issued_at, expires_at) VALUES ($1, $2, $3, $4, $5)`,
			r.ID, r.FamilyID, r.Subject, r.IssuedAt, r.ExpiresAt)
		return err
	})
}
```

```go
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_families SET revoked = TRUE WHERE id = $1`, familyID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE family_id = $1`, familyID)
		return err
	})
}
```

```go
// RevokeRefreshTokensForSubject implements auth.RefreshTokenStore.
func (s *Store) RevokeRefreshTokensForSubject(ctx context.Context, subject string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		// Waits for in-flight CreateRefreshToken calls for this subject,
		// including ones starting new families; see CreateRefreshToken.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, subject); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_families SET revoked = TRUE WHERE subject = $1`, subject); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE subject = $1`, subject)
		return err
	})
}
```

(`inTx` is a small helper in the example that commits if the function returns nil and rolls back otherwise.)

**Atomic consume.** A conditional `UPDATE` claims the token only if `used_at IS NULL`. A concurrent caller blocks on the row lock, and PostgreSQL then re-checks the `WHERE` clause against the committed row, so exactly one caller wins. Everyone else falls back to a plain `SELECT`, which returns the already-used record (with its original `used_at`) or reports that it is missing:

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

Wiring:

```go
store := &sqlstore.Store{DB: db}
a, err := auth.New(ctx,
	auth.WithUserStore(store),
	auth.WithKeyStore(store),
	auth.WithRefreshTokenStore(store),
)
```

The example also implements `RefreshTokenPurger`, so each `Authorizer` purges it in the background. It deletes expired tokens before expired families, so the cascade from each family has little left to delete, and works in batches of 1000 with `FOR UPDATE SKIP LOCKED`, so purges on different instances, and refreshes in progress, don't block each other.


## In-memory implementations

| Type | Implements | Notes |
|---|---|---|
| `MemoryUserStore` (`NewMemoryUserStore()`) | `UserStore`, `PasswordHashUpdater` | `SetPasswordHash(username, hash)` adds a user or replaces one. `UpdatePasswordHash` is a compare-and-swap. |
| `MemoryKeyStore` (`NewMemoryKeyStore()`) | `KeyStore` | Used automatically when no `KeyStore` is given. Keeps keys in encoded (PKIX DER) form, like a database would, and `StoreKey` rejects a key without a `PublicKey`. |
| `MemoryRefreshTokenStore` (`NewMemoryRefreshTokenStore()`) | `RefreshTokenStore`, `RefreshTokenPurger` | Tracks families and their revoked state under one mutex, so creation and revocation are atomic. A refresh into a family it no longer knows is rejected with `ErrTokenRevoked`. When a token is created, purges expired records and families at most once a minute. `Len()` reports how many records it holds, including used ones (families are not counted). |

All of them are safe for concurrent use. They never keep caller-owned pointers, so changing a value after passing it in does not affect the store.

Limits:

- **Nothing survives a restart.** With the default `MemoryKeyStore`, every token issued before a restart fails verification after it, because the new process cannot find the old keys. Every user has to log in again.
- **The default `MemoryKeyStore` works for one instance only.** Each process gets its own private store, so a token issued by instance A fails with `ErrInvalidToken` on instance B. Behind a load balancer, use a shared `KeyStore` (and a shared `RefreshTokenStore`).
- When creating a token, `MemoryRefreshTokenStore` purges records and families relative to the new record's `IssuedAt`, so it follows the `Authorizer`'s clock, including one set with `WithClock`.
- They are meant for tests, examples, prototypes and single-instance services that can accept losing every session on restart.

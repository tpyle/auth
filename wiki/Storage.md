# Storage

The library has no database code of its own. You supply persistence through these interfaces:

| Interface | Needed for | Option |
|---|---|---|
| `UserStore` | `Authenticate`, `Login` | `WithUserStore` |
| `PasswordHashUpdater` (optional, on the same value as `UserStore`) | Upgrading outdated hashes automatically | (detected on the `UserStore`) |
| `KeyStore` | Verifying tokens across instances and restarts | `WithKeyStore` (default: in-memory) |
| `RefreshTokenStore` | Refresh tokens, `Refresh`, `Logout` | `WithRefreshTokenStore` |

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
	GetKey(ctx context.Context, id uuid.UUID) (*VerificationKey, error)
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

- `StoreKey` saves a new key. It is called once in `New` and once per rotation. If it fails, `New` fails. If it fails during a rotation, the `Authorizer` keeps signing with the old key and tries again a minute later.
- `GetKey` returns the key, or an error **wrapping `auth.ErrKeyNotFound`**. A missing key makes verification fail with `ErrInvalidToken` (the client's fault). Any other error is an internal failure. Do not return `(nil, nil)` or a key with a nil `PublicKey`. Both are treated as internal errors.
- `ListKeys` returns **all** keys, including expired ones. It is used by expired-key cleanup and by `JWKS`.
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
	ConsumeRefreshToken(ctx context.Context, id uuid.UUID) (RefreshTokenRecord, error)
	RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error
}

type RefreshTokenRecord struct {
	ID        uuid.UUID // the token's "jti"
	FamilyID  uuid.UUID // one per login session
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Used      bool
}
```

A refresh token is a signed JWT. The record holds no secrets. It only tracks whether the token can still be used.

Contract:

- `CreateRefreshToken` saves a new record with `Used == false`.
- `ConsumeRefreshToken` must **atomically** mark the record as used and return the record **as it was before the call**. If two concurrent calls both see `Used == false`, one stolen token can be refreshed twice and reuse detection is bypassed. Use a row lock or a single conditional statement, never a separate read and then write. If the record does not exist, return an error **wrapping `auth.ErrRefreshTokenNotFound`**. `Refresh` turns that into `ErrTokenRevoked`.
- `RevokeRefreshTokenFamily` deletes every record with that `FamilyID`. An unknown family is not an error. `Logout` and reuse detection both call it.
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
    used       BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX refresh_tokens_family_idx  ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (expires_at);
```

### Implementation

This code uses only `database/sql`. Plug in any PostgreSQL driver (for example `github.com/jackc/pgx/v5/stdlib`). `uuid.UUID` implements `sql.Scanner` and `driver.Valuer`, so it maps straight onto `UUID` columns.

```go
package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

// Users implements auth.UserStore and auth.PasswordHashUpdater.
type Users struct{ DB *sql.DB }

func (s *Users) LookupPasswordHash(ctx context.Context, username string) (string, error) {
	var hash string
	err := s.DB.QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE username = $1`, username).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", auth.ErrUserNotFound, username)
	}
	return hash, err
}

func (s *Users) UpdatePasswordHash(ctx context.Context, username, encodedHash string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET password_hash = $2 WHERE username = $1`, username, encodedHash)
	return err
}

// Keys implements auth.KeyStore.
type Keys struct{ DB *sql.DB }

func (s *Keys) StoreKey(ctx context.Context, k *auth.VerificationKey) error {
	der, err := k.MarshalPublicKey()
	if err != nil {
		return err
	}
	var expires sql.NullTime
	if !k.ExpiresAt.IsZero() {
		expires = sql.NullTime{Time: k.ExpiresAt, Valid: true}
	}
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO signing_keys (id, public_key, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		k.ID, der, k.CreatedAt, expires)
	return err
}

func (s *Keys) GetKey(ctx context.Context, id uuid.UUID) (*auth.VerificationKey, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT id, public_key, created_at, expires_at FROM signing_keys WHERE id = $1`, id)
	k, err := scanKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", auth.ErrKeyNotFound, id)
	}
	return k, err
}

func (s *Keys) ListKeys(ctx context.Context) ([]*auth.VerificationKey, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, public_key, created_at, expires_at FROM signing_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*auth.VerificationKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Keys) DeleteKeys(ctx context.Context, ids []uuid.UUID) error {
	for _, id := range ids { // or: DELETE ... WHERE id = ANY($1) with your driver's array support
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM signing_keys WHERE id = $1`, id); err != nil {
			return err
		}
	}
	return nil
}

func scanKey(row interface{ Scan(...any) error }) (*auth.VerificationKey, error) {
	var (
		k       auth.VerificationKey
		der     []byte
		expires sql.NullTime
	)
	if err := row.Scan(&k.ID, &der, &k.CreatedAt, &expires); err != nil {
		return nil, err
	}
	pub, err := auth.ParsePublicKey(der)
	if err != nil {
		return nil, err
	}
	k.PublicKey = pub
	if expires.Valid {
		k.ExpiresAt = expires.Time
	}
	return &k, nil
}

// RefreshTokens implements auth.RefreshTokenStore.
type RefreshTokens struct{ DB *sql.DB }

func (s *RefreshTokens) CreateRefreshToken(ctx context.Context, r auth.RefreshTokenRecord) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, family_id, subject, issued_at, expires_at, used)
		 VALUES ($1, $2, $3, $4, $5, FALSE)`,
		r.ID, r.FamilyID, r.Subject, r.IssuedAt, r.ExpiresAt)
	return err
}

// ConsumeRefreshToken locks the row, sets used, and returns the previous
// value of used in one statement. A concurrent caller blocks on the row lock
// and then sees used = true.
func (s *RefreshTokens) ConsumeRefreshToken(ctx context.Context, id uuid.UUID) (auth.RefreshTokenRecord, error) {
	var r auth.RefreshTokenRecord
	err := s.DB.QueryRowContext(ctx, `
		UPDATE refresh_tokens t SET used = TRUE
		FROM (SELECT id, used FROM refresh_tokens WHERE id = $1 FOR UPDATE) old
		WHERE t.id = old.id
		RETURNING t.id, t.family_id, t.subject, t.issued_at, t.expires_at, old.used`, id).
		Scan(&r.ID, &r.FamilyID, &r.Subject, &r.IssuedAt, &r.ExpiresAt, &r.Used)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.RefreshTokenRecord{}, fmt.Errorf("%w: %s", auth.ErrRefreshTokenNotFound, id)
	}
	return r, err
}

func (s *RefreshTokens) RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE family_id = $1`, familyID)
	return err
}

// PurgeExpired deletes refresh token records that can no longer be used.
// Run it periodically.
func (s *RefreshTokens) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
```

If you would rather not rely on the `UPDATE ... FROM (SELECT ... FOR UPDATE)` form, run `SELECT ... FOR UPDATE` and then `UPDATE ... SET used = TRUE` inside one transaction, and return the values from the `SELECT`.

Wiring:

```go
a, err := auth.New(ctx,
	auth.WithUserStore(&pgstore.Users{DB: db}),
	auth.WithKeyStore(&pgstore.Keys{DB: db}),
	auth.WithRefreshTokenStore(&pgstore.RefreshTokens{DB: db}),
)
```

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

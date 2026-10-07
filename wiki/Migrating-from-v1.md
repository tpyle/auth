# Migrating from v1

v2 is a redesign. The API is not source-compatible, and **all tokens issued by v1 stop working after you upgrade**. Plan for every user to log in once.

## Checklist

1. Change the import path to `github.com/tpyle/auth/v2` and run `go get github.com/tpyle/auth/v2`.
2. Replace `auth.Create(...)` + `Initialize()` with `auth.New(ctx, ...)`, and add `defer a.Close()`.
3. Replace the v1 callback options with `UserStore`, `KeyStore` and `RefreshTokenStore` implementations ([Storage](Storage.md)).
4. Migrate the database: create the new `signing_keys` and `refresh_tokens` tables, and drop the v1 ones. Password hashes stay as they are.
5. Make your user-not-found path return `auth.ErrUserNotFound`.
6. Replace Viper wiring with `UnmarshalKey` into `auth.DefaultConfig()` and rename the config keys ([Configuration](Configuration.md#loading-configuration-with-viper)).
7. Update handlers to the new context helpers and `errors.Is` checks ([Error Handling](Error-Handling.md)).
8. Update clients to store the **new** refresh token after every refresh.

## API mapping

### Construction and authentication

| v1 | v2 |
|---|---|
| `auth.Create(opts...) *Authorizer` | `auth.New(ctx, opts...) (*Authorizer, error)` |
| `a.Initialize() error` | Done inside `New`. Call `a.Close()` on shutdown. |
| `a.Login(username, password) (bool, error)` | `a.Authenticate(ctx, username, password) error`. Wrong credentials give `ErrInvalidCredentials` instead of `false, nil`. |
| `a.LoginAndGetJWT(username, password, claims)` | `a.Login(ctx, username, password)` → `pair.AccessToken`. Extra claims come from `WithClaimsProvider`. |
| `a.LoginAndGetJWTWithRefreshToken(username, password, claims)` | `a.Login(ctx, username, password)` → `pair.AccessToken`, `pair.RefreshToken` |
| `a.LoginWithRefreshToken(token) (sub, bool, error)` | `a.Refresh(ctx, token)`. It also rotates the refresh token. |
| `a.LoginWithRefreshTokenAndGetJWT(token, claims)` | `a.Refresh(ctx, token)` → `*TokenPair` (claims from `ClaimsProvider`) |
| `a.Logout(refreshToken)` | `a.Logout(ctx, refreshToken)`. It revokes the whole session, not just one token. |
| `a.HashPassword(password)` | `a.HashPassword(ctx, password)` or `auth.HashPassword(password, params)` |
| `a.CreateJWT(sub, claims)` | `a.IssueAccessToken(sub, claims)`. Reserved claim names are now an error, not silently dropped. |
| `a.CreateRefreshToken(sub)` | `a.IssueTokenPair(ctx, sub, claims)` (refresh tokens are always issued together with an access token) |
| `a.VerifyToken(s) (*AuthorizerToken, error)` | `a.VerifyAccessToken(ctx, s) (*Claims, error)` |
| `a.KeyFunc` | Removed. Use `VerifyAccessToken`, or `JWKS`/`JWKSHandler` for external verifiers. |

### Store callbacks → interfaces

| v1 option | v2 |
|---|---|
| `WithLookupUserPasswordFunc(func(username) (string, error))` | `WithUserStore(UserStore)`: `LookupPasswordHash(ctx, username)`. Must return `ErrUserNotFound` for unknown users. Optionally also implement `PasswordHashUpdater` (`UpdatePasswordHash(ctx, username, oldHash, newHash)`, a compare-and-swap). |
| `WithStoreNewSigningKeyFunc` | `KeyStore.StoreKey` |
| `WithGetSigningKeyFunc` | Removed. There is no single-key lookup: each `Authorizer` keeps an in-memory copy of the key set loaded with `ListKeys` ([details](Tokens-and-Keys.md#key-set-cache)). |
| `WithGetSigningKeysFunc` | `KeyStore.ListKeys` |
| `WithDeleteExpiredSigningKeyFunc`, `WithDeleteExpiredSigningKeysFunc` | `KeyStore.DeleteKeys` |
| `WithLookupRefreshTokenFunc` | `RefreshTokenStore.ConsumeRefreshToken(ctx, id, now)` (atomically sets `UsedAt` if unset and returns the previous record) |
| `WithStoreRefreshTokenFunc` | `RefreshTokenStore.CreateRefreshToken`. A record without `ParentID` (login) starts a family. A record with one (refresh) continues it, and must fail with `ErrTokenRevoked` if the family is revoked or gone. |
| `WithDeleteRefreshTokenFunc` | `RefreshTokenStore.RevokeRefreshTokenFamily` (marks the family revoked and deletes its tokens) |
| (none) | `RefreshTokenStore.RevokeRefreshTokensForSubject`, used by the new `Authorizer.RevokeAllSessions` |

Pass them with `WithKeyStore(...)` and `WithRefreshTokenStore(...)`.

### Settings

| v1 option (default) | v2 |
|---|---|
| `WithSaltLength` (16) | `Argon2Params.SaltLength` (16) |
| `WithHashTime` (4) | `Argon2Params.Iterations` (**3**) |
| `WithHashMemoryKiB` (131072) | `Argon2Params.MemoryKiB` (**65536**) |
| `WithHashThreads` (4) | `Argon2Params.Parallelism` (4) |
| `WithKeyLength` (32) | `Argon2Params.KeyLength` (32) |
| (all five) | Set together with `WithArgon2Params(p)`, starting from `DefaultArgon2Params()` |
| `WithExpirationTime` (15m) | `WithAccessTokenTTL` (15m) |
| `WithRefreshTokenExpirationTime` (7d) | `WithRefreshTokenTTL` (7d) |
| `WithRefreshTokenLength` | Removed. Refresh tokens no longer contain a random secret. |
| `WithSigningKeyCreationFreq` (0 = never) | `WithKeyRotationInterval` (**24h**) |
| `WithSigningKeyValidity` | Removed. Key expiry is computed from rotation interval + token TTLs. |
| `WithAuthHeader(*string)` (`nil` = off) | `WithAuthHeader(string)` (`""` = off) |
| `WithAuthCookie(*string)` (`nil` = off) | `WithAuthCookie(string)` (`""` = off) |
| `WithViper(v)`, `WithViperPrefix(v, prefix)` | `cfg := auth.DefaultConfig(); v.UnmarshalKey("auth", &cfg)` then `WithConfig(cfg)` |

New in v2: `WithArgon2Limits`, `WithMaxConcurrentHashes`, `WithRefreshReuseGrace`, `WithKeyCacheTTL`, `WithIssuer`, `WithAudience`, `WithLeeway`, `WithClaimsProvider`, `WithUnauthorizedHandler`, `WithLogger`, `WithClock`.

Viper keys changed:

| v1 key | v2 key |
|---|---|
| `auth.salt_length` | `auth.argon2.salt_length` |
| `auth.hash_time` | `auth.argon2.iterations` |
| `auth.hash_memory_kib` | `auth.argon2.memory_kib` |
| `auth.hash_threads` | `auth.argon2.parallelism` |
| `auth.key_length` | `auth.argon2.key_length` |
| `auth.expiration_time` | `auth.access_token_ttl` |
| `auth.signing_key_creation_freq` | `auth.key_rotation_interval` |
| `auth.signing_key_validity` | (removed) |
| `auth.auth_header`, `auth.auth_cookie` | unchanged |

### Types and helpers

| v1 | v2 |
|---|---|
| `KeyPairWithCreationTime{ID, PublicKey, CreationTime}` | `VerificationKey{ID, PublicKey, CreatedAt, ExpiresAt}` |
| `kp.GetPublicKeyAsBinary()` | `key.MarshalPublicKey()` (same PKIX DER encoding) |
| `GetECDSAPublicKeyFromBinary(b)` | `ParsePublicKey(b)` (now rejects non-P-256 keys) |
| `RefreshToken{ID, Rand, Subject}` | `RefreshTokenRecord{ID, ParentID, FamilyID, Subject, IssuedAt, ExpiresAt, UsedAt}` (with method `Used()`) |
| `AuthorizerToken` (`jwt.Token`) / `tok.IsValid()` | `*Claims` (only returned when valid) |
| `GetToken(ctx) *AuthorizerToken` | `ClaimsFromContext(ctx) (*Claims, bool)` |
| `WithToken(ctx, tok)` | `ContextWithClaims(ctx, claims)` |
| `a.GetTokenFromRequest(r) *AuthorizerToken` | `a.ClaimsFromRequest(r) (*Claims, error)` |
| `HasToken(r) bool` | `_, ok := ClaimsFromContext(r.Context())` |
| `GetSub(r) (string, error)` | `SubjectFromContext(r.Context()) (string, bool)` |
| claims via `tok.Claims.(jwt.MapClaims)["role"]` | `claims.GetString("role")` or `claims.Extra["role"]` |

## Behavior changes

### Fixed v1 bugs

- **Verifying with stored keys never worked.** v1 put `kid` in the token claims instead of the JOSE header, and stored the public key under a different UUID from the one it signed with. A `GetSigningKeyFunc` lookup therefore always failed. v2 puts `kid` in the header and uses one ID for both.
- **Refresh tokens were accepted as access tokens.** v1 had no token type, so a refresh token (valid for 7 days) passed `VerifyToken` and the middleware. v2 checks `typ` everywhere.
- **Changing Argon2 parameters locked users out.** v1 ignored the parameters stored in each hash and recomputed with the current config. v2 reads them from the hash, and can upgrade hashes on login.
- **Rotation threw away the new private key.** v1's background rotation stored a new public key but kept signing with the old private key. v2 swaps keys after the public half is stored.
- **Key cleanup could delete keys still in use.** v1 deleted keys by age (`SigningKeyValidity`) without regard to token lifetimes or the current key. v2 gives each key an expiry covering every token it can have signed, and never deletes the current key.

Other differences:

- The cookie no longer overrides the header. In v2, a valid `Bearer` header wins.
- `RequireAuthHandler` now puts the claims in the request context. Its 401 response has a `WWW-Authenticate` header and the body `{"error":"unauthorized"}` (v1: `{"message": "missing token"}`). Internal errors return 500.
- Unknown users take as long as wrong passwords to reject, and both return `ErrInvalidCredentials`.
- `Logout` revokes the whole session, including refresh tokens issued from it. The new `RevokeAllSessions(ctx, subject)` ends every session of a user.
- Refreshing **rotates** the refresh token. Reusing an old one after the `RefreshReuseGrace` window (default 30s) revokes the session ([details](Tokens-and-Keys.md#reuse-detection)).
- Background goroutines stop on `Close`. v1's tickers ran forever.
- Signing keys rotate every 24h by default (v1: never).
- The library no longer depends on Viper.

### Password hashes: no migration needed

Existing v1 hashes are standard Argon2id PHC strings and **stay valid**. v1's defaults produced `$argon2id$v=19$m=131072,t=4,p=4$...`. v2 verifies these using the parameters inside the hash. They are well within the default verification limits (`DefaultArgon2Limits()`: 256 MiB, 16 iterations, 255 lanes). If you lower `Argon2Limits`, keep them at or above the v1 parameters until all hashes are upgraded. Because they differ from v2's defaults (`m=65536,t=3,p=4`), they are **rehashed transparently** on each user's next successful login, provided your `UserStore` implements `PasswordHashUpdater` (a compare-and-swap, see [Storage](Storage.md#passwordhashupdater)). Without it, the old hashes keep working but are never upgraded.

If you want to keep v1's cost, configure it explicitly:

```go
auth.WithArgon2Params(auth.Argon2Params{
	MemoryKiB: 128 * 1024, Iterations: 4, Parallelism: 4, SaltLength: 16, KeyLength: 32,
})
```

Note that 128 MiB per hash doubles peak memory. Size `MaxConcurrentHashes` with that in mind ([Security](Security.md#memory-sizing)).

### Tokens: all invalidated

Every v1 access token and refresh token is rejected after the upgrade. They have no `typ` claim, no `kid` header, and were signed by keys v2 has never seen. Users must log in again. If v1 access tokens are still in flight, roll out during a quiet period, or accept up to `AccessTokenTTL` of 401s.

### Refresh-token storage: new schema

The v1 refresh table (`id`, `rand`, `subject`) cannot be migrated: v2 records hold no `Rand` secret, and add `FamilyID`, `IssuedAt`, `ExpiresAt` and `UsedAt` (a nullable `used_at` timestamp). v2 also needs indexes on `family_id`, `subject` and `expires_at`. It also needs a new `refresh_families` table (`id`, `subject`, `revoked`, `expires_at`), which `refresh_tokens.family_id` references with `ON DELETE CASCADE`. Stores must remember revoked families so that a refresh racing a logout cannot survive it. Drop the old table and create both tables from [Storage](Storage.md#postgresql). Likewise, replace the v1 signing-key table: v2 needs an `expires_at` column, and v1's stored keys are useless because their IDs never matched any token.

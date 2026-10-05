# Tokens and Keys

## Two kinds of token

Both kinds are JWTs signed with ES256 by the same signing keys. The `typ` header and the `typ` claim tell them apart:

| | Access token | Refresh token |
|---|---|---|
| `typ` header | `"at+jwt"` (RFC 9068) | `"rt+jwt"` |
| `typ` claim | `"access"` | `"refresh"` |
| Lifetime | `AccessTokenTTL` (default 15m) | `RefreshTokenTTL` (default 7 days) |
| Purpose | Sent with every API request | Traded for a new pair at a refresh endpoint |
| Server state | None (stateless) | One `RefreshTokenRecord` per token |
| Extra claims | Yes (`ClaimsProvider` or `extra` argument) | No |
| Accepted by | `VerifyAccessToken`, middleware | `Refresh`, `Logout` |

Each kind is rejected with `ErrInvalidToken` where the other is expected. A refresh token sent as a Bearer token fails, and an access token sent to `Refresh` fails.

### Claim layout

JOSE header (refresh tokens use `"typ": "rt+jwt"`):

```json
{ "alg": "ES256", "typ": "at+jwt", "kid": "<signing key UUID>" }
```

Access token payload:

```json
{
  "sub": "alice",
  "iat": 1767225600,
  "exp": 1767226500,
  "jti": "<random UUID>",
  "typ": "access",
  "iss": "https://auth.example.com",
  "aud": ["https://api.example.com"],
  "role": "admin"
}
```

`iss` and `aud` appear only when `Issuer`/`Audience` are configured. `aud` is always written as an array. Anything not listed above (such as `role`) is an extra claim.

A refresh token payload has the same reserved claims with `"typ": "refresh"`, plus `"fam": "<family UUID>"`. It carries no extra claims.

### Reserved claims

The package manages `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `typ` and `fam`. `IsReservedClaim(name)` reports whether a name is one of them. If extra claims from `IssueAccessToken`, `IssueTokenPair` or a `ClaimsProvider` use one of these names, the call fails with `ErrReservedClaim`.

### Verified claims

`VerifyAccessToken` returns `*Claims`:

| Field | Source |
|---|---|
| `ID` | `jti` |
| `Subject` | `sub` |
| `Issuer` | `iss` |
| `Audience` | `aud` |
| `IssuedAt`, `ExpiresAt` | `iat`, `exp` |
| `Type` | `typ` (`TokenTypeAccess` or `TokenTypeRefresh`) |
| `Extra` | every non-reserved claim |

`Extra` values are decoded from JSON, so numbers are `float64`, arrays are `[]any`, and objects are `map[string]any`. `claims.GetString(name)` is a shortcut for string-valued extras.

Verification checks: the signature (ES256 only), that `kid` is a known and unexpired key, `exp` (required), `iat` (it must not be in the future), `iss` and `aud` when configured, the `typ` claim, and that `sub`, `jti` and `typ` are present. `Leeway` applies to the time checks.

## Refresh rotation

Each successful `Refresh`:

1. Verifies the refresh token (signature, expiry, `typ == "refresh"`, `fam`).
2. Calls `ConsumeRefreshToken`, which atomically marks the record as used.
3. Calls the `ClaimsProvider` again, so role changes show up at the next refresh.
4. Issues a new access token and a new refresh token **in the same family**, with a fresh `RefreshTokenTTL`.

A session therefore lasts for as long as the client refreshes at least once every `RefreshTokenTTL`. The library sets no maximum session length.

### Families

A **family** is the chain of refresh tokens that descends from one `Login` (or `IssueTokenPair`). Each login starts a new family with a new UUID. Revoking a family deletes every record in it, which ends that session and no other.

### Reuse detection

A refresh token is meant to be used exactly once. If a token whose record is already marked used is presented again (and it has not expired), `Refresh`:

1. Revokes the whole family with `RevokeRefreshTokenFamily`.
2. Returns `ErrRefreshTokenReused`.

The reasoning: if both an attacker and the real client hold the same refresh token, whichever uses it second triggers revocation, which shuts out the attacker too. Both must then log in again.

**Caveat: concurrent refreshes look like reuse.** If a client sends two refresh requests with the same token at the same time (two browser tabs, a retry after a timeout, a race at app start), one succeeds and the other revokes the session. Clients should make sure only one refresh is in flight at a time and always save the newest refresh token.

**Caveat: failures after consumption.** The `ClaimsProvider` is called before the token is consumed, so a provider failure leaves the token usable for a retry. But if `CreateRefreshToken` fails after consumption, the presented token is already spent, and a client that retries with it triggers reuse detection.

Reuse detection depends on used records staying in the store until they expire. See [Storage](Storage.md#refreshtokenstore).

## Logout

`Logout(ctx, refreshToken)`:

- verifies the refresh token's signature, `typ`, issuer and audience, but **accepts expired tokens**, so a client can always log out cleanly.
- revokes the token's whole family, which includes refresh tokens issued later from it.
- is idempotent. Logging out an already-revoked session returns nil.

Logout does **not** invalidate access tokens already issued. They are stateless and stay valid until `exp`. That is why `AccessTokenTTL` should be short. If you need immediate revocation of access tokens, keep a denylist of `jti` values in your own middleware.

The library has no "log out everywhere" operation. `RefreshTokenStore` has no revoke-by-subject method. To end every session for a user (for example after a password change), delete their records from your refresh token table directly (`DELETE FROM refresh_tokens WHERE subject = $1`).

## Signing-key rotation

### Lifecycle

1. **`New`** generates a P-256 key pair, saves the public half with `KeyStore.StoreKey`, and starts signing with it. It then deletes expired keys from the store.
2. **Every `KeyRotationInterval`** (default 24h), a background goroutine generates a new key, saves its public half, then switches to it for signing. Because the key is saved before it is used, no token is ever signed by a key that other instances cannot look up.
3. After each successful rotation, **expired keys are deleted** from the store and from the local cache.

Each key's `ExpiresAt` is set when the key is created:

```
ExpiresAt = CreatedAt + KeyRotationInterval + max(AccessTokenTTL, RefreshTokenTTL) + 5 minutes
```

A key signs for at most one rotation interval. The last token it signs can live for the longest token TTL. The 5-minute margin covers small delays in rotation. With the defaults, that is 24h + 168h + 5m = 192h5m.

- **The current signing key is never deleted** by cleanup, even if it has passed its `ExpiresAt`.
- **A key past its `ExpiresAt` is rejected** during verification even if it is still in the store, so cleanup timing does not affect correctness.
- **If a rotation fails** (for example the `KeyStore` is down), the error is logged and the rotation is retried after 1 minute (or after `KeyRotationInterval`, if that is shorter). Until a retry succeeds, the old key keeps signing. Tokens it signs past its planned window may stop verifying shortly before their own `exp`, once the key's `ExpiresAt` passes.
- **`KeyRotationInterval = 0`** turns rotation off. Keys get no `ExpiresAt`, are never cleaned up, and each restart adds one more key to the store.
- **`Close`** stops the rotation goroutine and waits for it to exit.

Private keys exist only in memory. A restart always creates a new key, and tokens signed by the old process stay verifiable through the old public key in the store.

### Key cache

To verify a token whose `kid` is not the instance's own current key, the `Authorizer` loads the key from the `KeyStore` with `GetKey` and caches it for `KeyCacheTTL` (default 5m). As a result:

- A key deleted from the store by hand keeps working on other instances for up to `KeyCacheTTL`.
- `KeyCacheTTL = 0` turns caching off, so every verification of another instance's token calls `GetKey`.
- Unknown `kid`s are not cached. Every token with an unknown `kid` calls `GetKey`.

### Multiple instances

Give every instance the **same `KeyStore`** (and the same `RefreshTokenStore`, and the same `Issuer`/`Audience`). Then:

- Each instance has its own signing key, and they rotate independently.
- Any instance verifies any other instance's tokens by loading the `kid` from the shared store.
- Any instance may delete any expired key. `DeleteKeys` must ignore missing IDs because instances race on this.
- The store holds about `instances × (1 + (KeyRotationInterval + max TTL + 5m) / KeyRotationInterval)` unexpired keys. With the defaults that is about 9 per instance, plus one per restart.

With the default private `MemoryKeyStore`, instances **cannot** verify each other's tokens.

## JWKS

`Authorizer.JWKS(ctx)` returns every unexpired public key in the `KeyStore` (from all instances), newest first, as a JSON Web Key Set. `JWKSHandler()` serves it with `Cache-Control: public, max-age=300`. Mount it at `/.well-known/jwks.json`:

```go
mux.Handle("GET /.well-known/jwks.json", a.JWKSHandler())
```

```json
{
  "keys": [
    {
      "kty": "EC", "crv": "P-256",
      "x": "...", "y": "...",
      "kid": "6f1c...", "use": "sig", "alg": "ES256"
    }
  ]
}
```

Services that verify tokens with their own JWT library should:

- **Fetch the set again when they see an unknown `kid`** (with a rate limit). Rotation adds keys, and an instance starts signing with a new key as soon as it is stored. A verifier that only refreshes on a timer will reject valid tokens until its next fetch.
- **Require the `at+jwt` header type** (RFC 9068; many JWT libraries can enforce it), or `typ == "access"` in the payload. Refresh tokens are signed by the same keys. A verifier that skips this check would accept a refresh token, which lives much longer, as an access token.
- Allow only `alg: ES256`, and check `exp`, and `iss`/`aud` if you use them.

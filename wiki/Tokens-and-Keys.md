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

Each kind is rejected with `ErrInvalidToken` where the other is expected. Sending a refresh token in the `Authorization` header fails, and so does passing an access token to `Refresh`.

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

Verification checks: the signature (ES256 only), that `kid` is a known and unexpired key, `exp` (required), `iat` (it must not be in the future), `iss` and `aud` when configured, the `typ` claim, and that `sub`, `jti` and `typ` are present. `Leeway` applies to the time checks. `ErrTokenExpired` is returned only for a token that passes every other check (signature, header and claim type, required claims, issuer, audience, and `iat`/`nbf` not in the future) and is merely past `exp`. Any other failure gives `ErrInvalidToken`, even if the token is also expired. For example, an expired refresh token passed to `VerifyAccessToken` gives `ErrInvalidToken`.

## Refresh rotation

Each successful `Refresh`:

1. Verifies the refresh token (signature, expiry, `typ`, issuer/audience, `fam`).
2. Calls the `ClaimsProvider` again, so role changes show up at the next refresh. This runs before the token is consumed, so if the provider fails, the client can retry with the same token.
3. Calls `ConsumeRefreshToken(ctx, id, now)`, which atomically sets the record's `UsedAt` if it was unset and returns the record as it was before.
4. Checks the record's subject and family against the token, then applies [reuse detection](#reuse-detection) if the record was already used.
5. Issues a new access token and a new refresh token **in the same family**, with a fresh `RefreshTokenTTL`.

A session therefore lasts for as long as the client refreshes at least once every `RefreshTokenTTL`. The library sets no maximum session length.

### Families

A **family** is the chain of refresh tokens that descends from one `Login` (or `IssueTokenPair`). Each login starts a new family with a new UUID. Revoking a family deletes every record in it, which ends that session and no other.

#### Revocation is final

The store remembers revoked families, not just their deleted records, and refuses to create new tokens in them. This closes a race. A refresh can be in flight when its family is revoked (by `Logout`, `RevokeAllSessions` or reuse detection): its old token is already consumed, but its replacement does not exist yet. There are two outcomes. Usually creating the replacement fails, and `Refresh` returns an error wrapping `ErrTokenRevoked` with no pair. Or the replacement was created just before the revocation: then `Refresh` returns a pair, but the revocation deletes the new refresh token, so the client's next refresh gets `ErrTokenRevoked`. Either way, no refresh token in a revoked family survives. In the second case the new access token, like every access token, stays valid until its `exp`. See the [store contract](Storage.md#refreshtokenstore).

### Reuse detection

A refresh token is meant to be used once. When a token whose record already has `UsedAt` set (and which has not expired) is presented again, the outcome depends on `RefreshReuseGrace` (default 30s):

| Time since the token's **first** use | Result |
|---|---|
| ≤ `RefreshReuseGrace` | Tolerated. A new pair is issued in the same family, exactly as for a first use. |
| > `RefreshReuseGrace` | Reuse. The whole family is revoked with `RevokeRefreshTokenFamily`, and `Refresh` returns `ErrRefreshTokenReused`. |

The reasoning: if both an attacker and the real client hold the same refresh token, whichever uses it second (after the grace window) triggers revocation, which shuts out the attacker too. Both must then log in again.

#### Grace period

The grace window handles legitimate clients that present the same token more than once in quick succession:

- several browser tabs refreshing at the same moment,
- two concurrent requests at app start,
- a retry after the response to the first refresh was lost (a timeout, a dropped connection, or a failure after the token was consumed, such as `CreateRefreshToken` failing).

Each of these gets a valid new pair instead of being logged out.

The window is measured from the token's **first** use. `UsedAt` is set once and never overwritten, so repeated reuses do not extend the window. A token is accepted for at most `RefreshReuseGrace` after its first exchange, however often it is presented.

The window applies in both directions. When instances' clocks differ, a reuse can appear to happen *before* the first use. It is tolerated only if it is within `RefreshReuseGrace` of the first use either way, so a fast clock on another instance cannot stretch the window. Keep instance clocks synchronized (for example with NTP) to well within `RefreshReuseGrace`. If skew exceeds it, legitimate concurrent refreshes across instances are treated as theft. That fails safe, but it logs users out.

**Security trade-off:** a stolen refresh token replayed inside the window is not detected. The attacker gets a working pair in the same family, and nothing is revoked. Keep the window short. Seconds are enough for the races above.

**`RefreshReuseGrace = 0` is strict mode.** Any second use of a token is treated as theft, even if the two requests raced and the clocks on two instances make the second appear earlier than the first. In strict mode, concurrent refreshes and retries after a lost response **do** revoke the session. That includes the new token the first request is issuing: either its creation is refused, or the revocation deletes it (see [Revocation is final](#revocation-is-final)). Both requests end up logged out. The same happens with a grace period if the second use comes after the window. Clients should then make sure only one refresh is in flight at a time and always save the newest refresh token.

Reuse detection depends on used records staying in the store until they expire. If a used record is deleted early, a replayed token gets `ErrTokenRevoked` and its family is not revoked. See [Storage](Storage.md#refreshtokenstore).

## Logout

`Logout(ctx, refreshToken)`:

- verifies the refresh token's signature, `typ`, issuer and audience.
- revokes the token's whole family, which includes refresh tokens issued later from it.
- is idempotent. Logging out an already-revoked session returns nil.

**Pass the most recent refresh token.** Expired tokens are accepted as long as their signature can still be checked. That is **guaranteed until the token's `exp` + `Leeway`**. After that, its signing key may be retired, and `Logout` returns `ErrInvalidToken`. A client holding the latest refresh token can therefore always log out while that token could still be used.

An **older** refresh token from a session that has since been refreshed can pass that point while the session is still active, because the session lives on through newer tokens. Logging out with such a token may then fail with `ErrInvalidToken` and leave the session running. To end every session regardless of which tokens the client still has, use [`RevokeAllSessions`](#revoking-all-sessions).

Logout does **not** invalidate access tokens already issued. They are stateless and stay valid until `exp`. That is why `AccessTokenTTL` should be short. If you need immediate revocation of access tokens, keep a denylist of `jti` values in your own middleware.

### Revoking all sessions

`RevokeAllSessions(ctx, subject)` revokes every refresh token issued to a subject, across all sessions and devices. It calls `RefreshTokenStore.RevokeRefreshTokensForSubject`. Use it after a password change, or when you disable an account. To keep the current device signed in, issue it a new pair afterwards:

```go
if err := a.RevokeAllSessions(ctx, username); err != nil {
	return err
}
pair, err := a.IssueTokenPair(ctx, username, nil) // new session for this device
```

- A login that creates its session at the same moment is either revoked too, or creates its session after the call completes. The store contract requires this ([Storage](Storage.md#refreshtokenstore)). A session created after the call completes is a new session and is not affected.
- **For a password change, change the password first, then call `RevokeAllSessions`.** In the reverse order, any login with the old password between the two calls would create a valid new session. In this order, only a login whose password check came before the change and whose session creation came after the revocation can survive. The library cannot tie sessions to password versions. See [Security](Security.md#recommendations).
- It returns `ErrNotConfigured` without a `RefreshTokenStore`, and an error for an empty subject. A subject with no sessions is not an error.
- Access tokens already issued stay valid until they expire.
- A refresh that is in flight when you revoke fails with `ErrTokenRevoked`, or its new refresh token is deleted by the revocation (see [Revocation is final](#revocation-is-final)). It cannot keep the session alive.
- To keep a disabled account from **logging in** again, check account status in your `UserStore` or `ClaimsProvider`. `RevokeAllSessions` only ends existing sessions.

## Signing-key rotation

### Lifecycle

With rotation on, each instance holds two keys: the **current** key, which signs now, and the **next** key, which is already published and will sign after the next rotation.

1. **`New`** generates the current key and stores its public half with `KeyStore.StoreKey`. If rotation is on, it also generates and stores the next key. Then it deletes expired keys from the store. If either store call fails, `New` fails.
2. **Every `KeyRotationInterval`** (default 24h), a background goroutine **promotes** the pre-stored next key to current. No store call is needed for this, so a `KeyStore` outage at rotation time does not delay rotation.
3. It then generates and stores a **new next key**. If that fails, the error is logged and the step is retried every minute until it succeeds.
4. Then it **deletes expired keys** from the store and from its in-memory key set.

If no next key exists at rotation time (because storing it kept failing), or the next key's own signing window has already passed (because rotation ran very late), a fresh key is generated and stored on the spot before switching. If that also fails, the old key keeps signing for now (see the signing-time guard below), and the rotation is retried after 1 minute (or after `KeyRotationInterval`, if that is shorter). Every key is stored before it signs anything, so no token is ever signed by a key other instances cannot look up.

Each key's `ExpiresAt` is set when the key is created:

```
ExpiresAt = activation time + KeyRotationInterval + max(AccessTokenTTL, RefreshTokenTTL) + 5 minutes + Leeway
```

A key signs for at most one rotation interval after it is activated (its signing window). The last token it signs can live for the longest token TTL, and it is accepted for `Leeway` past its `exp`. The 5-minute margin covers small delays in rotation. With the defaults (`Leeway` = 0), that is 24h + 168h + 5m = 192h5m after activation. A next key is created one interval before it activates, so it is kept one interval longer than a key created on the spot.

- **The current and next keys are never deleted** by cleanup, even if they have passed their `ExpiresAt`.
- **A key past its `ExpiresAt` is rejected** during verification even if it is still in the store, so cleanup timing does not affect correctness.
- **The 5-minute margin also bounds a late rotation.** A key may keep signing for up to 5 minutes past its planned window, and every token it signs in that time is still covered by its `ExpiresAt`.
- **`KeyRotationInterval = 0`** turns rotation off. There is no next key, keys get no `ExpiresAt`, they are never cleaned up, and each restart adds one more key to the store.
- **`Close`** stops the rotation goroutine and waits for it to exit.

#### Signing-time guard

Each key has a planned signing window: from its activation to activation + `KeyRotationInterval`. Normally the background loop rotates on time. If it falls behind (for example because the process or VM was suspended), the current key could pass its window. Tokens it signed then would outlive the key's stored `ExpiresAt`, and other instances would stop accepting them before their `exp`.

To prevent this, every signing operation first checks the current key. If the key is more than 5 minutes past the end of its window, the operation rotates **synchronously** before signing:

- If the pre-generated next key is still within its own window, it is promoted.
- Otherwise a fresh key is generated and stored with `KeyStore.StoreKey`.

If no usable key can be stored (the `KeyStore` is down), **issuing fails** with an internal error instead of signing with a key whose expiry would not cover the token. This affects `Login`, `Refresh`, `IssueAccessToken` and `IssueTokenPair`. Verification is not affected. Only one goroutine rotates, and concurrent callers then use the key it installed. With rotation off (`KeyRotationInterval = 0`), keys have no window, so the guard never triggers.

Private keys exist only in memory. A restart always creates new keys, and tokens signed by the old process stay verifiable through the old public keys in the store. The old process's unused next key stays in the store until it expires.

### Key set cache

Each `Authorizer` keeps an in-memory copy of the whole key set from the `KeyStore`:

- It reloads the set with `ListKeys` every `KeyCacheTTL` (default 5m). The reload is triggered by the first verification after the copy goes stale. `KeyCacheTTL = 0` means the set is reloaded on every verification of another instance's token, at most once per second.
- When a token names a `kid` the instance does not know, it reloads the set at once, **at most once per second**. A flood of tokens with random `kid`s costs at most one `ListKeys` call per second per instance, and the copy does not grow because unknown IDs are never stored.
- A key deleted from the store by hand keeps working on an instance until its next reload (up to `KeyCacheTTL`).
- **If the store is down,** keys the instance already knows keep verifying (a warning is logged). A token with an unknown `kid` fails with the store error, which is an internal error (500). That includes tokens arriving within the same second as a failed reload.
- The instance's own current key never needs the store.

Because other instances' next keys are already in the store, they are normally in this copy before they sign anything.

### Multiple instances

Give every instance the **same `KeyStore`** (and the same `RefreshTokenStore`, and the same `Issuer`/`Audience`). Then:

- Each instance has its own signing keys, and they rotate independently.
- Any instance verifies any other instance's tokens through its copy of the shared key set.
- Any instance may delete any expired key. `DeleteKeys` must ignore missing IDs because instances race on this.
- The store holds about `instances × (2 + (KeyRotationInterval + max TTL + 5m + Leeway) / KeyRotationInterval)` unexpired keys. With the defaults that is about 10 per instance, plus two per restart.

With the default private `MemoryKeyStore`, instances **cannot** verify each other's tokens.

## JWKS

`Authorizer.JWKS(ctx)` returns every unexpired public key in the `KeyStore` (from all instances), newest first, as a JSON Web Key Set. It reads the store directly on each call. Malformed stored entries (a nil key or a nil `PublicKey`) are skipped rather than failing the whole set. The set includes the **next** keys that have not started signing yet, so a single freshly started instance publishes two keys. A verifier that caches the set for less than `KeyRotationInterval` therefore knows every key before it signs anything. The one exception is a freshly started instance's first key, which signs immediately. `JWKSHandler()` serves it with `Cache-Control: public, max-age=N`, where N is the smaller of 5 minutes and half of `KeyRotationInterval` (5 minutes when rotation is off). A set cached for that long always contains a pre-published key before that key starts signing. Mount it at `/.well-known/jwks.json`:

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

- **Fetch the set again when they see an unknown `kid`** (with a rate limit). Rotated keys are published one interval before use, but a newly started (or restarted) instance signs with its first key right away. A verifier that only refreshes on a timer would reject that instance's tokens until its next fetch.
- **Require the `at+jwt` header type** (RFC 9068; many JWT libraries can enforce it), or `typ == "access"` in the payload. Refresh tokens are signed by the same keys. A verifier that skips this check would accept a refresh token, which lives much longer, as an access token.
- Allow only `alg: ES256`, and check `exp`, and `iss`/`aud` if you use them.

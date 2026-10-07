# Security

## Password hashing

### Argon2id defaults

`DefaultArgon2Params()` is the **second recommended option in RFC 9106 §4**:

| Parameter | Value |
|---|---|
| Memory | 64 MiB (`MemoryKiB: 65536`) |
| Iterations | 3 |
| Parallelism | 4 lanes |
| Salt | 16 random bytes |
| Hash | 32 bytes |

Hashes are stored as PHC strings, `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`, with unpadded standard base64. `VerifyPassword` reads the cost parameters **from the hash**, not from the config, and compares in constant time. Only Argon2id version 19 is accepted.

### Verification limits

Because the cost parameters come from the stored hash, a corrupt or tampered hash (for example `m=4294967295`) could otherwise make a single login allocate gigabytes of memory or run for minutes. To prevent this, every hash is checked against **limits** before it is computed. A hash whose parameters exceed them fails with `ErrInvalidHash`, and no Argon2 work is done.

| Limit | `DefaultArgon2Limits()` |
|---|---|
| `MemoryKiB` | 256 MiB (`256 * 1024`) |
| `Iterations` | 16 |
| `Parallelism` | 255 |
| `SaltLength` | 64 bytes |
| `KeyLength` | 128 bytes |

- `VerifyPassword` uses `DefaultArgon2Limits()`. `VerifyPasswordWithLimits(password, hash, limits)` takes explicit limits.
- `Authenticate` and `Login` use `Config.Argon2Limits` (default `DefaultArgon2Limits()`, option `WithArgon2Limits`).
- `New` rejects a config whose `Argon2` parameters exceed `Argon2Limits` in any field, so you can never create hashes you would refuse to verify.
- Independently of the configured limits, parsing a PHC string rejects any salt or hash field whose decoded length would exceed **1024 bytes**, before decoding it, so an oversized string cannot force a large allocation. This applies to `VerifyPassword`, `VerifyPasswordWithLimits` and `NeedsRehash`. For the same reason, `Argon2Limits.SaltLength` and `KeyLength` may not be set above 1024.
- The defaults are far above any sensible setting. v1's `m=131072,t=4,p=4` hashes are well within them. Lowering the limits to just above the parameters you have actually used tightens the bound on per-login cost.

If you raise the cost, measure first: one login should take a few hundred milliseconds at most on your hardware.

### Memory sizing

Each running hash allocates memory. `MaxConcurrentHashes` (default: `GOMAXPROCS` ÷ 4 lanes, at least 1; `GOMAXPROCS` respects container CPU limits) caps how many run at once. Hashing a new password uses `Argon2.MemoryKiB`, but verifying a stored hash uses **that hash's own** memory cost, which can be anything up to `Argon2Limits.MemoryKiB`. The guaranteed upper bound is therefore:

```
MaxConcurrentHashes × max(Argon2.MemoryKiB, Argon2Limits.MemoryKiB)
```

With the defaults on an 8-core machine, normal operation uses 2 × 64 MiB = 128 MiB, and the worst case (every concurrent login hitting a hash at the limit) is 2 × 256 MiB = 512 MiB. If all your stored hashes use the current parameters, lower `Argon2Limits.MemoryKiB` to match `Argon2.MemoryKiB`, so the bound equals normal operation. Keep it at or above the largest cost among your stored hashes, or those users can no longer log in. Set `MaxConcurrentHashes` so this fits within your container's memory limit, with room left for everything else. Requests beyond the cap wait for a slot (and give up when their `ctx` is cancelled), so a flood of login requests causes queueing instead of running out of memory. Each hash uses `Parallelism` threads, so the default cap keeps the CPU fully used without oversubscribing it.

`MaxConcurrentHashes` applies to `Authorizer.HashPassword`, `Authenticate` and `Login`. The package-level `HashPassword`/`VerifyPassword` functions ignore it.

### Automatic rehash

When you change `Argon2` parameters, existing hashes keep working because each hash records its own parameters. If your `UserStore` implements `PasswordHashUpdater`, every successful login with an outdated hash re-hashes the password with the current parameters and saves the result. To find hashes that still need upgrading, call `NeedsRehash(hash, params)`.

The save is a **compare-and-swap**: `UpdatePasswordHash(ctx, username, oldHash, newHash)` replaces the hash only if it is still the one the login verified. If a password change lands while such a login is running, the upgrade is skipped. Otherwise it would write a fresh hash of the **old** password and undo the change. Custom stores must implement this check atomically. See [Storage](Storage.md#passwordhashupdater).

### Unknown users

If `LookupPasswordHash` returns `ErrUserNotFound`, `Authenticate` still runs a full Argon2 verification against a dummy hash made with the current parameters. Then it returns the same `ErrInvalidCredentials` as for a wrong password. Response time and error therefore do not reveal whether a username exists.

The dummy hash is computed once in `New` when a `UserStore` is configured, so `New` performs one extra Argon2 hash at startup. Verifying against it takes a hashing slot like any other login, so it respects `MaxConcurrentHashes`. The path behaves like a real login in other ways too: if the context is cancelled while waiting for a slot, unknown-user logins return the context error just as known users do.

One limit remains: users whose stored hash still uses older, different parameters take a different time to verify than the dummy, until their hash is upgraded.

## Tokens

- **ES256 only.** Tokens are signed with ECDSA P-256 / SHA-256. The parser accepts only `ES256`, which blocks `alg: none` and algorithm-confusion attacks.
- **Private keys never leave the process.** They are generated in memory, never written to disk or to any store, and die with the process. Only public keys go to the `KeyStore`. A leaked key database therefore cannot be used to forge tokens. Its integrity still matters, though: anyone who can **write** to the key table can insert their own public key and forge tokens with it. Restrict write access to it.
- **Key rotation** (default every 24h) limits how long a key is in use. A signing-time guard refuses to sign with a key past its window (if the rotation loop fell behind) when no fresh key can be stored, so every token is covered by its key's stored expiry. See [Tokens and Keys](Tokens-and-Keys.md#signing-time-guard).
- **Access and refresh tokens cannot be swapped.** The `typ` claim is checked on every verification.
- **Refresh-token reuse detection** revokes a session when a stolen refresh token is used after (or before) the real client uses it.
- **Revocation is final.** Stores track revoked families, so a refresh in flight at the moment of a logout, `RevokeAllSessions` or a theft detection cannot leave behind a working token. See [Tokens and Keys](Tokens-and-Keys.md#revocation-is-final).
- **Reuse grace period trade-off.** `RefreshReuseGrace` (default 30s) lets a spent refresh token be used again for a short time after its first use without revoking anything. This keeps users logged in when several tabs refresh at once or a response is lost. The cost: an attacker who replays a stolen token **within that window** gets a working session, and the theft is not detected. The window is fixed from the first use and does not slide. Keep it to seconds. Set it to 0 for strict detection if your clients never refresh concurrently. See [reuse detection](Tokens-and-Keys.md#reuse-detection).

### Issuer and audience

Set `Issuer` and `Audience` whenever more than one service or environment might see your tokens:

```go
auth.WithIssuer("https://auth.example.com"),
auth.WithAudience("https://api.example.com"),
```

With these set, tokens must carry a matching `iss` and an `aud` that includes one of the configured values. A token minted for staging, or for another service that shares a key store, is then rejected. Without them, any token signed by a known key is accepted.

## Recommendations

- **Serve everything over HTTPS.** Passwords and Bearer tokens are sent as-is.
- **Keep `AccessTokenTTL` short** (the default 15 minutes is reasonable). Access tokens cannot be revoked. Logout only stops refreshes.
- **Cookies:** if you use `WithAuthCookie`, set `HttpOnly` (blocks theft through XSS), `Secure`, and `SameSite=Lax` or `Strict`. Cookie authentication is exposed to CSRF. Use `SameSite`, CSRF tokens, or check `Origin` on requests that change state. Do not use cookies to authenticate cross-site requests.
- **Rate-limit logins yourself.** The library does not rate-limit or lock accounts. Limit attempts per account and per IP in front of your login handler. `MaxConcurrentHashes` only protects memory, not passwords.
- **Refresh tokens on clients:**
  - Browsers: an `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to the refresh/logout path. Never `localStorage`.
  - Mobile/desktop: the platform keystore (iOS Keychain, Android Keystore).
  - Always replace the stored refresh token with the new one from each refresh. If you run with `RefreshReuseGrace = 0`, also allow only one refresh in flight at a time. See [reuse detection](Tokens-and-Keys.md#reuse-detection).
- **Treat `ErrRefreshTokenReused` as a security signal.** Log it with the subject and alert on spikes.
- **End all sessions after a password change or account disable** with `RevokeAllSessions(ctx, subject)`, then issue a new pair for the current device with `IssueTokenPair`. Access tokens already issued stay valid until they expire. One gap remains: a login whose password check passed **before** the password change, but which creates its session **after** `RevokeAllSessions` completes, gets a new, valid session. The library cannot tie sessions to password versions. Always save the new password hash **first** and call `RevokeAllSessions` **afterwards**. In the reverse order, any login with the old password between the two calls would survive. In this order, a login survives only if its password check came before the change and its session creation came after the revocation. That requires the login's own short check-to-create step to span both calls. See [Tokens and Keys](Tokens-and-Keys.md#revoking-all-sessions).
- **External verifiers** must check the `at+jwt` header type (or `typ == "access"` in the payload). See [JWKS](Tokens-and-Keys.md#jwks).
- **Don't log tokens** or password inputs. Errors from this package never contain them.

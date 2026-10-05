# Error Handling

All errors the package returns are values declared in `errors.go`, and they are often **wrapped** with extra context (`fmt.Errorf("%w: ...")`, and in one case `errors.Join`). Always compare them with `errors.Is`, never `==`:

```go
if errors.Is(err, auth.ErrTokenExpired) { ... }
```

Any error that matches none of the sentinels below is an **internal failure**: a store error, a context cancellation, a `ClaimsProvider` error, and so on. Return 500 and log it.

## Errors returned to callers

| Error | Returned by | Meaning | Suggested HTTP status |
|---|---|---|---|
| `ErrInvalidCredentials` | `Authenticate`, `Login` | Wrong password **or** unknown user. The two cases cannot be told apart. | 401 |
| `ErrInvalidToken` | `VerifyAccessToken`, `ClaimsFromRequest`, `Refresh`, `Logout` | Malformed token, bad signature, unknown or expired signing key, wrong `iss`/`aud`, wrong `typ` (e.g. a refresh token used as an access token), missing required claims, or a refresh token that does not match its record. | 401 |
| `ErrTokenExpired` | `VerifyAccessToken`, `ClaimsFromRequest`, `Refresh` | The token is otherwise valid but past `exp` (allowing for `Leeway`). `Logout` accepts expired tokens. | 401 (clients should refresh, or log in again if the refresh token expired) |
| `ErrNoToken` | `ClaimsFromRequest`, middleware | No token in the configured header or cookie. | 401 |
| `ErrTokenRevoked` | `Refresh` | The refresh token is validly signed, but its record is gone (logged out, family revoked, or purged), or its family was revoked while this refresh was in flight. The store's `CreateRefreshToken` refuses the replacement, and the error is wrapped. | 401 |
| `ErrRefreshTokenReused` | `Refresh` | A spent refresh token was presented again after the `RefreshReuseGrace` window (measured from its first use), or at all when the grace is 0. The family has been revoked. Reuse inside the window is not an error: it gets a new pair. If revoking failed, the error is `errors.Join(ErrRefreshTokenReused, <store error>)`. | 401, and consider logging it as a security event |
| `ErrReservedClaim` | `IssueAccessToken`, `IssueTokenPair`, `Login`, `Refresh` | An extra claim (from the argument or the `ClaimsProvider`) used a reserved name. This is a programming error. | 500 |
| `ErrNotConfigured` | `Authenticate`/`Login` (no `UserStore`), `Refresh`/`Logout`/`RevokeAllSessions` (no `RefreshTokenStore`) | A store the operation needs was not passed to `New`. This is a programming error. | 500 |
| `ErrClosed` | `Login`, `IssueAccessToken`, `IssueTokenPair`, `Refresh` | `Close` has been called. Verification still works after close. | 503 during shutdown |
| `ErrInvalidHash` | `VerifyPassword`, `NeedsRehash`, `Authenticate`, `Login` | A stored password hash is not a valid Argon2id PHC string. This points to corrupt data. | 500 |

`ErrNoToken` is **not** returned by `VerifyAccessToken`. An empty string there gives `ErrInvalidToken`.

### Other errors you may see

- `ctx.Err()` (`context.Canceled` / `context.DeadlineExceeded`) from `HashPassword`, `Authenticate` and `Login` when the context ends while waiting for a hashing slot. This happens for unknown users too, because they are checked against a dummy hash in the same way.
- Errors from `New`: invalid configuration (all problems joined), a failure to store the first signing key (or the next key, with rotation on), or a failure to compute the dummy password hash.
- From `Login`, `Refresh`, `IssueAccessToken` and `IssueTokenPair`: a wrapped `KeyStore` error, if the current signing key is past its window and no fresh key can be stored (see [signing-time guard](Tokens-and-Keys.md#signing-time-guard)). Treat it as a 500.
- A `KeyStore.ListKeys` failure while verifying a token whose `kid` the instance does not know yet. Keys the instance already knows keep verifying while the store is down. This is an internal error (500), not `ErrInvalidToken`.
- Calling `IssueAccessToken`/`IssueTokenPair`/`RevokeAllSessions` with an empty subject returns a plain error, not a sentinel.

## Errors your stores must return

These sentinels are part of the store contracts. Return them, optionally wrapped, so the library can tell "not found" apart from a failure:

| Error | Returned by your | Library behavior |
|---|---|---|
| `ErrUserNotFound` | `UserStore.LookupPasswordHash` | Checks a dummy hash, then returns `ErrInvalidCredentials` |
| `ErrRefreshTokenNotFound` | `RefreshTokenStore.ConsumeRefreshToken` | `Refresh` returns `ErrTokenRevoked` |

If a store returns a different error for "not found", it is treated as an internal failure. `KeyStore` has no "not found" case: a `kid` missing from `ListKeys` makes verification fail with `ErrInvalidToken`. See [Storage](Storage.md).

## Middleware

`RequireAuthHandler` passes the error to the `UnauthorizedHandler`. The default handler maps `ErrNoToken`, `ErrInvalidToken` and `ErrTokenExpired` to 401 and everything else to 500. `AuthHandler` ignores client errors and logs internal ones. See [HTTP Middleware](HTTP-Middleware.md).

## Example mapping function

```go
func statusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrInvalidToken),
		errors.Is(err, auth.ErrTokenExpired),
		errors.Is(err, auth.ErrNoToken),
		errors.Is(err, auth.ErrTokenRevoked),
		errors.Is(err, auth.ErrRefreshTokenReused):
		return http.StatusUnauthorized
	case errors.Is(err, auth.ErrClosed):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
```

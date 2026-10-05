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
| `ErrTokenRevoked` | `Refresh` | The refresh token is validly signed, but its record is gone (logged out, family revoked, or purged). | 401 |
| `ErrRefreshTokenReused` | `Refresh` | A spent refresh token was presented again. The family has been revoked. If revoking failed, the error is `errors.Join(ErrRefreshTokenReused, <store error>)`. | 401, and consider logging it as a security event |
| `ErrReservedClaim` | `IssueAccessToken`, `IssueTokenPair`, `Login`, `Refresh` | An extra claim (from the argument or the `ClaimsProvider`) used a reserved name. This is a programming error. | 500 |
| `ErrNotConfigured` | `Authenticate`/`Login` (no `UserStore`), `Refresh`/`Logout` (no `RefreshTokenStore`) | A store the operation needs was not passed to `New`. This is a programming error. | 500 |
| `ErrClosed` | `Login`, `IssueAccessToken`, `IssueTokenPair`, `Refresh` | `Close` has been called. Verification still works after close. | 503 during shutdown |
| `ErrInvalidHash` | `VerifyPassword`, `NeedsRehash`, `Authenticate`, `Login` | A stored password hash is not a valid Argon2id PHC string. This points to corrupt data. | 500 |

`ErrNoToken` is **not** returned by `VerifyAccessToken`. An empty string there gives `ErrInvalidToken`.

### Other errors you may see

- `ctx.Err()` (`context.Canceled` / `context.DeadlineExceeded`) from `HashPassword`, `Authenticate` and `Login` when the context ends while waiting for a hashing slot.
- Errors from `New`: invalid configuration (all problems joined), or a failure to store the first signing key.
- Calling `IssueAccessToken`/`IssueTokenPair` with an empty subject returns a plain error, not a sentinel.

## Errors your stores must return

These sentinels are part of the store contracts. Return them, optionally wrapped, so the library can tell "not found" apart from a failure:

| Error | Returned by your | Library behavior |
|---|---|---|
| `ErrUserNotFound` | `UserStore.LookupPasswordHash` | Checks a dummy hash, then returns `ErrInvalidCredentials` |
| `ErrKeyNotFound` | `KeyStore.GetKey` | Verification fails with `ErrInvalidToken` |
| `ErrRefreshTokenNotFound` | `RefreshTokenStore.ConsumeRefreshToken` | `Refresh` returns `ErrTokenRevoked` |

If a store returns a different error for "not found", it is treated as an internal failure. See [Storage](Storage.md).

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

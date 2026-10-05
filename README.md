# auth

A pluggable authentication toolkit for Go services: Argon2id password
hashing, ES256 JWT access tokens, rotating refresh tokens, automatic
signing-key rotation, `net/http` middleware and a JWKS endpoint. You supply
storage through three small interfaces; the library handles the cryptography.

```bash
go get github.com/tpyle/auth/v2
```

Upgrading from v1? See [wiki/Migrating-from-v1.md](wiki/Migrating-from-v1.md).

## Features

- **Passwords**: Argon2id in PHC format (RFC 9106 defaults). Cost parameters
  are read from each stored hash, so you can raise them at any time, and
  outdated hashes are upgraded automatically on login. A concurrency limit
  bounds memory use, and unknown users take as long to reject as wrong passwords.
- **Tokens**: short-lived ES256 access tokens and refresh tokens that are
  rotated on every use, with reuse detection that revokes the session. A
  short grace period keeps concurrent refreshes (several browser tabs, a
  retried request) from logging users out. Access and refresh tokens can't be
  swapped for each other. `RevokeAllSessions` signs a user out everywhere,
  for example after a password change.
- **Keys**: signing keys rotate automatically and are published one rotation
  interval before they start signing. Private keys never leave the process;
  only public keys are stored, so any number of instances can verify each
  other's tokens, and other services can use the JWKS endpoint. Tokens with
  made-up key IDs can't flood your key store.
- **HTTP**: optional and required authentication middleware, `Bearer` header
  and/or cookie support, RFC 6750 error responses.
- **Small dependency footprint**: `golang-jwt/jwt`, `google/uuid` and
  `golang.org/x/crypto`.

## Quick start

```go
ctx := context.Background()
users := auth.NewMemoryUserStore() // implement auth.UserStore on your database

a, err := auth.New(ctx,
	auth.WithUserStore(users),
	auth.WithKeyStore(myKeyStore),          // omit for single-instance, in-memory keys
	auth.WithRefreshTokenStore(myRefreshStore), // omit to disable refresh tokens
	auth.WithClaimsProvider(func(ctx context.Context, user string) (map[string]any, error) {
		return map[string]any{"role": lookupRole(user)}, nil
	}),
)
if err != nil {
	log.Fatal(err)
}
defer a.Close()

// Registration
hash, _ := a.HashPassword(ctx, []byte(password))
users.SetPasswordHash("alice", hash)

// Login -> access + refresh token
pair, err := a.Login(ctx, "alice", []byte(password))
if errors.Is(err, auth.ErrInvalidCredentials) { /* 401 */ }

// Protect routes
mux := http.NewServeMux()
mux.Handle("GET /.well-known/jwks.json", a.JWKSHandler())
mux.Handle("GET /me", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	fmt.Fprintln(w, "hello", claims.Subject)
})))

// Later
next, err := a.Refresh(ctx, pair.RefreshToken)
err = a.Logout(ctx, next.RefreshToken)
```

## Examples

- [`examples/basic`](examples/basic): the whole lifecycle in one program (`go run ./examples/basic`).
- [`examples/server`](examples/server): a JSON API with login, refresh, logout and protected routes.
- [`examples/sqlstore`](examples/sqlstore): PostgreSQL implementations of every store using `database/sql`.

## Documentation

- [Getting Started](wiki/Getting-Started.md)
- [Configuration](wiki/Configuration.md) (including Viper)
- [Storage](wiki/Storage.md): store contracts and schemas
- [Tokens and Keys](wiki/Tokens-and-Keys.md)
- [HTTP Middleware](wiki/HTTP-Middleware.md)
- [Error Handling](wiki/Error-Handling.md)
- [Security](wiki/Security.md)

API reference: [pkg.go.dev/github.com/tpyle/auth/v2](https://pkg.go.dev/github.com/tpyle/auth/v2)

## License

MIT

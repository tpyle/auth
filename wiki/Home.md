# auth v2

`github.com/tpyle/auth/v2` is a password and token authentication toolkit for Go services. It handles password hashing, JWT issuance and verification, refresh-token rotation, and signing-key rotation, and leaves persistence to you through three small interfaces.

```go
import "github.com/tpyle/auth/v2"
```

## Features

- **Argon2id password hashing** in the standard PHC string format (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`). Cost parameters live inside each hash, so changing them never locks anyone out. Outdated hashes are upgraded automatically on login.
- **Login timing equalization.** Unknown users are checked against a dummy hash, so they take about as long to reject as a wrong password.
- **Bounded hashing memory.** A semaphore caps concurrent Argon2 computations.
- **ES256 (P-256 ECDSA) JWTs** for access tokens and refresh tokens. Each kind is rejected where the other is expected.
- **Refresh-token rotation with reuse detection.** Each refresh token works once. Presenting a spent token revokes the whole session ("family").
- **Automatic signing-key rotation.** Private keys stay in process memory. Only public keys are persisted, so several instances can verify each other's tokens through a shared `KeyStore`.
- **Optional `iss`/`aud` claims** with enforcement on verification.
- **net/http middleware** for optional and required authentication, using a `Bearer` header or a cookie.
- **JWKS endpoint** so other services can verify tokens with any standard JWT library.
- **In-memory stores** for tests, examples and single-instance deployments.
- Dependencies: `golang-jwt/jwt/v5`, `google/uuid`, `golang.org/x/crypto`. No dependency on any configuration library.

## Pages

| Page | Contents |
|---|---|
| [Getting Started](Getting-Started.md) | Install, create an `Authorizer`, hash passwords, log in, verify, refresh, log out |
| [Configuration](Configuration.md) | Every `Config` field and option, defaults, loading config with Viper |
| [Storage](Storage.md) | The store interfaces, PostgreSQL schemas, in-memory stores |
| [Tokens and Keys](Tokens-and-Keys.md) | Token layout, refresh rotation, reuse detection, key rotation, JWKS |
| [HTTP Middleware](HTTP-Middleware.md) | `AuthHandler`, `RequireAuthHandler`, token extraction, a full server example |
| [Error Handling](Error-Handling.md) | Every sentinel error and how to map it to HTTP statuses |
| [Security](Security.md) | Hashing parameters, cryptographic choices, deployment advice |
| [Migrating from v1](Migrating-from-v1.md) | API mapping and behavior changes from v1 |

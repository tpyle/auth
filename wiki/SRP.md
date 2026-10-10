# SRP

`github.com/tpyle/auth/srp` adds password login with the Secure Remote Password protocol (SRP-6a). The password never reaches the server, not even at registration. A successful SRP login issues the same access and refresh tokens as a password login, through your existing `auth.Authorizer`.

```bash
go get github.com/tpyle/auth/srp
```

It's a **separate Go module**, like [`passkey`](Passkeys.md). It requires Go 1.27 or later and uses the standard library's `uuid.UUID` for session IDs. Apart from the core module, its only dependency is `golang.org/x/crypto` (for Argon2id).

## When to use it

With an ordinary password login (`Authorizer.Login`), the client sends the password over TLS and the server hashes it. SRP changes three things:

- **The server never sees the password.** It stores a *verifier* computed on the client. A server-side bug that logs request bodies, or a TLS-terminating proxy, can't leak passwords.
- **The server proves itself too.** At the end of a login the server sends a proof that it holds the user's verifier. A client whose code the server doesn't control can use it to detect a server that merely accepts any password.
- **Offline guessing costs as much as with Argon2id.** A stolen verifier can be used to guess passwords offline, just like a stolen hash. Here the password is put through Argon2id before it becomes the SRP private key, so each guess costs as much as against an Argon2id password hash. That's equal to a password hash, not better. (Textbook SRP uses a single SHA hash, which is much cheaper to attack.)

The costs: the client must run SRP and Argon2id (in JavaScript or WebAssembly for browsers), each login takes two round trips, and the client pays the Argon2id cost on every login. This module provides only a Go client.

SRP doesn't replace TLS. Run it over HTTPS so tokens and the rest of the application are protected too.

Good fits are clients the server doesn't deliver: native mobile and desktop apps, command-line tools, and end-to-end encrypted products where the server must never be trusted with anything that unlocks user data.

## When not to use it

**Browser apps.** Both guarantees above depend on the client code being independent of the server. In a browser the server delivers the JavaScript that handles the password:

- A compromised server can serve JavaScript that sends the password elsewhere, so "the server never sees the password" holds only against accidental leaks, such as logged request bodies. Careful logging and TLS handling prevent those for ordinary password logins too.
- A phishing site serves its own JavaScript, which simply skips the server-proof check. The user can't tell the difference. SRP does **not** protect browser users from phishing.

For browser apps, use [passkeys](Passkeys.md), which the browser binds to your origin and which do resist phishing, with `Authorizer.Login` over HTTPS as the password fallback.

**Pre-computation.** `BeginLogin` sends a user's salt to anyone who asks for it, as SRP requires. An attacker can collect it and prepare guesses for that account before stealing the verifier, so a breach can be exploited faster. An Argon2id password hash keeps its salt secret. [OPAQUE](https://www.rfc-editor.org/rfc/rfc9807) (RFC 9807), a newer protocol of the same kind, avoids this and is worth considering over SRP for new designs.

**Interoperability.** Deriving `x` with Argon2id instead of SHA is a deliberate departure from RFC 5054. Off-the-shelf SRP clients won't work; clients must follow the [specification](#protocol-specification) below.

## Setup

```go
a, _ := auth.New(ctx, auth.WithRefreshTokenStore(refresh), auth.WithClaimsProvider(claims))

server, err := srp.New(
	srp.WithUserStore(users),            // implements srp.UserStore
	srp.WithSessionStore(sessions),      // shared store for multi-instance deployments
	srp.WithDecoyKey(decoyKey),          // 32+ random bytes, the same on every instance
	srp.WithTokenIssuer(a),              // *auth.Authorizer
	srp.WithClaimsProvider(claims),      // same provider, same claims as password logins
)
```

### Config

| Field | Default | Meaning |
|---|---|---|
| `Group` | `3072` | The RFC 5054 group new verifiers use: `2048`, `3072` or `4096`. 3072 bits gives about 128-bit security. Existing verifiers keep working in their own group. |
| `KDF` | `m=65536, t=3, p=4` | Argon2id cost of new verifiers (64 MiB, 3 passes, 4 lanes). **Clients pay it on every login**, so it must suit the slowest device users log in from. |
| `KDFLimits` | `m=262144, t=16, p=255` | The largest cost accepted in stored verifiers. Go clients refuse challenges over `srp.DefaultKDFLimits()` by default. |
| `SaltLength` | `16` | Bytes of salt for new verifiers, 16 to 64. |
| `SessionTTL` | `2m` | Time allowed between `BeginLogin` and `FinishLogin`, including the client's Argon2id. 10s to 10m. |

`Config` has `mapstructure` tags (`group`, `kdf`, `kdf_limits`, `salt_length`, `session_ttl`), so it can be loaded with Viper like the core [Configuration](Configuration.md).

The decoy key isn't part of `Config`, because it's a secret. See [Unknown users](#unknown-users).

## Registration

The client derives the verifier and sends only that:

```go
// Server: POST /register/begin
reg := server.NewRegistration() // {group, kdf, salt}, as JSON

// Client
v, err := srp.Client{}.NewVerifier(password, reg)
send(v.String())

// Server: POST /register/finish
v, err := srp.ParseVerifier(body.Verifier)
if err == nil {
	err = server.CheckVerifier(v) // must use the configured group, cost and salt length
}
store(username, v.String())
```

`CheckVerifier` can't tell how strong the password is, or whether the client used one at all, because the server never sees it. Enforce password rules on the client.

Use the same flow when the user changes their password, behind `RequireAuthHandler` and ideally after a fresh login. Follow it with `Authorizer.RevokeAllSessions`.

If the client can't run SRP during sign-up (for example, when importing accounts), `server.NewVerifier(password)` creates the verifier on the server. The server then sees the password once.

## Login

```go
// 1. Client -> server: {"username": "alice"}
ch, err := server.BeginLogin(ctx, username) // send ch as JSON

// 2. Client: derive x with Argon2id, compute A and the proof M1
login, err := srp.Client{}.Login(username, password, ch)
send(login.Response()) // {"sessionId", "clientPublic", "clientProof"}

// 3. Server: check M1 and issue tokens
res, err := server.FinishLogin(ctx, resp) // res.Tokens, res.ServerProof

// 4. Client: check M2 before trusting the tokens
err = login.VerifyServer(res.ServerProof)
```

`server.Authenticate` does step 3 without issuing tokens, for example to re-confirm a signed-in user before a sensitive action. Check that `res.Subject` is the current user.

Each session can be finished **once**, successfully or not. Every `BeginLogin` therefore allows exactly one password guess. Rate-limit both endpoints per username and per IP, as you would a password login.

`Result.VerifierOutdated` is set when the user's verifier uses an older group, cost or salt length than the current configuration. The server can't upgrade it (it doesn't know the password), but the client just proved it does. Tell the client to repeat the registration flow while it still has the password.

The client must send exactly the username string it began with, because the username is part of the proof. Normalize usernames and passwords (for example, to Unicode NFC) the same way at registration and login.

### Unknown users

`BeginLogin` doesn't return an error for an unknown username. It returns a decoy challenge that looks like a real one, and the login then fails as if the password were wrong. This is the approach RFC 5054 §2.5.1.3 suggests.

A decoy's salt is derived from the username with the decoy key, so it stays the same across calls, as a real user's salt does. **Set `WithDecoyKey`** to 32 or more random bytes shared by every instance. Without it, a random key is generated at startup. Decoy salts then change on every restart and differ between instances, and anyone who asks about the same username twice can tell it doesn't exist.

The remaining signals are ones the library can't hide:

- A real user whose verifier uses an older group or cost gets a challenge with those parameters, while decoys always use the current ones.
- Your user store may take longer to find a row than to miss one.

## Storage

### UserStore

```go
type UserStore interface {
	LookupVerifier(ctx context.Context, username string) (string, error) // auth.ErrUserNotFound if absent
}
```

Store `Verifier.String()` in a text column. It's PHC-like and holds everything needed to log in:

```
$srp6a-sha256-argon2id$g=3072,m=65536,t=3,p=4$<salt>$<verifier>
```

Salt and verifier are unpadded standard base64. Treat verifiers as you would password hashes: they allow offline guessing.

```sql
ALTER TABLE users ADD COLUMN srp_verifier TEXT;
```

### SessionStore

```go
type SessionStore interface {
	SaveSession(ctx context.Context, id uuid.UUID, data []byte, expiresAt time.Time) error
	ConsumeSession(ctx context.Context, id uuid.UUID, now time.Time) ([]byte, error) // srp.ErrSessionNotFound
}
```

`ConsumeSession` must delete and return in one atomic step. The default `MemorySessionStore` works only when a login finishes on the instance that began it.

Unlike passkey ceremonies, **session data is secret**. It contains the server's private value for the login and the user's verifier. Anyone who reads it before the login finishes can impersonate the server to that client, and can attempt offline guessing. Don't put it anywhere less protected than the verifiers.

```sql
CREATE TABLE srp_sessions (
	id         UUID PRIMARY KEY,
	data       BYTEA NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX ON srp_sessions (expires_at);

-- ConsumeSession
DELETE FROM srp_sessions WHERE id = $1 AND expires_at > $2 RETURNING data;
-- Periodic cleanup
DELETE FROM srp_sessions WHERE expires_at < now();
```

## Errors

| Error | Meaning | Suggested status |
|---|---|---|
| `auth.ErrInvalidCredentials` | Wrong password, unknown user, or malformed `clientPublic`/`clientProof`. The reason is logged at debug level. | 401 |
| `srp.ErrInvalidSession` | Session unknown, expired or already used. The client should start over. | 400 |
| `srp.ErrInvalidVerifier` | A verifier from the client is malformed or doesn't match the policy. Also wrapped for a stored verifier that's malformed or over `KDFLimits` (a server problem). | 400 at registration, 500 at login |
| `auth.ErrNotConfigured` | `FinishLogin` without `WithTokenIssuer`. | 500 |
| `srp.ErrInvalidChallenge` | Client side: the challenge is malformed or asks for too much Argon2id work. | — |
| `srp.ErrInvalidServerProof` | Client side: the server couldn't prove it holds the verifier. Discard its response. | — |

## Protocol specification

This section is for implementing a client in another language, typically JavaScript in the browser. The protocol is SRP-6a as in [RFC 5054](https://www.rfc-editor.org/rfc/rfc5054) §2.5–2.6, with SHA-256 and Argon2id.

**Notation.** `H` is SHA-256. `|` is byte concatenation. Integers are unsigned big-endian. `PAD(x)` left-pads `x` with zero bytes to the byte length of `N` (256, 384 or 512 bytes). Exponentiation is modulo `N`.

**Groups.** `N` and `g` are the 2048-, 3072- and 4096-bit groups of RFC 5054 Appendix A (`g` = 2, 5 and 5). The `group` field gives the size in bits.

**Derived constants.**

```
k = H(N | PAD(g))
```

**Private key.** The Argon2id output is read as a big-endian integer:

```
x = Argon2id(password, salt, t, m, p, length = 32), version 0x13, no secret, no associated data
```

**Verifier.**

```
v = g^x mod N        (encoded as PAD(v))
```

**Login.** The client receives `salt`, `kdf` (`{"m","t","p"}`) and `serverPublic` (`B`). Byte fields are standard base64.

1. Check `group` is supported and `kdf` is within your limits. Reject `B` unless `0 < B < N`.
2. Pick a random 32-byte `a` and compute `A = g^a mod N`.
3. `u = H(PAD(A) | PAD(B))`. If `u = 0`, pick a new `a`.
4. `S = (B - k * g^x) ^ (a + u * x) mod N`. Reduce `B - k * g^x` into `[0, N)` first. The exponent isn't reduced.
5. `K = H(PAD(S))`.
6. `M1 = H(H(PAD(N)) XOR H(PAD(g)) | H(username) | salt | PAD(A) | PAD(B) | K)`, where `username` is UTF-8.
7. Send `{"sessionId", "clientPublic": PAD(A), "clientProof": M1}`.
8. Expect `M2 = H(PAD(A) | M1 | K)` from the server. Compare it in constant time, and distrust the response if it differs.

The server checks `0 < A < N` and `u ≠ 0`, computes `S = (A * v^u)^b mod N`, and compares `M1` in constant time.

**Browser notes.** Argon2id is available in WebAssembly from libraries such as [hash-wasm](https://github.com/Daninet/hash-wasm) (MIT). JavaScript's `BigInt` supports the arithmetic, using a square-and-multiply `modPow`. SHA-256 is in `crypto.subtle.digest`, and random bytes in `crypto.getRandomValues`. Test your client against the Go server, or against `srp.Client` with fixed inputs.

The Go package checks its arithmetic against the RFC 5054 Appendix B test vectors (with SHA-1 and the RFC's `x`, which share every formula but `x`).

## Security notes

- **Timing.** The arithmetic uses Go's `math/big`, which isn't constant-time. On the server the secret exponent is fresh for every login, and the verifier is only ever the base of an exponentiation. That makes remote timing attacks impractical. Don't run the server where an attacker can time it precisely, such as on CPU cores shared with untrusted code.
- **Rate limiting.** Each `BeginLogin` stores a session, and each finish is one guess. Rate-limit both.
- **Weak passwords.** The server can't check password strength. Do it on the client.
- **The client must verify M2.** Otherwise it gets none of SRP's protection against impostor servers.

## Examples

- [`srp/examples/server`](../srp/examples/server): JSON API with registration, login and a protected route.
- [`srp/examples/client`](../srp/examples/client): a Go command-line client for it.

```bash
cd srp
go run ./examples/server &
go run ./examples/client -register -user alice -password 'correct horse'
go run ./examples/client -user alice -password 'correct horse'
```

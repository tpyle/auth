// Package srp adds password login with the Secure Remote Password protocol
// (SRP-6a) to services that use [github.com/tpyle/auth/v2].
//
// With SRP the password never reaches the server, not even at registration.
// The client derives a [Verifier] from the password and the server stores
// that instead of a password hash. At login the two sides run a key
// exchange that succeeds only if the client knows the password, and the
// server proves in return that it holds the verifier.
//
// These guarantees hold only when the client code doesn't come from the
// server it authenticates to, as with native apps and command-line tools.
// In a browser the server delivers the JavaScript that handles the
// password, and a phishing site serves its own, so SRP adds little over
// [github.com/tpyle/auth/v2.Authorizer.Login] over HTTPS. Prefer passkeys
// for phishing resistance.
//
// # Flow
//
// Registration: the client gets the group, cost and salt from
// [Server.NewRegistration], computes a verifier with [Client.NewVerifier]
// (or its JavaScript equivalent) and sends it to the server, which checks
// it with [Server.CheckVerifier] and stores [Verifier.String].
//
// Login takes two round trips:
//
//  1. The client sends its username. [Server.BeginLogin] returns a
//     [Challenge] with the salt, cost and the server's public value B.
//  2. The client computes its public value A and proof M1 with
//     [Client.Login] and sends them as a [LoginResponse].
//     [Server.FinishLogin] checks the proof and issues an access and refresh
//     token pair through the [github.com/tpyle/auth/v2.Authorizer], exactly
//     as a password login does. [Server.Authenticate] checks without issuing
//     tokens. Both return the server's proof M2, which the client checks with
//     [ClientLogin.VerifyServer].
//
// Login state is kept between the steps in a [SessionStore], and each
// session can be finished once, so every BeginLogin allows one password
// guess. Unknown usernames get decoy challenges, so the protocol does not
// reveal which accounts exist (see [WithDecoyKey]).
//
// # Protocol
//
// The protocol is SRP-6a as specified in RFC 5054, using SHA-256 and the
// 2048-, 3072- and 4096-bit groups of RFC 5054 Appendix A, with one change:
// the private key x is Argon2id(password, salt) rather than a single hash
// of the password, so a stolen verifier is as costly to attack as an
// Argon2id password hash. The exact computations are described in the
// project wiki for implementers of other clients.
//
// The arithmetic uses math/big, which is not constant-time, so the time it
// takes can depend on secret values. On the server the secret exponent is
// fresh for every login and the verifier is only ever the base of an
// exponentiation, which makes timing attacks impractical over a network.
// Do not run the server where an attacker can measure its timing precisely,
// such as on CPU cores shared with untrusted code.
//
// SRP is not a substitute for TLS: run it over HTTPS so tokens and the
// rest of the application are protected too.
package srp

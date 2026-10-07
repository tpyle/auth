// Package auth is a pluggable authentication toolkit for Go services.
//
// It provides:
//
//   - Argon2id password hashing in the standard PHC string format, with
//     support for upgrading hashes when parameters change (see [HashPassword],
//     [VerifyPassword] and [NeedsRehash]).
//   - ES256-signed JWT access tokens and rotating refresh tokens with reuse
//     detection.
//   - Automatic signing-key rotation. Private keys never leave the process;
//     only public keys are persisted through a [KeyStore], so any number of
//     instances can verify each other's tokens.
//   - net/http middleware and a JWKS endpoint.
//
// Persistence is supplied by the caller through small interfaces
// ([UserStore], [KeyStore], [RefreshTokenStore]). In-memory implementations
// are provided for tests and single-instance deployments. A refresh-token
// store that also implements [RefreshTokenPurger] has its expired records
// deleted in the background (see [Config.RefreshPurgeInterval]).
//
// An [Authorizer] is created with [New] and must be released with
// [Authorizer.Close], which stops background key rotation and purging.
package auth

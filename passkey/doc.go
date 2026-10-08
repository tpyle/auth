// Package passkey adds passwordless login with passkeys and other FIDO2
// security keys (W3C WebAuthn) to services that use
// [github.com/tpyle/auth/v2].
//
// A WebAuthn exchange is a two-step "ceremony". The server begins it by
// creating a random challenge, the browser asks the authenticator (a phone,
// laptop, password manager or USB key) to sign it, and the server finishes it
// by verifying the signed response:
//
//   - Registration ([Passkeys.BeginRegistration], [Passkeys.FinishRegistration])
//     adds a credential to a user who is already signed in, for example with a
//     password or a token issued at sign-up.
//   - Login ([Passkeys.BeginLogin], [Passkeys.FinishLogin]) verifies an
//     assertion and issues an access and refresh token pair through the
//     [github.com/tpyle/auth/v2.Authorizer], exactly as a password login does.
//     [Passkeys.Authenticate] verifies without issuing tokens, for example to
//     confirm a sensitive action.
//
// The Begin methods return JSON options for the browser's
// navigator.credentials.create or navigator.credentials.get (pass the
// "publicKey" member to PublicKeyCredential.parseCreationOptionsFromJSON or
// parseRequestOptionsFromJSON). The Finish methods take the JSON-serialized
// PublicKeyCredential the browser returns (credential.toJSON()).
//
// # Relying party ID and origins
//
// [Config.RPID] is the domain credentials are scoped to, such as
// "example.com"; a credential registered for it works on that domain and its
// subdomains. [Config.RPOrigins] lists the exact origins (scheme, host and
// port) pages may run the ceremony from, such as "https://login.example.com".
// Browsers allow WebAuthn only in secure contexts: HTTPS, or http://localhost
// for development.
//
// # State
//
// Persistence is supplied through three interfaces: a [UserStore] that maps
// users to their WebAuthn user handles, a [CredentialStore] holding public
// keys, and a [CeremonyStore] holding challenges between the Begin and Finish
// steps. Challenges are kept server-side and are single-use, so a captured
// response cannot be replayed. In-memory implementations are provided for
// tests and examples.
//
// Attestation is not requested or verified: the package checks that a
// response comes from the credential that was registered, not which make of
// authenticator created it.
package passkey

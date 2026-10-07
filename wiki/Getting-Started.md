# Getting Started

## Install

```sh
go get github.com/tpyle/auth/v2
```

The package name is `auth`:

```go
import "github.com/tpyle/auth/v2"
```

## Create an Authorizer

An `Authorizer` does all the work. Create it with `auth.New` and stop it with `Close`. `New` checks the configuration, generates the first signing key (and the next one, which is published ahead of use), stores their public halves, and starts key rotation in the background. With a `UserStore` configured, it also computes one Argon2 hash up front: the dummy hash used to equalize timing for unknown users. Only the setup work in `New` respects `ctx`. Rotation keeps running until you call `Close`.

```go
ctx := context.Background()

users := auth.NewMemoryUserStore() // replace with your own UserStore

a, err := auth.New(ctx,
	auth.WithUserStore(users),
	auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
)
if err != nil {
	log.Fatal(err)
}
defer a.Close()
```

Every option is optional. Without a `UserStore`, `Authenticate` and `Login` fail with `ErrNotConfigured`. Without a `RefreshTokenStore`, no refresh tokens are issued. Without a `KeyStore`, the `Authorizer` uses a private in-memory store, so only the same process can verify its tokens, and they stop working after a restart. See [Storage](Storage.md) before you deploy more than one instance.

After `Close`, existing tokens still verify, but new ones are refused with `ErrClosed`.

## Hash passwords

Hash a password when a user signs up or changes it, and save the result in your user table:

```go
hash, err := a.HashPassword(ctx, []byte(password))
if err != nil {
	return err
}
// Store hash (a PHC string, about 100 characters) with the user.
users.SetPasswordHash("alice", hash)
```

`Authorizer.HashPassword` uses the configured Argon2 parameters. It waits for a free slot if `MaxConcurrentHashes` hashes are already running. If `ctx` is cancelled while it waits, it returns `ctx.Err()`.

The package-level functions work without an `Authorizer`. They are useful in scripts and migrations:

```go
hash, err := auth.HashPassword([]byte("correct horse"), auth.DefaultArgon2Params())
ok, err := auth.VerifyPassword([]byte("correct horse"), hash)
stale, err := auth.NeedsRehash(hash, auth.DefaultArgon2Params())
```

These functions ignore `MaxConcurrentHashes`.

## Log in

`Login` checks the username and password against the `UserStore`. On success, it returns a `*TokenPair`:

```go
pair, err := a.Login(ctx, "alice", []byte("s3cret"))
switch {
case errors.Is(err, auth.ErrInvalidCredentials):
	// wrong username or password: respond 401
case err != nil:
	// store failure etc.: respond 500
}
fmt.Println(pair.AccessToken, pair.AccessTokenExpiresAt)
fmt.Println(pair.RefreshToken, pair.RefreshTokenExpiresAt) // empty without a RefreshTokenStore
```

The token subject (`sub`) is the username passed to `Login`. To add claims such as roles, configure a `ClaimsProvider`. It runs on every `Login` and `Refresh`:

```go
auth.WithClaimsProvider(func(ctx context.Context, subject string) (map[string]any, error) {
	return map[string]any{"role": "admin"}, nil
})
```

To check credentials without issuing tokens, call `Authenticate(ctx, username, password)`. It returns nil on success.

If you authenticate users some other way (SSO, magic links), issue tokens directly. These calls check no credentials:

```go
access, err := a.IssueAccessToken("alice", map[string]any{"role": "admin"})
pair, err := a.IssueTokenPair(ctx, "alice", nil)
```

## Verify access tokens

```go
claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
switch {
case errors.Is(err, auth.ErrTokenExpired), errors.Is(err, auth.ErrInvalidToken):
	// client error: respond 401
case err != nil:
	// internal error (e.g. KeyStore unreachable): respond 500
}
role, _ := claims.GetString("role")
fmt.Println(claims.Subject, role, claims.ExpiresAt)
```

In HTTP servers, middleware usually does this step for you. See [HTTP Middleware](HTTP-Middleware.md).

## Refresh

Trade a refresh token for a new pair. The old refresh token is spent once it is used:

```go
newPair, err := a.Refresh(ctx, pair.RefreshToken)
switch {
case errors.Is(err, auth.ErrRefreshTokenReused):
	// token was reused after the grace window: the whole session has been revoked
case errors.Is(err, auth.ErrTokenRevoked):
	// logged out
case errors.Is(err, auth.ErrTokenExpired), errors.Is(err, auth.ErrInvalidToken):
	// user must log in again
case err != nil:
	// internal error
}
```

Clients must always save the new refresh token. If the same refresh token is used again within `RefreshReuseGrace` (default 30s) of its first use, for example by two tabs refreshing at once or by a retry after a lost response, the second use also gets a new pair. A reuse after that window revokes the session. See [Tokens and Keys](Tokens-and-Keys.md#reuse-detection).

## Log out

```go
if err := a.Logout(ctx, pair.RefreshToken); err != nil {
	// ErrInvalidToken for a bad token; other errors are internal
}
```

`Logout` revokes the session that the refresh token belongs to. Pass the client's most recent refresh token. Expired refresh tokens are accepted at least until `exp` + `Leeway` (see [Logout](Tokens-and-Keys.md#logout)), and logging out twice is not an error. Access tokens already issued stay valid until they expire, so keep `AccessTokenTTL` short.

To end **every** session of a user, for example after a password change, call `RevokeAllSessions`. To keep the current device signed in, issue it a new pair:

```go
if err := a.RevokeAllSessions(ctx, "alice"); err != nil {
	return err
}
pair, err := a.IssueTokenPair(ctx, "alice", nil)
```

## Complete program

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/tpyle/auth/v2"
)

func main() {
	ctx := context.Background()
	users := auth.NewMemoryUserStore()

	a, err := auth.New(ctx,
		auth.WithUserStore(users),
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	hash, err := a.HashPassword(ctx, []byte("s3cret"))
	if err != nil {
		log.Fatal(err)
	}
	users.SetPasswordHash("alice", hash)

	pair, err := a.Login(ctx, "alice", []byte("s3cret"))
	if err != nil {
		log.Fatal(err)
	}

	claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("logged in as", claims.Subject)

	pair, err = a.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}

	if err := a.Logout(ctx, pair.RefreshToken); err != nil {
		log.Fatal(err)
	}
	_, err = a.Refresh(ctx, pair.RefreshToken)
	fmt.Println(errors.Is(err, auth.ErrTokenRevoked)) // true
}
```

Next: [Configuration](Configuration.md), [Storage](Storage.md).

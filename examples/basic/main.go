// Command basic walks through hashing a password, logging in, verifying an
// access token, refreshing and logging out, using the in-memory stores.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/tpyle/auth/v2"
)

func main() {
	ctx := context.Background()
	users := auth.NewMemoryUserStore()

	a, err := auth.New(ctx,
		auth.WithUserStore(users),
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithAccessTokenTTL(10*time.Minute),
		auth.WithIssuer("example"),
		auth.WithClaimsProvider(func(ctx context.Context, subject string) (map[string]any, error) {
			// Look up roles, tenant, etc. Called on login and on every refresh.
			return map[string]any{"role": "admin"}, nil
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	// Registration: hash the password and store it.
	hash, err := a.HashPassword(ctx, []byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	users.SetPasswordHash("alice", hash)
	fmt.Println("stored hash:", hash)

	// Login.
	if _, err := a.Login(ctx, "alice", []byte("wrong")); errors.Is(err, auth.ErrInvalidCredentials) {
		fmt.Println("wrong password rejected")
	}
	pair, err := a.Login(ctx, "alice", []byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("access token expires at", pair.AccessTokenExpiresAt.Format(time.RFC3339))

	// Verify the access token, as an API would on each request.
	claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	role, _ := claims.GetString("role")
	fmt.Printf("verified: subject=%s role=%s issuer=%s\n", claims.Subject, role, claims.Issuer)

	// A refresh token is not accepted as an access token.
	if _, err := a.VerifyAccessToken(ctx, pair.RefreshToken); errors.Is(err, auth.ErrInvalidToken) {
		fmt.Println("refresh token rejected as access token")
	}

	// Refresh: the old refresh token is consumed and a new pair is issued.
	next, err := a.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("refreshed")

	// Logout revokes the session; its refresh tokens stop working.
	if err := a.Logout(ctx, next.RefreshToken); err != nil {
		log.Fatal(err)
	}
	if _, err := a.Refresh(ctx, next.RefreshToken); errors.Is(err, auth.ErrTokenRevoked) {
		fmt.Println("logged out")
	}
}

package auth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/tpyle/auth/v2"
)

func ExampleHashPassword() {
	hash, err := auth.HashPassword([]byte("correct horse"), auth.DefaultArgon2Params())
	if err != nil {
		log.Fatal(err)
	}
	ok, _ := auth.VerifyPassword([]byte("correct horse"), hash)
	fmt.Println(ok)
	// Output: true
}

func ExampleAuthorizer_Login() {
	ctx := context.Background()
	users := auth.NewMemoryUserStore()

	a, err := auth.New(ctx,
		auth.WithUserStore(users),
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithClaimsProvider(func(ctx context.Context, subject string) (map[string]any, error) {
			return map[string]any{"role": "admin"}, nil
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing authorizer: %v", err)
		}
	}()

	hash, _ := a.HashPassword(ctx, []byte("s3cret"))
	users.SetPasswordHash("alice", hash)

	if _, err := a.Login(ctx, "alice", []byte("wrong")); errors.Is(err, auth.ErrInvalidCredentials) {
		fmt.Println("rejected wrong password")
	}

	pair, err := a.Login(ctx, "alice", []byte("s3cret"))
	if err != nil {
		log.Fatal(err)
	}
	claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	role, _ := claims.GetString("role")
	fmt.Println(claims.Subject, role)

	// Exchange the refresh token for a new pair, then log out, which ends
	// the session for every token descended from this login.
	next, err := a.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}
	if err := a.Logout(ctx, next.RefreshToken); err != nil {
		log.Fatal(err)
	}
	_, err = a.Refresh(ctx, next.RefreshToken)
	fmt.Println(errors.Is(err, auth.ErrTokenRevoked))
	// Output:
	// rejected wrong password
	// alice admin
	// true
}

func ExampleAuthorizer_RequireAuthHandler() {
	a, err := auth.New(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing authorizer: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("GET /.well-known/jwks.json", a.JWKSHandler())
	mux.Handle("GET /me", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, _ := auth.SubjectFromContext(r.Context())
		_, _ = fmt.Fprintf(w, "hello, %s\n", sub)
	})))
	_ = mux // pass to http.ListenAndServe
}

// With RefreshPurgeInterval set to 0, expired refresh tokens are only purged
// when PurgeExpiredRefreshTokens is called, for example from a scheduled job.
func ExampleAuthorizer_PurgeExpiredRefreshTokens() {
	ctx := context.Background()
	a, err := auth.New(ctx,
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithRefreshPurgeInterval(0),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing authorizer: %v", err)
		}
	}()

	n, err := a.PurgeExpiredRefreshTokens(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("purged:", n)
	// Output: purged: 0
}

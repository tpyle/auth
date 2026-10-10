package srp_test

import (
	"context"
	"fmt"
	"log"

	"github.com/tpyle/auth/srp"
	"github.com/tpyle/auth/v2"
)

// Registration and login, with the client and server in one program. In a
// real application each arrow is an HTTP request, and the values are sent
// as JSON.
func Example() {
	ctx := context.Background()
	a, err := auth.New(ctx, auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	users := srp.NewMemoryUserStore() // implement srp.UserStore on your user table
	server, err := srp.New(
		srp.WithUserStore(users),
		srp.WithTokenIssuer(a),
		// Low cost so the example runs quickly; omit to use the defaults.
		srp.WithKDFParams(srp.KDFParams{MemoryKiB: 1024, Iterations: 1, Parallelism: 1}),
	)
	if err != nil {
		log.Fatal(err)
	}
	var client srp.Client

	// Registration: server -> client -> server. The password stays on the
	// client.
	reg := server.NewRegistration()
	verifier, err := client.NewVerifier([]byte("correct horse"), reg)
	if err != nil {
		log.Fatal(err)
	}
	if err := server.CheckVerifier(verifier); err != nil {
		log.Fatal(err)
	}
	users.SetVerifier("alice", verifier)

	// Login: client -> server (username), server -> client (challenge).
	challenge, err := server.BeginLogin(ctx, "alice")
	if err != nil {
		log.Fatal(err)
	}
	// client -> server (response), server -> client (result).
	login, err := client.Login("alice", []byte("correct horse"), challenge)
	if err != nil {
		log.Fatal(err)
	}
	result, err := server.FinishLogin(ctx, login.Response())
	if err != nil {
		log.Fatal(err)
	}
	// The client checks that the server knew its verifier.
	if err := login.VerifyServer(result.ServerProof); err != nil {
		log.Fatal(err)
	}

	claims, err := a.VerifyAccessToken(ctx, result.Tokens.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("logged in as", claims.Subject)
	// Output: logged in as alice
}

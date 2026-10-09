package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"uuid"

	"github.com/tpyle/auth/passkey"
	"github.com/tpyle/auth/v2"
)

// The service is created next to the Authorizer, sharing its claims
// provider, and exposed through four endpoints. Registration is behind
// RequireAuthHandler, so only a signed-in user can add a passkey.
func Example() {
	ctx := context.Background()
	claims := func(ctx context.Context, subject string) (map[string]any, error) {
		return map[string]any{"role": "user"}, nil
	}
	a, err := auth.New(ctx,
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithClaimsProvider(claims),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	users := passkey.NewMemoryUserStore() // implement passkey.UserStore on your user table
	users.AddUser("alice", "alice@example.com")

	pk, err := passkey.New(
		passkey.WithRelyingParty("example.com", "Example", "https://example.com"),
		passkey.WithUserStore(users),
		passkey.WithCredentialStore(passkey.NewMemoryCredentialStore()),
		passkey.WithTokenIssuer(a),
		passkey.WithClaimsProvider(claims),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /passkey/register/begin", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		ch, err := pk.BeginRegistration(r.Context(), subject)
		reply(w, ch, err)
	})))
	mux.Handle("POST /passkey/register/finish", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		id, body, err := readFinish(r)
		if err == nil {
			_, err = pk.FinishRegistration(r.Context(), subject, id, body, r.URL.Query().Get("label"))
		}
		reply(w, map[string]bool{"ok": err == nil}, err)
	})))
	mux.HandleFunc("POST /passkey/login/begin", func(w http.ResponseWriter, r *http.Request) {
		ch, err := pk.BeginLogin(r.Context())
		reply(w, ch, err)
	})
	mux.HandleFunc("POST /passkey/login/finish", func(w http.ResponseWriter, r *http.Request) {
		id, body, err := readFinish(r)
		var pair *auth.TokenPair
		if err == nil {
			pair, err = pk.FinishLogin(r.Context(), id, body)
		}
		reply(w, pair, err)
	})
	_ = mux // serve it with http.ListenAndServe
}

// readFinish reads a Finish request: the ceremony ID in the query string and
// the browser's PublicKeyCredential JSON as the body.
func readFinish(r *http.Request) (uuid.UUID, []byte, error) {
	id, err := uuid.Parse(r.URL.Query().Get("ceremony"))
	if err != nil {
		return uuid.Nil(), nil, passkey.ErrInvalidCeremony
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 64<<10))
	return id, body, err
}

func reply(w http.ResponseWriter, v any, err error) {
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	case errors.Is(err, auth.ErrInvalidCredentials):
		http.Error(w, "login failed", http.StatusUnauthorized)
	case errors.Is(err, passkey.ErrInvalidCeremony), errors.Is(err, passkey.ErrInvalidResponse):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, passkey.ErrCredentialExists):
		http.Error(w, "passkey already registered", http.StatusConflict)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

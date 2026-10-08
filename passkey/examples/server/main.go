// Command server is a small web app showing passkey registration and
// passwordless login alongside password login.
//
//	cd passkey && go run ./examples/server
//
// Then open http://localhost:8080 in a browser, sign in with alice /
// password, register a passkey, sign out, and sign back in with the passkey.
// Chrome's DevTools (More tools > WebAuthn) can emulate an authenticator if
// the machine has none.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/passkey"
	"github.com/tpyle/auth/v2"
)

//go:embed index.html
var indexHTML []byte

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
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing authorizer: %v", err)
		}
	}()
	hash, err := a.HashPassword(ctx, []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	users.SetPasswordHash("alice", hash)

	pk, err := newPasskeys(a, "http://localhost:8080")
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           newMux(a, pk),
		ReadHeaderTimeout: 5 * time.Second,
	}
	slog.Info("open http://localhost:8080", "user", "alice", "password", "password")
	log.Fatal(srv.ListenAndServe())
}

// newPasskeys creates the passkey service for alice. A real application
// would implement passkey.UserStore on its user table and create each user's
// handle when the user is created.
func newPasskeys(issuer passkey.TokenIssuer, origin string) (*passkey.Passkeys, error) {
	users := passkey.NewMemoryUserStore()
	users.AddUser("alice", "alice")
	return passkey.New(
		passkey.WithRelyingParty("localhost", "Passkey example", origin),
		passkey.WithUserStore(users),
		passkey.WithCredentialStore(passkey.NewMemoryCredentialStore()),
		passkey.WithTokenIssuer(issuer),
	)
}

func newMux(a *auth.Authorizer, pk *passkey.Passkeys) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		pair, err := a.Login(r.Context(), req.Username, []byte(req.Password))
		reply(w, r, newTokenResponse(pair), err)
	})

	// Registration adds a passkey to the signed-in user.
	mux.Handle("POST /passkey/register/begin", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		ch, err := pk.BeginRegistration(r.Context(), subject)
		reply(w, r, ch, err)
	})))
	mux.Handle("POST /passkey/register/finish", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		var req finishRequest
		if !readJSON(w, r, &req) {
			return
		}
		cred, err := pk.FinishRegistration(r.Context(), subject, req.CeremonyID, req.Credential, req.Label)
		var resp map[string]any
		if err == nil {
			resp = map[string]any{"label": cred.Label, "synced": cred.BackupEligible}
		}
		reply(w, r, resp, err)
	})))
	mux.Handle("GET /passkeys", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		creds, err := pk.ListCredentials(r.Context(), subject)
		out := []map[string]any{}
		for _, c := range creds {
			out = append(out, map[string]any{"label": c.Label, "created_at": c.CreatedAt, "last_used_at": c.LastUsedAt})
		}
		reply(w, r, out, err)
	})))

	// Login needs no username: the authenticator says who the user is.
	mux.HandleFunc("POST /passkey/login/begin", func(w http.ResponseWriter, r *http.Request) {
		ch, err := pk.BeginLogin(r.Context())
		reply(w, r, ch, err)
	})
	mux.HandleFunc("POST /passkey/login/finish", func(w http.ResponseWriter, r *http.Request) {
		var req finishRequest
		if !readJSON(w, r, &req) {
			return
		}
		pair, err := pk.FinishLogin(r.Context(), req.CeremonyID, req.Credential)
		reply(w, r, newTokenResponse(pair), err)
	})

	mux.Handle("GET /me", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]string{"subject": subject})
	})))
	return mux
}

// finishRequest is the body of both Finish endpoints.
type finishRequest struct {
	CeremonyID uuid.UUID `json:"ceremonyId"`
	// Credential is the browser's PublicKeyCredential, from toJSON().
	Credential json.RawMessage `json:"credential"`
	// Label names a new passkey; registration only.
	Label string `json:"label"`
}

type tokenResponse struct {
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"`
}

func newTokenResponse(p *auth.TokenPair) *tokenResponse {
	if p == nil {
		return nil
	}
	return &tokenResponse{AccessToken: p.AccessToken, ExpiresAt: p.AccessTokenExpiresAt, RefreshToken: p.RefreshToken}
}

// reply writes v, or maps err to an HTTP status without leaking details.
func reply(w http.ResponseWriter, r *http.Request, v any, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, v)
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	case errors.Is(err, passkey.ErrInvalidCeremony), errors.Is(err, passkey.ErrInvalidResponse):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "try_again"})
	case errors.Is(err, passkey.ErrCredentialExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_registered"})
	case errors.Is(err, context.Canceled):
		// Client went away; nothing useful to send.
	default:
		slog.ErrorContext(r.Context(), "request failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

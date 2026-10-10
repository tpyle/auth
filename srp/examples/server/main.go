// Command server is a small JSON API showing SRP registration and login.
//
//	cd srp && go run ./examples/server
//
// Then, in another terminal, register and log in with the example client:
//
//	go run ./examples/client -register -user alice -password 'correct horse'
//	go run ./examples/client -user alice -password 'correct horse'
//
// Data is kept in memory and lost when the server stops.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/tpyle/auth/srp"
	"github.com/tpyle/auth/v2"
)

func main() {
	ctx := context.Background()
	a, err := auth.New(ctx, auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()))
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			log.Printf("closing authorizer: %v", err)
		}
	}()
	users := srp.NewMemoryUserStore()
	server, err := srp.New(
		srp.WithUserStore(users),
		srp.WithTokenIssuer(a),
		// In production also set srp.WithDecoyKey and srp.WithSessionStore,
		// shared by every instance.
	)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              "localhost:8080",
		Handler:           newMux(a, server, users),
		ReadHeaderTimeout: 5 * time.Second,
	}
	slog.Info("listening on http://localhost:8080")
	log.Fatal(srv.ListenAndServe())
}

func newMux(a *auth.Authorizer, server *srp.Server, users *srp.MemoryUserStore) http.Handler {
	// Guards the check-then-set in /register/finish; a database would use a
	// unique constraint instead.
	var registerMu sync.Mutex

	mux := http.NewServeMux()

	// Sign-up: the client fetches the parameters, derives a verifier from
	// the password locally, and sends only the verifier.
	mux.HandleFunc("POST /register/begin", func(w http.ResponseWriter, r *http.Request) {
		reply(w, r, server.NewRegistration(), nil)
	})
	mux.HandleFunc("POST /register/finish", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Verifier string `json:"verifier"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		v, err := srp.ParseVerifier(req.Verifier)
		if err == nil {
			err = server.CheckVerifier(v)
		}
		if err == nil && req.Username == "" {
			err = srp.ErrInvalidVerifier
		}
		if err == nil {
			registerMu.Lock()
			defer registerMu.Unlock()
			if _, lookupErr := users.LookupVerifier(r.Context(), req.Username); lookupErr == nil {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "username_taken"})
				return
			}
			users.SetVerifier(req.Username, v)
		}
		reply(w, r, map[string]bool{"ok": true}, err)
	})

	// Login: two round trips. Rate-limit both in production; every
	// /login/begin stores a session, and every /login/finish is one guess.
	mux.HandleFunc("POST /login/begin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		ch, err := server.BeginLogin(r.Context(), req.Username)
		reply(w, r, ch, err)
	})
	mux.HandleFunc("POST /login/finish", func(w http.ResponseWriter, r *http.Request) {
		var req srp.LoginResponse
		if !readJSON(w, r, &req) {
			return
		}
		res, err := server.FinishLogin(r.Context(), req)
		var resp *loginResult
		if err == nil {
			resp = &loginResult{
				ServerProof:      res.ServerProof,
				AccessToken:      res.Tokens.AccessToken,
				RefreshToken:     res.Tokens.RefreshToken,
				VerifierOutdated: res.VerifierOutdated,
			}
		}
		reply(w, r, resp, err)
	})

	mux.Handle("GET /me", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, _ := auth.SubjectFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]string{"subject": subject})
	})))
	return mux
}

// loginResult is the body returned by /login/finish.
type loginResult struct {
	// ServerProof lets the client check the server knew its verifier.
	ServerProof      []byte `json:"serverProof"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	VerifierOutdated bool   `json:"verifier_outdated"`
}

// reply writes v, or maps err to an HTTP status without leaking details.
func reply(w http.ResponseWriter, r *http.Request, v any, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, v)
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	case errors.Is(err, srp.ErrInvalidSession):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "try_again"})
	case errors.Is(err, srp.ErrInvalidVerifier):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_verifier"})
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

// Command server is a small JSON API showing login, refresh, logout,
// protected routes and a JWKS endpoint.
//
//	go run ./examples/server
//	curl -s -XPOST localhost:8080/login -d '{"username":"alice","password":"password"}'
//	curl -s localhost:8080/me -H "Authorization: Bearer <access_token>"
//	curl -s -XPOST localhost:8080/refresh -d '{"refresh_token":"<refresh_token>"}'
//	curl -s -XPOST localhost:8080/logout -d '{"refresh_token":"<refresh_token>"}'
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/tpyle/auth/v2"
)

func main() {
	ctx := context.Background()
	users := auth.NewMemoryUserStore()
	a, err := auth.New(ctx,
		auth.WithUserStore(users),
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithIssuer("http://localhost:8080"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	hash, err := a.HashPassword(ctx, []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	users.SetPasswordHash("alice", hash)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           newMux(a),
		ReadHeaderTimeout: 5 * time.Second,
	}
	slog.Info("listening", "addr", srv.Addr, "user", "alice", "password", "password")
	log.Fatal(srv.ListenAndServe())
}

func newMux(a *auth.Authorizer) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /.well-known/jwks.json", a.JWKSHandler())
	mux.HandleFunc("POST /login", loginHandler(a))
	mux.HandleFunc("POST /refresh", refreshHandler(a))
	mux.HandleFunc("POST /logout", logoutHandler(a))

	// Routes that require a valid access token.
	mux.Handle("GET /me", a.RequireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := auth.ClaimsFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"subject": claims.Subject, "expires_at": claims.ExpiresAt})
	})))

	// Optional auth: the handler works either way.
	mux.Handle("GET /hello", a.AuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := "anonymous"
		if sub, ok := auth.SubjectFromContext(r.Context()); ok {
			name = sub
		}
		writeJSON(w, http.StatusOK, map[string]string{"hello": name})
	})))
	return mux
}

type tokenResponse struct {
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"`
}

func newTokenResponse(p *auth.TokenPair) tokenResponse {
	return tokenResponse{AccessToken: p.AccessToken, ExpiresAt: p.AccessTokenExpiresAt, RefreshToken: p.RefreshToken}
}

func loginHandler(a *auth.Authorizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		pair, err := a.Login(r.Context(), req.Username, []byte(req.Password))
		if err != nil {
			writeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, newTokenResponse(pair))
	}
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func refreshHandler(a *auth.Authorizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if !readJSON(w, r, &req) {
			return
		}
		pair, err := a.Refresh(r.Context(), req.RefreshToken)
		if err != nil {
			writeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, newTokenResponse(pair))
	}
}

func logoutHandler(a *auth.Authorizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if !readJSON(w, r, &req) {
			return
		}
		if err := a.Logout(r.Context(), req.RefreshToken); err != nil {
			writeError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// writeError maps auth errors to HTTP statuses without leaking details.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrInvalidToken),
		errors.Is(err, auth.ErrTokenExpired),
		errors.Is(err, auth.ErrTokenRevoked),
		errors.Is(err, auth.ErrRefreshTokenReused):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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

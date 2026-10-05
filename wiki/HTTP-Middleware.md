# HTTP Middleware

## AuthHandler vs RequireAuthHandler

| | `AuthHandler` | `RequireAuthHandler` |
|---|---|---|
| Valid token | Claims added to the context, request continues | Claims added to the context, request continues |
| Missing / invalid / expired token | Request continues **without** claims | `UnauthorizedHandler` is called (default: 401) |
| Internal error (e.g. `KeyStore` down) | Logged, request continues without claims | Logged, `UnauthorizedHandler` is called (default: 500) |
| Claims already in the context | Not checked again | Reused, not checked again |

Use `AuthHandler` for routes where login is optional (pages that change when you are logged in). Use `RequireAuthHandler` for protected routes. You can stack them: wrap the whole mux in `AuthHandler` and individual routes in `RequireAuthHandler`, and each token is verified only once.

Both are `func(http.Handler) http.Handler`, so they work with `net/http` and any router that accepts standard middleware.

## Token extraction

The token is read from the request in this order:

1. **Header** (`Config.AuthHeader`, default `Authorization`). The value must be `Bearer <token>`. The scheme is case-insensitive (`bearer`, `BEARER` work), and surrounding whitespace is trimmed. A header with any other scheme (e.g. `Basic ...`) or an empty token is **ignored**, as if it were absent.
2. **Cookie** (`Config.AuthCookie`, off by default). The cookie value is the raw access token, with no `Bearer` prefix.

If both carry a token, **the header wins**. The cookie is not tried even if the header token is invalid. If you set `AuthHeader` to `""`, only the cookie is used. If you set both to `""`, every request is unauthenticated.

`ClaimsFromRequest(r)` runs the same extraction and verification by hand. It returns `ErrNoToken` when there is no token.

## Context helpers

```go
claims, ok := auth.ClaimsFromContext(r.Context())   // *auth.Claims
sub, ok := auth.SubjectFromContext(r.Context())     // claims.Subject
ctx := auth.ContextWithClaims(ctx, claims)          // e.g. in tests
```

## Default rejection response

`RequireAuthHandler` uses this default `UnauthorizedHandler`. It always sets `Content-Type: application/json` and never shows error details to the client:

| Cause | Status | `WWW-Authenticate` | Body |
|---|---|---|---|
| No token (`ErrNoToken`) | 401 | `Bearer` | `{"error":"unauthorized"}` |
| Invalid or expired token (`ErrInvalidToken`, `ErrTokenExpired`) | 401 | `Bearer error="invalid_token"` | `{"error":"unauthorized"}` |
| Anything else (internal) | 500 | — | `{"error":"internal_error"}` |

### Custom UnauthorizedHandler

```go
auth.WithUnauthorizedHandler(func(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrNoToken):
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	case errors.Is(err, auth.ErrTokenExpired):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="expired"`)
		http.Error(w, "token expired", http.StatusUnauthorized)
	case errors.Is(err, auth.ErrInvalidToken):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	default: // internal error; already logged by the middleware
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
})
```

`err` wraps `ErrNoToken`, `ErrInvalidToken` or `ErrTokenExpired` when the client is at fault. Any other error is an internal failure.

## JWKSHandler

`a.JWKSHandler()` serves the public keys as a JWK Set with `Cache-Control: public, max-age=300`. If `ListKeys` fails, it returns a plain-text 500. See [Tokens and Keys](Tokens-and-Keys.md#jwks).

## Full example

A JSON API with login, refresh, logout, a protected route, and JWKS. It uses in-memory stores; for production, swap in the stores from [Storage](Storage.md).

```go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/tpyle/auth/v2"
)

type server struct{ a *auth.Authorizer }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

type tokenResponse struct {
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
}

func pairResponse(p *auth.TokenPair) tokenResponse {
	return tokenResponse{AccessToken: p.AccessToken, ExpiresAt: p.AccessTokenExpiresAt, RefreshToken: p.RefreshToken}
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	pair, err := s.a.Login(r.Context(), req.Username, []byte(req.Password))
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeErr(w, http.StatusUnauthorized, "invalid_credentials")
	case err != nil:
		log.Printf("login: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal_error")
	default:
		writeJSON(w, http.StatusOK, pairResponse(pair))
	}
}

func (s *server) refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	pair, err := s.a.Refresh(r.Context(), req.RefreshToken)
	switch {
	case errors.Is(err, auth.ErrRefreshTokenReused),
		errors.Is(err, auth.ErrTokenRevoked),
		errors.Is(err, auth.ErrTokenExpired),
		errors.Is(err, auth.ErrInvalidToken):
		writeErr(w, http.StatusUnauthorized, "invalid_grant")
	case err != nil:
		log.Printf("refresh: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal_error")
	default:
		writeJSON(w, http.StatusOK, pairResponse(pair))
	}
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	err := s.a.Logout(r.Context(), req.RefreshToken)
	switch {
	case errors.Is(err, auth.ErrInvalidToken):
		writeErr(w, http.StatusUnauthorized, "invalid_token")
	case err != nil:
		log.Printf("logout: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal_error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context()) // always present behind RequireAuthHandler
	role, _ := claims.GetString("role")
	writeJSON(w, http.StatusOK, map[string]string{"user": claims.Subject, "role": role})
}

func main() {
	ctx := context.Background()
	users := auth.NewMemoryUserStore()

	a, err := auth.New(ctx,
		auth.WithUserStore(users),
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithIssuer("http://localhost:8080"),
		auth.WithClaimsProvider(func(ctx context.Context, subject string) (map[string]any, error) {
			return map[string]any{"role": "user"}, nil
		}),
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

	s := &server{a: a}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /refresh", s.refresh)
	mux.HandleFunc("POST /logout", s.logout)
	mux.Handle("GET /me", a.RequireAuthHandler(http.HandlerFunc(s.me)))
	mux.Handle("GET /.well-known/jwks.json", a.JWKSHandler())

	srv := &http.Server{Addr: ":8080", Handler: a.AuthHandler(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
```

Try it:

```sh
curl -s -XPOST localhost:8080/login -d '{"username":"alice","password":"s3cret"}'
curl -s localhost:8080/me -H "Authorization: Bearer $ACCESS"
curl -s -XPOST localhost:8080/refresh -d "{\"refresh_token\":\"$REFRESH\"}"
curl -s -XPOST localhost:8080/logout  -d "{\"refresh_token\":\"$REFRESH\"}"
```

### Cookie-based variant

For browser apps, put the access token in an `HttpOnly` cookie and turn on cookie extraction with `auth.WithAuthCookie("access_token")`:

```go
http.SetCookie(w, &http.Cookie{
	Name:     "access_token",
	Value:    pair.AccessToken,
	Path:     "/",
	Expires:  pair.AccessTokenExpiresAt,
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteLaxMode,
})
```

Store the refresh token in a separate `HttpOnly` cookie scoped to the refresh and logout endpoints (e.g. serve them under `/auth/` and set `Path: "/auth/"`) so it is not sent with every request. Cookie authentication is open to CSRF. See [Security](Security.md#recommendations).

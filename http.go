package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// jwksMaxAge is the longest time JWKS responses may be cached.
const jwksMaxAge = 5 * time.Minute

type claimsKey struct{}

// ContextWithClaims returns a copy of ctx carrying c.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

// ClaimsFromContext returns the claims stored by [Authorizer.AuthHandler] or
// [Authorizer.RequireAuthHandler], if any.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*Claims)
	return c, ok && c != nil
}

// SubjectFromContext returns the subject of the claims in ctx, if any.
func SubjectFromContext(ctx context.Context) (string, bool) {
	c, ok := ClaimsFromContext(ctx)
	if !ok {
		return "", false
	}
	return c.Subject, true
}

// tokenFromRequest extracts the raw token. A "Bearer" header takes priority
// over the cookie; a header with any other scheme is ignored.
func (a *Authorizer) tokenFromRequest(r *http.Request) string {
	if a.s.AuthHeader != "" {
		scheme, tok, ok := strings.Cut(strings.TrimSpace(r.Header.Get(a.s.AuthHeader)), " ")
		if tok = strings.TrimSpace(tok); ok && strings.EqualFold(scheme, "Bearer") && tok != "" {
			return tok
		}
	}
	if a.s.AuthCookie != "" {
		if c, err := r.Cookie(a.s.AuthCookie); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// ClaimsFromRequest extracts and verifies the access token in r. It returns
// [ErrNoToken] if the request has none.
func (a *Authorizer) ClaimsFromRequest(r *http.Request) (*Claims, error) {
	tok := a.tokenFromRequest(r)
	if tok == "" {
		return nil, ErrNoToken
	}
	return a.VerifyAccessToken(r.Context(), tok)
}

// isClientError reports whether err is the caller's fault rather than an
// internal failure.
func isClientError(err error) bool {
	return errors.Is(err, ErrNoToken) || errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrTokenExpired)
}

// AuthHandler is middleware for optional authentication. If the request
// carries a valid access token, its [Claims] are added to the request context
// (see [ClaimsFromContext]); otherwise the request continues without them.
// Internal errors are logged.
func (a *Authorizer) AuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ClaimsFromContext(r.Context()); !ok {
			c, err := a.ClaimsFromRequest(r)
			switch {
			case err == nil:
				r = r.WithContext(ContextWithClaims(r.Context(), c))
			case !isClientError(err):
				a.s.logger.ErrorContext(r.Context(), "auth: verifying request token", "error", err)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAuthHandler is middleware that rejects requests without a valid
// access token, using the [UnauthorizedHandler] (by default a JSON 401 with a
// WWW-Authenticate header). Accepted requests have their [Claims] in the
// context. Claims already placed there by [Authorizer.AuthHandler] are
// reused rather than verified again.
func (a *Authorizer) RequireAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ClaimsFromContext(r.Context()); ok {
			next.ServeHTTP(w, r)
			return
		}
		c, err := a.ClaimsFromRequest(r)
		if err != nil {
			if !isClientError(err) {
				a.s.logger.ErrorContext(r.Context(), "auth: verifying request token", "error", err)
			}
			a.s.unauthorized(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), c)))
	})
}

// defaultUnauthorized writes a 401 per RFC 6750 for client errors and a 500
// for internal ones. Error details are not exposed to the client.
func defaultUnauthorized(w http.ResponseWriter, _ *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	if !isClientError(err) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal_error"}` + "\n"))
		return
	}
	if errors.Is(err, ErrNoToken) {
		w.Header().Set("WWW-Authenticate", `Bearer`)
	} else {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}` + "\n"))
}

// JWKSHandler serves [Authorizer.JWKS] as JSON. Mount it at
// /.well-known/jwks.json. Responses may be cached for five minutes, or half
// of [Config.KeyRotationInterval] if that is shorter, so a cached set always
// includes a pre-published key before it starts signing.
func (a *Authorizer) JWKSHandler() http.Handler {
	maxAge := jwksMaxAge
	if a.s.KeyRotationInterval > 0 {
		maxAge = min(maxAge, a.s.KeyRotationInterval/2)
	}
	cacheControl := fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set, err := a.JWKS(r.Context())
		if err != nil {
			a.s.logger.ErrorContext(r.Context(), "auth: serving JWKS", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", cacheControl)
		_ = json.NewEncoder(w).Encode(set)
	})
}

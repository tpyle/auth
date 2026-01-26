package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func parseAuthHeader(header string) (string, string) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return strings.ToLower(parts[0]), parts[1]
}

type contextKey string

const tokenKey contextKey = "token"

func GetToken(ctx context.Context) *AuthorizerToken {
	if value, ok := ctx.Value(tokenKey).(*AuthorizerToken); ok {
		return value
	} else {
		return nil
	}
}

func WithToken(ctx context.Context, token *AuthorizerToken) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}

func (a *Authorizer) GetTokenFromRequest(r *http.Request) *AuthorizerToken {
	token := ""

	if a.Options.AuthHeader != nil {
		authHeader := r.Header.Get(*a.Options.AuthHeader)
		if authHeader != "" {
			var tokenType string
			tokenType, token = parseAuthHeader(authHeader)
			if tokenType != "bearer" {
				token = ""
			}
		}
	}
	if a.Options.AuthCookie != nil {
		jwtCookie, err := r.Cookie(*a.Options.AuthCookie)
		if err == nil {
			token = jwtCookie.Value
		}
	}

	if token != "" {
		tok, err := a.VerifyToken(token)
		if err == nil {
			if tok.IsValid() {
				return tok
			}
		}
	}

	return nil
}

// AuthHandler is a middleware that extracts the JWT token from the request
// and verifies it. If the token is valid, it is added to the request context.
// If no token is found, the request is passed through without a token in the context.
func (a *Authorizer) AuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := a.GetTokenFromRequest(r)
		if token != nil {
			ctx := r.Context()
			ctx = WithToken(ctx, token)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAuthHandler is a middleware that requires a valid JWT token
// in the request context. If no valid token is found, a 401 Unauthorized
// response is returned.
func (a *Authorizer) RequireAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := a.GetTokenFromRequest(r)
		if token == nil || !token.IsValid() {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("{\"message\": \"missing token\"}"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func HasToken(r *http.Request) bool {
	token := GetToken(r.Context())

	return token != nil
}

func GetSub(r *http.Request) (string, error) {
	token := GetToken(r.Context())
	if token == nil {
		return "", fmt.Errorf("no token in context")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	return getClaimAsString(claims, "sub")
}

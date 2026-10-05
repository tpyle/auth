package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenFromRequest(t *testing.T) {
	both := newTestAuthorizer(t, WithAuthCookie("session"))
	headerOnly := newTestAuthorizer(t)
	cookieOnly := newTestAuthorizer(t, WithAuthHeader(""), WithAuthCookie("session"))
	custom := newTestAuthorizer(t, WithAuthHeader("X-Token"))

	tests := []struct {
		name   string
		a      *Authorizer
		header string
		hval   string
		cookie string
		want   string
	}{
		{"bearer", headerOnly, "Authorization", "Bearer abc", "", "abc"},
		{"case-insensitive scheme", headerOnly, "Authorization", "bEaReR abc", "", "abc"},
		{"extra whitespace", headerOnly, "Authorization", "  Bearer   abc  ", "", "abc"},
		{"basic scheme ignored", headerOnly, "Authorization", "Basic abc", "", ""},
		{"no token", headerOnly, "Authorization", "Bearer", "", ""},
		{"blank token", headerOnly, "Authorization", "Bearer   ", "", ""},
		{"cookie ignored when disabled", headerOnly, "", "", "abc", ""},
		{"custom header", custom, "X-Token", "Bearer abc", "", "abc"},
		{"default header ignored when renamed", custom, "Authorization", "Bearer abc", "", ""},
		{"cookie", cookieOnly, "", "", "abc", "abc"},
		{"header ignored when disabled", cookieOnly, "Authorization", "Bearer abc", "", ""},
		{"header wins over cookie", both, "Authorization", "Bearer fromheader", "fromcookie", "fromheader"},
		{"cookie used if header has other scheme", both, "Authorization", "Basic x", "fromcookie", "fromcookie"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				r.Header.Set(tt.header, tt.hval)
			}
			if tt.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "session", Value: tt.cookie})
			}
			if got := tt.a.tokenFromRequest(r); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

// claimsRecorder is a handler that records the claims it sees.
type claimsRecorder struct {
	called bool
	claims *Claims
}

func (h *claimsRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.claims, _ = ClaimsFromContext(r.Context())
	w.WriteHeader(http.StatusTeapot)
}

func request(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestAuthHandler(t *testing.T) {
	ctx := context.Background()
	keys := newFaultyKeyStore()
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithKeyStore(keys))
	other := newTestAuthorizer(t, WithKeyStore(keys))
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	otherTok, _ := other.IssueAccessToken("carol", nil)

	tests := []struct {
		name    string
		token   string
		listErr error
		subject string
	}{
		{"valid", pair.AccessToken, nil, "bob"},
		{"none", "", nil, ""},
		{"invalid", "garbage", nil, ""},
		{"refresh token", pair.RefreshToken, nil, ""},
		{"key store down", otherTok, errTest, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys.fail(&keys.listErr, tt.listErr)
			defer keys.fail(&keys.listErr, nil)
			next := &claimsRecorder{}
			a.AuthHandler(next).ServeHTTP(httptest.NewRecorder(), request(tt.token))
			if !next.called {
				t.Fatal("next handler not called")
			}
			got := ""
			if next.claims != nil {
				got = next.claims.Subject
			}
			if got != tt.subject {
				t.Errorf("subject = %q; want %q", got, tt.subject)
			}
		})
	}

	t.Run("existing claims kept", func(t *testing.T) {
		next := &claimsRecorder{}
		r := request("garbage")
		r = r.WithContext(ContextWithClaims(r.Context(), &Claims{Subject: "pre"}))
		a.AuthHandler(next).ServeHTTP(httptest.NewRecorder(), r)
		if next.claims == nil || next.claims.Subject != "pre" {
			t.Errorf("claims = %+v", next.claims)
		}
	})
}

func TestRequireAuthHandler(t *testing.T) {
	ctx := context.Background()
	keys := newFaultyKeyStore()
	a := newRefreshAuthorizer(t, NewMemoryRefreshTokenStore(), WithKeyStore(keys))
	other := newTestAuthorizer(t, WithKeyStore(keys))
	pair, _ := a.IssueTokenPair(ctx, "bob", nil)
	otherTok, _ := other.IssueAccessToken("carol", nil)

	tests := []struct {
		name      string
		token     string
		listErr   error
		status    int
		challenge string
	}{
		{"valid", pair.AccessToken, nil, http.StatusTeapot, ""},
		{"missing", "", nil, http.StatusUnauthorized, "Bearer"},
		{"invalid", "garbage", nil, http.StatusUnauthorized, `Bearer error="invalid_token"`},
		{"refresh token", pair.RefreshToken, nil, http.StatusUnauthorized, `Bearer error="invalid_token"`},
		{"key store down", otherTok, errTest, http.StatusInternalServerError, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys.fail(&keys.listErr, tt.listErr)
			defer keys.fail(&keys.listErr, nil)
			next := &claimsRecorder{}
			rec := httptest.NewRecorder()
			a.RequireAuthHandler(next).ServeHTTP(rec, request(tt.token))

			if rec.Code != tt.status {
				t.Errorf("status = %d; want %d", rec.Code, tt.status)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.challenge {
				t.Errorf("WWW-Authenticate = %q; want %q", got, tt.challenge)
			}
			if tt.status == http.StatusTeapot {
				if next.claims == nil || next.claims.Subject != "bob" {
					t.Errorf("claims not in context: %+v", next.claims)
				}
				return
			}
			if next.called {
				t.Error("next handler called for rejected request")
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q", ct)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
				t.Errorf("body = %q", rec.Body.String())
			}
		})
	}

	t.Run("reuses claims from AuthHandler", func(t *testing.T) {
		next := &claimsRecorder{}
		r := request("")
		r = r.WithContext(ContextWithClaims(r.Context(), &Claims{Subject: "pre"}))
		a.RequireAuthHandler(next).ServeHTTP(httptest.NewRecorder(), r)
		if !next.called || next.claims.Subject != "pre" {
			t.Error("pre-verified claims were not accepted")
		}
	})

	t.Run("chained after AuthHandler", func(t *testing.T) {
		next := &claimsRecorder{}
		a.AuthHandler(a.RequireAuthHandler(next)).ServeHTTP(httptest.NewRecorder(), request(pair.AccessToken))
		if next.claims == nil || next.claims.Subject != "bob" {
			t.Errorf("claims = %+v", next.claims)
		}
	})
}

func TestCustomUnauthorizedHandler(t *testing.T) {
	var gotErr error
	a := newTestAuthorizer(t, WithUnauthorizedHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusForbidden)
	}))
	rec := httptest.NewRecorder()
	a.RequireAuthHandler(&claimsRecorder{}).ServeHTTP(rec, request(""))
	if rec.Code != http.StatusForbidden || !errors.Is(gotErr, ErrNoToken) {
		t.Errorf("status %d err %v", rec.Code, gotErr)
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	if _, ok := ClaimsFromContext(ctx); ok {
		t.Error("empty context has claims")
	}
	if _, ok := SubjectFromContext(ctx); ok {
		t.Error("empty context has subject")
	}
	if _, ok := ClaimsFromContext(ContextWithClaims(ctx, nil)); ok {
		t.Error("nil claims reported as present")
	}
	ctx = ContextWithClaims(ctx, &Claims{Subject: "bob"})
	if sub, ok := SubjectFromContext(ctx); !ok || sub != "bob" {
		t.Errorf("SubjectFromContext = %q, %v", sub, ok)
	}
}

func TestJWKSHandler(t *testing.T) {
	keys := newFaultyKeyStore()
	a := newTestAuthorizer(t, WithKeyStore(keys))

	rec := httptest.NewRecorder()
	a.JWKSHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") == "" {
		t.Errorf("status %d headers %v", rec.Code, rec.Header())
	}
	var set JWKSet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil || len(set.Keys) != 2 { // current and next
		t.Errorf("body %q: %v", rec.Body.String(), err)
	}

	keys.fail(&keys.listErr, errTest)
	rec = httptest.NewRecorder()
	a.JWKSHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", rec.Code)
	}
}

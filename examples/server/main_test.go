package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tpyle/auth/v2"
)

func TestServerFlow(t *testing.T) {
	ctx := context.Background()
	users := auth.NewMemoryUserStore()
	a, err := auth.New(ctx,
		auth.WithUserStore(users),
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithArgon2Params(auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	hash, _ := a.HashPassword(ctx, []byte("password"))
	users.SetPasswordHash("alice", hash)
	srv := httptest.NewServer(newMux(a))
	defer srv.Close()

	do := func(method, path, body, token string) (*http.Response, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}

	if resp, _ := do("POST", "/login", `{"username":"alice","password":"nope"}`, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad login status %d", resp.StatusCode)
	}
	if resp, _ := do("POST", "/login", `{`, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed body status %d", resp.StatusCode)
	}
	resp, login := do("POST", "/login", `{"username":"alice","password":"password"}`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	access, _ := login["access_token"].(string)
	refresh, _ := login["refresh_token"].(string)

	if resp, _ := do("GET", "/me", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/me without token: %d", resp.StatusCode)
	}
	if resp, me := do("GET", "/me", "", access); resp.StatusCode != http.StatusOK || me["subject"] != "alice" {
		t.Errorf("/me: %d %v", resp.StatusCode, me)
	}
	if _, hello := do("GET", "/hello", "", ""); hello["hello"] != "anonymous" {
		t.Errorf("/hello anonymous: %v", hello)
	}
	if _, hello := do("GET", "/hello", "", access); hello["hello"] != "alice" {
		t.Errorf("/hello authed: %v", hello)
	}
	if resp, jwks := do("GET", "/.well-known/jwks.json", "", ""); resp.StatusCode != http.StatusOK || len(jwks["keys"].([]any)) != 2 { // current and pre-published next key
		t.Errorf("jwks: %d %v", resp.StatusCode, jwks)
	}

	resp, refreshed := do("POST", "/refresh", `{"refresh_token":"`+refresh+`"}`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status %d", resp.StatusCode)
	}
	newRefresh, _ := refreshed["refresh_token"].(string)
	if resp, _ := do("POST", "/logout", `{"refresh_token":"`+newRefresh+`"}`, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("logout status %d", resp.StatusCode)
	}
	if resp, _ := do("POST", "/refresh", `{"refresh_token":"`+newRefresh+`"}`, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("refresh after logout status %d", resp.StatusCode)
	}
}

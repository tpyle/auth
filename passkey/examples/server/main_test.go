package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

func TestServerRoutes(t *testing.T) {
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
	defer func() { _ = a.Close() }()
	hash, _ := a.HashPassword(ctx, []byte("password"))
	users.SetPasswordHash("alice", hash)
	pk, err := newPasskeys(a, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newMux(a, pk))
	defer srv.Close()

	do := func(method, path, body, token string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("GET / = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	if code, _ := do("POST", "/passkey/register/begin", "", ""); code != http.StatusUnauthorized {
		t.Errorf("register without token = %d", code)
	}
	code, login := do("POST", "/login", `{"username":"alice","password":"password"}`, "")
	if code != http.StatusOK {
		t.Fatalf("login = %d", code)
	}
	token := login["access_token"].(string)

	code, ch := do("POST", "/passkey/register/begin", "", token)
	if code != http.StatusOK || ch["ceremonyId"] == nil || ch["options"] == nil {
		t.Fatalf("register begin = %d %v", code, ch)
	}
	body := `{"ceremonyId":"` + ch["ceremonyId"].(string) + `","credential":{"id":"x"}}`
	if code, _ := do("POST", "/passkey/register/finish", body, token); code != http.StatusBadRequest {
		t.Errorf("register finish with bad credential = %d", code)
	}
	if code, list := do("GET", "/passkeys", "", token); code != http.StatusOK || list != nil {
		t.Errorf("list = %d %v", code, list)
	}

	code, ch = do("POST", "/passkey/login/begin", "", "")
	if code != http.StatusOK {
		t.Fatalf("login begin = %d", code)
	}
	body = `{"ceremonyId":"` + ch["ceremonyId"].(string) + `","credential":{"id":"x"}}`
	if code, _ := do("POST", "/passkey/login/finish", body, ""); code != http.StatusUnauthorized {
		t.Errorf("login finish with bad credential = %d", code)
	}
	body = `{"ceremonyId":"` + uuid.NewString() + `","credential":{}}`
	if code, _ := do("POST", "/passkey/login/finish", body, ""); code != http.StatusBadRequest {
		t.Errorf("login finish with unknown ceremony = %d", code)
	}
	if code, _ := do("POST", "/passkey/login/finish", "not json", ""); code != http.StatusBadRequest {
		t.Errorf("login finish with bad JSON = %d", code)
	}
}

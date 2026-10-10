package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tpyle/auth/srp"
	"github.com/tpyle/auth/v2"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	a, err := auth.New(context.Background(), auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	users := srp.NewMemoryUserStore()
	server, err := srp.New(srp.WithUserStore(users), srp.WithTokenIssuer(a),
		srp.WithKDFParams(srp.KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1}))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(newMux(a, server, users))
	t.Cleanup(ts.Close)
	return ts
}

func post(t *testing.T, ts *httptest.Server, path string, body, out any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

func register(t *testing.T, ts *httptest.Server, user, password string) int {
	t.Helper()
	var reg srp.Registration
	if code := post(t, ts, "/register/begin", struct{}{}, &reg); code != http.StatusOK {
		t.Fatalf("register/begin: %d", code)
	}
	v, err := srp.Client{}.NewVerifier([]byte(password), &reg)
	if err != nil {
		t.Fatal(err)
	}
	return post(t, ts, "/register/finish", map[string]string{"username": user, "verifier": v.String()}, nil)
}

func login(t *testing.T, ts *httptest.Server, user, password string) (*loginResult, *srp.ClientLogin, int) {
	t.Helper()
	var ch srp.Challenge
	if code := post(t, ts, "/login/begin", map[string]string{"username": user}, &ch); code != http.StatusOK {
		t.Fatalf("login/begin: %d", code)
	}
	cl, err := srp.Client{}.Login(user, []byte(password), &ch)
	if err != nil {
		t.Fatal(err)
	}
	var res loginResult
	code := post(t, ts, "/login/finish", cl.Response(), &res)
	return &res, cl, code
}

func TestRegisterAndLogin(t *testing.T) {
	ts := newTestServer(t)
	if code := register(t, ts, "alice", "correct horse"); code != http.StatusOK {
		t.Fatalf("register: %d", code)
	}
	res, cl, code := login(t, ts, "alice", "correct horse")
	if code != http.StatusOK {
		t.Fatalf("login: %d", code)
	}
	if err := cl.VerifyServer(res.ServerProof); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+res.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var me map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&me)
	if resp.StatusCode != http.StatusOK || me["subject"] != "alice" {
		t.Errorf("/me = %d %v", resp.StatusCode, me)
	}
}

func TestErrors(t *testing.T) {
	ts := newTestServer(t)
	register(t, ts, "alice", "correct horse")

	if code := register(t, ts, "alice", "other"); code != http.StatusConflict {
		t.Errorf("duplicate registration: %d", code)
	}
	if code := register(t, ts, "", "pw"); code != http.StatusBadRequest {
		t.Errorf("empty username: %d", code)
	}
	if code := post(t, ts, "/register/finish", map[string]string{"username": "bob", "verifier": "junk"}, nil); code != http.StatusBadRequest {
		t.Errorf("junk verifier: %d", code)
	}
	if _, _, code := login(t, ts, "alice", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", code)
	}
	if _, _, code := login(t, ts, "nobody", "pw"); code != http.StatusUnauthorized {
		t.Errorf("unknown user: %d", code)
	}
	if code := post(t, ts, "/login/finish", srp.LoginResponse{}, nil); code != http.StatusBadRequest {
		t.Errorf("unknown session: %d", code)
	}
	resp, err := http.Post(ts.URL+"/login/begin", "application/json", bytes.NewReader([]byte("{")))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", resp.StatusCode)
	}
}

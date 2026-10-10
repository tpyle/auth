package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tpyle/auth/srp"
)

// newTestServer serves the endpoints the client uses, backed by an
// srp.Server, without tokens.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	users := srp.NewMemoryUserStore()
	server, err := srp.New(srp.WithUserStore(users),
		srp.WithKDFParams(srp.KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1}))
	if err != nil {
		t.Fatal(err)
	}
	write := func(w http.ResponseWriter, v any, err error) {
		if err != nil {
			http.Error(w, `{"error":"failed"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register/begin", func(w http.ResponseWriter, _ *http.Request) {
		write(w, server.NewRegistration(), nil)
	})
	mux.HandleFunc("POST /register/finish", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		v, err := srp.ParseVerifier(req["verifier"])
		if err == nil {
			users.SetVerifier(req["username"], v)
		}
		write(w, struct{}{}, err)
	})
	mux.HandleFunc("POST /login/begin", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		ch, err := server.BeginLogin(r.Context(), req["username"])
		write(w, ch, err)
	})
	mux.HandleFunc("POST /login/finish", func(w http.ResponseWriter, r *http.Request) {
		var req srp.LoginResponse
		_ = json.NewDecoder(r.Body).Decode(&req)
		res, err := server.Authenticate(r.Context(), req)
		var out *loginResult
		if err == nil {
			out = &loginResult{ServerProof: res.ServerProof, AccessToken: "token"}
		}
		write(w, out, err)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestClient(t *testing.T) {
	ts := newTestServer(t)
	c := &apiClient{base: ts.URL, http: ts.Client()}
	if err := c.Register("alice", []byte("pw")); err != nil {
		t.Fatal(err)
	}
	res, err := c.Login("alice", []byte("pw"))
	if err != nil || res.AccessToken != "token" {
		t.Fatalf("Login = %+v, %v", res, err)
	}
	if _, err := c.Login("alice", []byte("wrong")); !errors.Is(err, errStatus) {
		t.Errorf("wrong password: %v", err)
	}
}

func TestClientRejectsBadServerProof(t *testing.T) {
	// A server that accepts the login but cannot prove it knows the verifier
	// is not trusted.
	real := newTestServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/finish" {
			_ = json.NewEncoder(w).Encode(loginResult{ServerProof: make([]byte, 32), AccessToken: "evil"})
			return
		}
		proxy, _ := http.NewRequest(r.Method, real.URL+r.URL.Path, r.Body)
		resp, err := real.Client().Do(proxy)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		var v any
		_ = json.NewDecoder(resp.Body).Decode(&v)
		_ = json.NewEncoder(w).Encode(v)
	})
	evil := httptest.NewServer(mux)
	defer evil.Close()

	if err := (&apiClient{base: real.URL, http: real.Client()}).Register("alice", []byte("pw")); err != nil {
		t.Fatal(err)
	}
	c := &apiClient{base: evil.URL, http: evil.Client()}
	if _, err := c.Login("alice", []byte("pw")); !errors.Is(err, srp.ErrInvalidServerProof) {
		t.Errorf("err = %v", err)
	}
}

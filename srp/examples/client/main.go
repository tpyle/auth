// Command client registers and logs in against the example server in
// ../server using SRP. The password never leaves this process.
//
//	go run ./examples/client -register -user alice -password 'correct horse'
//	go run ./examples/client -user alice -password 'correct horse'
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/tpyle/auth/srp"
)

func main() {
	base := flag.String("server", "http://localhost:8080", "server URL")
	user := flag.String("user", "", "username")
	password := flag.String("password", "", "password")
	register := flag.Bool("register", false, "register the user instead of logging in")
	flag.Parse()
	if *user == "" || *password == "" {
		log.Fatal("-user and -password are required")
	}

	c := &apiClient{base: *base, http: http.DefaultClient}
	if *register {
		if err := c.Register(*user, []byte(*password)); err != nil {
			log.Fatal(err)
		}
		fmt.Println("registered", *user)
		return
	}
	res, err := c.Login(*user, []byte(*password))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("logged in; access token:", res.AccessToken)
	if res.VerifierOutdated {
		fmt.Println("the server asks for a new verifier: register again to upgrade it")
	}
}

// apiClient talks to the example server.
type apiClient struct {
	base string
	http *http.Client
	srp  srp.Client
}

// Register creates a verifier with the server's parameters and uploads it.
func (c *apiClient) Register(user string, password []byte) error {
	var reg srp.Registration
	if err := c.post("/register/begin", struct{}{}, &reg); err != nil {
		return err
	}
	v, err := c.srp.NewVerifier(password, &reg)
	if err != nil {
		return err
	}
	return c.post("/register/finish", map[string]string{"username": user, "verifier": v.String()}, nil)
}

// loginResult mirrors the server's /login/finish response.
type loginResult struct {
	ServerProof      []byte `json:"serverProof"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	VerifierOutdated bool   `json:"verifier_outdated"`
}

// Login runs both round trips and checks the server's proof before
// trusting the tokens.
func (c *apiClient) Login(user string, password []byte) (*loginResult, error) {
	var ch srp.Challenge
	if err := c.post("/login/begin", map[string]string{"username": user}, &ch); err != nil {
		return nil, err
	}
	login, err := c.srp.Login(user, password, &ch)
	if err != nil {
		return nil, err
	}
	var res loginResult
	if err := c.post("/login/finish", login.Response(), &res); err != nil {
		return nil, err
	}
	if err := login.VerifyServer(res.ServerProof); err != nil {
		return nil, err
	}
	return &res, nil
}

// errStatus is returned for non-200 responses.
var errStatus = errors.New("unexpected status")

func (c *apiClient) post(path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.http.Post(c.base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s: %w %d (%s)", path, errStatus, resp.StatusCode, e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

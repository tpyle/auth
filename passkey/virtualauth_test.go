package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// virtualAuthenticator is a software WebAuthn authenticator plus browser:
// it answers creation and request options the way navigator.credentials
// would, producing JSON-serialized PublicKeyCredentials.
type virtualAuthenticator struct {
	t      *testing.T
	origin string
	// Flags added to every response, on top of UP.
	userVerified, backupEligible, backupState bool
	// counter is reported (then incremented) by each assertion if
	// useCounter is set; otherwise 0 is always reported.
	useCounter bool
	counter    uint32

	// Credentials created so far, by base64url ID.
	creds map[string]*virtualCredential
}

type virtualCredential struct {
	id     []byte
	key    *ecdsa.PrivateKey
	rpID   string
	handle []byte
}

func newVirtualAuthenticator(t *testing.T, origin string) *virtualAuthenticator {
	t.Helper()
	return &virtualAuthenticator{t: t, origin: origin, userVerified: true, creds: map[string]*virtualCredential{}}
}

var b64 = base64.RawURLEncoding

// creationOptions is the subset of PublicKeyCredentialCreationOptionsJSON
// the authenticator needs.
type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

// create answers a registration Challenge.
func (a *virtualAuthenticator) create(c *Challenge) ([]byte, *virtualCredential) {
	a.t.Helper()
	var opts creationOptions
	mustUnmarshal(a.t, c.Options, &opts)
	handle, err := b64.DecodeString(opts.PublicKey.User.ID)
	if err != nil {
		a.t.Fatalf("decoding user id: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		a.t.Fatal(err)
	}
	cred := &virtualCredential{id: randomBytes(a.t, 32), key: key, rpID: opts.PublicKey.RP.ID, handle: handle}
	return a.attest(cred, opts.PublicKey.Challenge, "webauthn.create"), cred
}

// attest builds a registration response for cred and remembers it.
func (a *virtualAuthenticator) attest(cred *virtualCredential, challenge, typ string) []byte {
	a.t.Helper()
	a.creds[b64.EncodeToString(cred.id)] = cred
	clientData := a.clientData(typ, challenge)

	pub, err := cred.key.PublicKey.ECDH()
	if err != nil {
		a.t.Fatal(err)
	}
	raw := pub.Bytes() // 0x04 || X || Y
	coseKey, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:]})
	if err != nil {
		a.t.Fatal(err)
	}
	authData := a.authData(cred.rpID, 0x40, 0) // AT
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(cred.id)))
	authData = append(authData, cred.id...)
	authData = append(authData, coseKey...)

	attObj, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		a.t.Fatal(err)
	}
	return mustMarshal(a.t, map[string]any{
		"id":    b64.EncodeToString(cred.id),
		"rawId": b64.EncodeToString(cred.id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal", "hybrid"},
		},
		"clientExtensionResults": map[string]any{},
	})
}

// get answers a login Challenge with cred, or with the first credential the
// options allow if cred is nil. sendHandle controls whether the user handle
// is included, as it always is for discoverable credentials.
func (a *virtualAuthenticator) get(c *Challenge, cred *virtualCredential, sendHandle bool) []byte {
	a.t.Helper()
	var opts requestOptions
	mustUnmarshal(a.t, c.Options, &opts)
	if cred == nil {
		for _, ac := range opts.PublicKey.AllowCredentials {
			if cred = a.creds[ac.ID]; cred != nil {
				break
			}
		}
		if cred == nil {
			a.t.Fatal("virtual authenticator has no allowed credential")
		}
	}
	return a.assert(cred, opts.PublicKey.Challenge, opts.PublicKey.RPID, sendHandle)
}

func (a *virtualAuthenticator) assert(cred *virtualCredential, challenge, rpID string, sendHandle bool) []byte {
	a.t.Helper()
	clientData := a.clientData("webauthn.get", challenge)
	var count uint32
	if a.useCounter {
		a.counter++
		count = a.counter
	}
	authData := a.authData(rpID, 0, count)
	hash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(authData[:len(authData):len(authData)], hash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, cred.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	resp := map[string]any{
		"clientDataJSON":    b64.EncodeToString(clientData),
		"authenticatorData": b64.EncodeToString(authData),
		"signature":         b64.EncodeToString(sig),
	}
	if sendHandle {
		resp["userHandle"] = b64.EncodeToString(cred.handle)
	}
	return mustMarshal(a.t, map[string]any{
		"id":                     b64.EncodeToString(cred.id),
		"rawId":                  b64.EncodeToString(cred.id),
		"type":                   "public-key",
		"response":               resp,
		"clientExtensionResults": map[string]any{},
	})
}

func (a *virtualAuthenticator) clientData(typ, challenge string) []byte {
	return mustMarshal(a.t, map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
}

// authData returns rpIdHash || flags || signCount.
func (a *virtualAuthenticator) authData(rpID string, extraFlags byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	flags := byte(0x01) | extraFlags // UP
	if a.userVerified {
		flags |= 0x04
	}
	if a.backupEligible {
		flags |= 0x08
	}
	if a.backupState {
		flags |= 0x10
	}
	out := append(h[:], flags)
	return binary.BigEndian.AppendUint32(out, count)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustUnmarshal(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
}

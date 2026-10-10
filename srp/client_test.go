package srp

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
)

func TestClientNewVerifierDefaults(t *testing.T) {
	// A nil registration uses the defaults, including the full KDF cost.
	v, err := Client{}.NewVerifier([]byte("pw"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.Group != Group3072 || v.KDF != DefaultKDFParams() || len(v.Salt) != minSaltLength {
		t.Errorf("verifier = %d %+v salt %d", v.Group, v.KDF, len(v.Salt))
	}
}

func TestClientNewVerifier(t *testing.T) {
	salt := bytes.Repeat([]byte{3}, 20)
	reg := &Registration{Group: Group2048, KDF: testKDF, Salt: salt}
	v1, err := Client{}.NewVerifier([]byte("pw"), reg)
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := Client{}.NewVerifier([]byte("pw"), reg)
	if !bytes.Equal(v1.Value, v2.Value) {
		t.Error("same inputs gave different verifiers")
	}
	salt[0] = 9
	if v1.Salt[0] != 3 {
		t.Error("verifier aliases the registration's salt")
	}

	// A registration without a salt gets a random one.
	r1, _ := Client{}.NewVerifier([]byte("pw"), &Registration{Group: Group2048, KDF: testKDF})
	r2, _ := Client{}.NewVerifier([]byte("pw"), &Registration{Group: Group2048, KDF: testKDF})
	if len(r1.Salt) != minSaltLength || bytes.Equal(r1.Salt, r2.Salt) || bytes.Equal(r1.Value, r2.Value) {
		t.Error("random salts not used")
	}
}

func TestClientNewVerifierRejects(t *testing.T) {
	salt := make([]byte, 16)
	tests := map[string]struct {
		c   Client
		reg Registration
	}{
		"group":         {Client{}, Registration{Group: 1024, KDF: testKDF, Salt: salt}},
		"invalid kdf":   {Client{}, Registration{Group: Group2048, KDF: KDFParams{}, Salt: salt}},
		"over limits":   {Client{}, Registration{Group: Group2048, KDF: KDFParams{MemoryKiB: 1 << 30, Iterations: 1, Parallelism: 1}, Salt: salt}},
		"custom limits": {Client{KDFLimits: KDFParams{MemoryKiB: 32, Iterations: 1, Parallelism: 1}}, Registration{Group: Group2048, KDF: testKDF, Salt: salt}},
		"short salt":    {Client{}, Registration{Group: Group2048, KDF: testKDF, Salt: make([]byte, 8)}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := tt.c.NewVerifier([]byte("pw"), &tt.reg); !errors.Is(err, ErrInvalidVerifier) {
				t.Errorf("err = %v, want ErrInvalidVerifier", err)
			}
		})
	}
}

func TestClientLoginRejectsChallenge(t *testing.T) {
	p := groups[Group2048]
	good := func() Challenge {
		return Challenge{Group: Group2048, KDF: testKDF, Salt: make([]byte, 16), ServerPublic: p.pad(big.NewInt(12345))}
	}
	tests := map[string]struct {
		c      Client
		mutate func(*Challenge)
	}{
		"group":         {Client{}, func(ch *Challenge) { ch.Group = 1536 }},
		"invalid kdf":   {Client{}, func(ch *Challenge) { ch.KDF.Iterations = 0 }},
		"over default":  {Client{}, func(ch *Challenge) { ch.KDF.MemoryKiB = DefaultKDFLimits().MemoryKiB + 1 }},
		"over custom":   {Client{KDFLimits: KDFParams{MemoryKiB: 63, Iterations: 1, Parallelism: 1}}, func(*Challenge) {}},
		"no salt":       {Client{}, func(ch *Challenge) { ch.Salt = nil }},
		"B missing":     {Client{}, func(ch *Challenge) { ch.ServerPublic = nil }},
		"B zero":        {Client{}, func(ch *Challenge) { ch.ServerPublic = make([]byte, p.size) }},
		"B N":           {Client{}, func(ch *Challenge) { ch.ServerPublic = p.pad(p.n) }},
		"B wrong group": {Client{}, func(ch *Challenge) { ch.ServerPublic = groups[Group3072].pad(big.NewInt(5)) }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ch := good()
			tt.mutate(&ch)
			if _, err := tt.c.Login("alice", []byte("pw"), &ch); !errors.Is(err, ErrInvalidChallenge) {
				t.Errorf("err = %v, want ErrInvalidChallenge", err)
			}
		})
	}
	ch := good()
	if _, err := (Client{}).Login("alice", []byte("pw"), &ch); err != nil {
		t.Fatalf("baseline: %v", err)
	}
}

func TestClientLoginResponse(t *testing.T) {
	p := groups[Group2048]
	ch := &Challenge{Group: Group2048, KDF: testKDF, Salt: make([]byte, 16), ServerPublic: p.pad(big.NewInt(12345))}
	cl, err := Client{}.Login("alice", []byte("pw"), ch)
	if err != nil {
		t.Fatal(err)
	}
	r := cl.Response()
	if len(r.ClientPublic) != p.size || len(r.ClientProof) != 32 || r.SessionID != ch.SessionID {
		t.Errorf("response = %d-byte A, %d-byte M1", len(r.ClientPublic), len(r.ClientProof))
	}
	r.ClientProof[0] ^= 1
	if bytes.Equal(r.ClientProof, cl.Response().ClientProof) {
		t.Error("Response returned an alias of internal state")
	}

	// A fresh login uses a fresh A.
	cl2, _ := Client{}.Login("alice", []byte("pw"), ch)
	if bytes.Equal(cl2.Response().ClientPublic, cl.Response().ClientPublic) {
		t.Error("A reused")
	}

	if cl.SessionKey() != nil {
		t.Error("session key available before the server is verified")
	}
	if err := cl.VerifyServer(nil); !errors.Is(err, ErrInvalidServerProof) {
		t.Errorf("VerifyServer(nil) = %v", err)
	}
	if err := cl.VerifyServer(make([]byte, 32)); !errors.Is(err, ErrInvalidServerProof) {
		t.Errorf("VerifyServer(zeros) = %v", err)
	}
	if cl.SessionKey() != nil {
		t.Error("session key available after a failed verification")
	}
}

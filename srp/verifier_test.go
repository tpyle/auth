package srp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func TestKDFParamsValidate(t *testing.T) {
	tests := []struct {
		name string
		p    KDFParams
		ok   bool
	}{
		{"default", DefaultKDFParams(), true},
		{"limits", DefaultKDFLimits(), true},
		{"minimal", KDFParams{MemoryKiB: 8, Iterations: 1, Parallelism: 1}, true},
		{"no iterations", KDFParams{MemoryKiB: 64, Iterations: 0, Parallelism: 1}, false},
		{"no lanes", KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 0}, false},
		{"memory below 8 KiB per lane", KDFParams{MemoryKiB: 31, Iterations: 1, Parallelism: 4}, false},
		{"zero", KDFParams{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(); (err == nil) != tt.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestKDFParamsWithin(t *testing.T) {
	limits := KDFParams{MemoryKiB: 100, Iterations: 10, Parallelism: 4}
	tests := []struct {
		name string
		p    KDFParams
		ok   bool
	}{
		{"equal", limits, true},
		{"below", KDFParams{MemoryKiB: 8, Iterations: 1, Parallelism: 1}, true},
		{"memory", KDFParams{MemoryKiB: 101, Iterations: 1, Parallelism: 1}, false},
		{"iterations", KDFParams{MemoryKiB: 8, Iterations: 11, Parallelism: 1}, false},
		{"parallelism", KDFParams{MemoryKiB: 64, Iterations: 1, Parallelism: 5}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.within(limits); (err == nil) != tt.ok {
				t.Errorf("within() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestDeriveX(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, 16)
	x1 := deriveX([]byte("pw"), salt, testKDF)
	if x1.BitLen() > xLength*8 || x1.Sign() == 0 {
		t.Fatalf("x has %d bits", x1.BitLen())
	}
	if deriveX([]byte("pw"), salt, testKDF).Cmp(x1) != 0 {
		t.Error("not deterministic")
	}
	for name, x := range map[string]*big.Int{
		"password": deriveX([]byte("pW"), salt, testKDF),
		"salt":     deriveX([]byte("pw"), bytes.Repeat([]byte{2}, 16), testKDF),
		"params":   deriveX([]byte("pw"), salt, KDFParams{MemoryKiB: 64, Iterations: 2, Parallelism: 1}),
	} {
		if x.Cmp(x1) == 0 {
			t.Errorf("changing the %s did not change x", name)
		}
	}
}

func testVerifier(t *testing.T, g Group) *Verifier {
	t.Helper()
	v, err := Client{}.NewVerifier([]byte("pw"), &Registration{Group: g, KDF: testKDF, Salt: bytes.Repeat([]byte{7}, 16)})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifierRoundTrip(t *testing.T) {
	for _, g := range []Group{Group2048, Group3072, Group4096} {
		t.Run(g.String(), func(t *testing.T) {
			v := testVerifier(t, g)
			s := v.String()
			want := "$srp6a-sha256-argon2id$g=" + g.String() + ",m=64,t=1,p=1$BwcHBwcHBwcHBwcHBwcHBw$"
			if !strings.HasPrefix(s, want) {
				t.Fatalf("String() = %q, want prefix %q", s, want)
			}
			got, err := ParseVerifier(s)
			if err != nil {
				t.Fatalf("ParseVerifier: %v", err)
			}
			if got.Group != v.Group || got.KDF != v.KDF || !bytes.Equal(got.Salt, v.Salt) || !bytes.Equal(got.Value, v.Value) {
				t.Errorf("round trip changed the verifier: %+v != %+v", got, v)
			}
			if len(got.Value) != int(g)/8 {
				t.Errorf("value is %d bytes", len(got.Value))
			}
		})
	}
}

func TestParseVerifierRejects(t *testing.T) {
	v := testVerifier(t, Group2048)
	enc := base64.RawStdEncoding.EncodeToString
	salt, value := enc(v.Salt), enc(v.Value)
	p := groups[Group2048]
	build := func(params, salt, value string) string {
		return "$srp6a-sha256-argon2id$" + params + "$" + salt + "$" + value
	}
	const good = "g=2048,m=64,t=1,p=1"

	tests := map[string]string{
		"empty":             "",
		"no leading dollar": strings.TrimPrefix(v.String(), "$"),
		"too few fields":    "$srp6a-sha256-argon2id$" + good + "$" + salt,
		"too many fields":   v.String() + "$extra",
		"wrong scheme":      strings.Replace(v.String(), "srp6a-sha256-argon2id", "srp6a-sha1", 1),
		"argon2 hash":       "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + salt,
		"missing param":     build("g=2048,m=64,t=1", salt, value),
		"extra param":       build(good+",x=1", salt, value),
		"duplicate param":   build("g=2048,m=64,t=1,t=1", salt, value),
		"unknown param":     build("g=2048,m=64,t=1,q=1", salt, value),
		"param without =":   build("g=2048,m=64,t=1,p", salt, value),
		"non-numeric":       build("g=2048,m=lots,t=1,p=1", salt, value),
		"negative":          build("g=2048,m=-64,t=1,p=1", salt, value),
		"p over 255":        build("g=2048,m=64,t=1,p=256", salt, value),
		"m over uint32":     build("g=2048,m=4294967296,t=1,p=1", salt, value),
		"unsupported group": build("g=1024,m=64,t=1,p=1", salt, value),
		"invalid kdf":       build("g=2048,m=64,t=0,p=1", salt, value),
		"bad salt base64":   build(good, "!!", value),
		"padded salt":       build(good, salt+"==", value),
		"bad value base64":  build(good, salt, "!!"),
		"short salt":        build(good, enc(make([]byte, 15)), value),
		"long salt":         build(good, enc(make([]byte, 65)), value),
		"huge field":        build(good, salt, strings.Repeat("A", 1000)),
		"short value":       build(good, salt, enc(v.Value[1:])),
		"long value":        build(good, salt, enc(append([]byte{0}, v.Value...))),
		"value zero":        build(good, salt, enc(make([]byte, 256))),
		"value one":         build(good, salt, enc(p.pad(big.NewInt(1)))),
		"value N":           build(good, salt, enc(p.pad(p.n))),
		"value in 3072":     build("g=3072,m=64,t=1,p=1", salt, value),
	}
	for name, s := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseVerifier(s); !errors.Is(err, ErrInvalidVerifier) {
				t.Errorf("ParseVerifier(%.80q) = %v, want ErrInvalidVerifier", s, err)
			}
		})
	}
	// Sanity check that build makes valid strings.
	if _, err := ParseVerifier(build(good, salt, value)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
}

func TestParseVerifierAcceptsSaltLengths(t *testing.T) {
	for _, n := range []int{minSaltLength, 32, maxSaltLength} {
		v := testVerifier(t, Group2048)
		v.Salt = make([]byte, n)
		if _, err := ParseVerifier(v.String()); err != nil {
			t.Errorf("salt length %d: %v", n, err)
		}
	}
}

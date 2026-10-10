package srp

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // RFC 5054's test vectors use SHA-1.
	"math/big"
	"testing"
)

// The 1024-bit group of RFC 5054 Appendix A, used only by its test vectors.
const rfc5054Prime1024 = `
	EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
	9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
	8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
	7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
	FD5138FE 8376435B 9FC61D2F C0EB06E3`

// TestRFC5054Vectors checks the arithmetic against RFC 5054 Appendix B,
// which uses SHA-1, the 1024-bit group, and x = H(s | H(I | ":" | P))
// instead of Argon2id. Everything but x is shared with the real groups.
func TestRFC5054Vectors(t *testing.T) {
	p := newGroupParams(rfc5054Prime1024, 2, sha1.New)
	var (
		username = "alice"
		password = "password123"
		salt     = mustHex(t, "BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
		wantK    = mustHex(t, "7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")
		wantX    = mustHex(t, "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")
		wantV    = mustHex(t, `
			7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
			9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
			C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
			EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
			E955A5E2 9E7AB245 DB2BE315 E2099AFB`)
		a = mustHex(t, `
			60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD
			DA2D4393`)
		b = mustHex(t, `
			E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1
			05284D20`)
		wantA = mustHex(t, `
			61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
			4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
			8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
			BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
			B349EF5D 76988A36 72FAC47B 0769447B`)
		wantB = mustHex(t, `
			BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
			BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
			6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
			37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
			EB4012B7 D7665238 A8E3FB00 4B117B58`)
		wantU = mustHex(t, "CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019")
		wantS = mustHex(t, `
			B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
			233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
			41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
			3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
			C346D7E4 74B29EDE 8A469FFE CA686E5A`)
	)

	x := p.hashInt(salt, p.hash([]byte(username+":"+password)))
	v := p.verifier(x)
	A := p.clientPublic(a)
	B := p.serverPublic(v, b)
	u := p.scramble(A, B)
	for _, c := range []struct {
		name      string
		got, want *big.Int
	}{
		{"k", p.k, wantK},
		{"x", x, wantX},
		{"v", v, wantV},
		{"A", A, wantA},
		{"B", B, wantB},
		{"u", u, wantU},
		{"client S", p.clientSecret(B, x, a, u), wantS},
		{"server S", p.serverSecret(A, v, u, b), wantS},
	} {
		if c.got.Cmp(c.want) != 0 {
			t.Errorf("%s = %X, want %X", c.name, c.got, c.want)
		}
	}
}

// TestGroups checks that each N is a safe prime of the stated size and g
// generates the whole multiplicative group, as RFC 5054 requires.
func TestGroups(t *testing.T) {
	for g, p := range groups {
		t.Run(g.String(), func(t *testing.T) {
			if p.n.BitLen() != int(g) {
				t.Errorf("N has %d bits, want %d", p.n.BitLen(), int(g))
			}
			if p.size*8 != int(g) {
				t.Errorf("size = %d bytes", p.size)
			}
			if !p.n.ProbablyPrime(20) {
				t.Fatal("N is not prime")
			}
			q := new(big.Int).Rsh(p.n, 1) // (N-1)/2, as N is odd
			if !q.ProbablyPrime(20) {
				t.Fatal("(N-1)/2 is not prime")
			}
			// The group has order 2q, so g generates it unless its order is
			// 1, 2 or q; g^q = -1 rules all of those out.
			nMinus1 := new(big.Int).Sub(p.n, big.NewInt(1))
			if new(big.Int).Exp(p.g, q, p.n).Cmp(nMinus1) != 0 {
				t.Error("g is not a primitive root")
			}
			if len(p.nxorg) != 32 || p.k.Sign() == 0 {
				t.Error("derived constants not set")
			}
		})
	}
}

func TestGroupString(t *testing.T) {
	if s := Group3072.String(); s != "3072" {
		t.Errorf("String = %q", s)
	}
	if Group(1024).valid() || !Group4096.valid() {
		t.Error("valid() wrong")
	}
}

func TestNewGroupParamsPanicsOnBadPrime(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	newGroupParams("not hex", 2, sha1.New)
}

// TestSharedSecret runs the arithmetic with random values in every group.
func TestSharedSecret(t *testing.T) {
	for g, p := range groups {
		t.Run(g.String(), func(t *testing.T) {
			for range 3 {
				x, a, b := randomExponent(), randomExponent(), randomExponent()
				v := p.verifier(x)
				A, B := p.clientPublic(a), p.serverPublic(v, b)
				u := p.scramble(A, B)
				cs, ss := p.clientSecret(B, x, a, u), p.serverSecret(A, v, u, b)
				if cs.Cmp(ss) != 0 {
					t.Fatal("client and server secrets differ")
				}
				// A wrong password gives a different secret.
				wrong := p.clientSecret(B, new(big.Int).Add(x, big.NewInt(1)), a, u)
				if wrong.Cmp(ss) == 0 {
					t.Fatal("wrong x produced the same secret")
				}
			}
		})
	}
}

func TestDecodePublic(t *testing.T) {
	p := groups[Group2048]
	nMinus1 := new(big.Int).Sub(p.n, big.NewInt(1))
	tests := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"one", []byte{1}, true},
		{"padded one", p.pad(big.NewInt(1)), true},
		{"N-1", p.pad(nMinus1), true},
		{"empty", nil, false},
		{"zero", []byte{0}, false},
		{"padded zero", make([]byte, p.size), false},
		{"N", p.pad(p.n), false},
		{"all ones", bytes.Repeat([]byte{0xff}, p.size), false},
		{"too long", append([]byte{0}, p.pad(big.NewInt(5))...), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := p.decodePublic(tt.in); ok != tt.ok {
				t.Errorf("decodePublic ok = %v, want %v", ok, tt.ok)
			}
		})
	}
}

func TestPad(t *testing.T) {
	p := groups[Group2048]
	got := p.pad(big.NewInt(0x0102))
	if len(got) != 256 || got[254] != 1 || got[255] != 2 || !bytes.Equal(got[:254], make([]byte, 254)) {
		t.Errorf("pad = %x", got)
	}
}

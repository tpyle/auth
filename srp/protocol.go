package srp

import (
	"crypto/rand"
	"math/big"
)

// This file holds the SRP-6a arithmetic, written with the RFC 5054 names.
// H is the group's hash, PAD left-pads to the length of N, and | is
// concatenation:
//
//	k  = H(N | PAD(g))
//	x  = Argon2id(P, s)                      (see deriveX)
//	v  = g^x % N
//	A  = g^a % N
//	B  = (k*v + g^b) % N
//	u  = H(PAD(A) | PAD(B))
//	S  = (B - k*g^x)^(a + u*x) % N           (client)
//	S  = (A * v^u)^b % N                     (server)
//	K  = H(PAD(S))
//	M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K)
//	M2 = H(PAD(A) | M1 | K)
//
// math/big is not constant-time. The long-term secrets (x on the client, v
// on the server) only ever appear combined with fresh random values, but
// see the package documentation.

// exponentBytes is the size of the random private values a and b. RFC 5054
// requires at least 256 bits.
const exponentBytes = 32

// pad returns x as a big-endian byte string of the length of N.
func (p *groupParams) pad(x *big.Int) []byte {
	return x.FillBytes(make([]byte, p.size))
}

func (p *groupParams) hash(parts ...[]byte) []byte {
	h := p.newHash()
	for _, b := range parts {
		h.Write(b)
	}
	return h.Sum(nil)
}

func (p *groupParams) hashInt(parts ...[]byte) *big.Int {
	return new(big.Int).SetBytes(p.hash(parts...))
}

// validPublic reports whether x is a usable public value: 0 < x < N. A value
// of 0 mod N would force the shared secret to a known value, and values of N
// or more are rejected rather than reduced so each value has one encoding.
func (p *groupParams) validPublic(x *big.Int) bool {
	return x.Sign() > 0 && x.Cmp(p.n) < 0
}

// decodePublic parses a public value received from the other party.
func (p *groupParams) decodePublic(b []byte) (*big.Int, bool) {
	if len(b) == 0 || len(b) > p.size {
		return nil, false
	}
	x := new(big.Int).SetBytes(b)
	return x, p.validPublic(x)
}

// randomExponent returns a random private value a or b.
func randomExponent() *big.Int {
	b := make([]byte, exponentBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails.
	return new(big.Int).SetBytes(b)
}

func (p *groupParams) verifier(x *big.Int) *big.Int {
	return new(big.Int).Exp(p.g, x, p.n)
}

func (p *groupParams) clientPublic(a *big.Int) *big.Int {
	return new(big.Int).Exp(p.g, a, p.n)
}

func (p *groupParams) serverPublic(v, b *big.Int) *big.Int {
	kv := new(big.Int).Mul(p.k, v)
	gb := new(big.Int).Exp(p.g, b, p.n)
	return kv.Add(kv, gb).Mod(kv, p.n)
}

// scramble computes u.
func (p *groupParams) scramble(A, B *big.Int) *big.Int {
	return p.hashInt(p.pad(A), p.pad(B))
}

func (p *groupParams) clientSecret(B, x, a, u *big.Int) *big.Int {
	base := new(big.Int).Exp(p.g, x, p.n)
	base.Mul(base, p.k)
	base.Sub(B, base).Mod(base, p.n) // Mod is Euclidean, so never negative
	exp := new(big.Int).Mul(u, x)
	exp.Add(exp, a)
	return base.Exp(base, exp, p.n)
}

func (p *groupParams) serverSecret(A, v, u, b *big.Int) *big.Int {
	base := new(big.Int).Exp(v, u, p.n)
	base.Mul(base, A).Mod(base, p.n)
	return base.Exp(base, b, p.n)
}

// sessionKey computes K.
func (p *groupParams) sessionKey(S *big.Int) []byte {
	return p.hash(p.pad(S))
}

// clientProof computes M1.
func (p *groupParams) clientProof(username string, salt []byte, A, B *big.Int, K []byte) []byte {
	return p.hash(p.nxorg, p.hash([]byte(username)), salt, p.pad(A), p.pad(B), K)
}

// serverProof computes M2.
func (p *groupParams) serverProof(A *big.Int, m1, K []byte) []byte {
	return p.hash(p.pad(A), m1, K)
}

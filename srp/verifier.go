package srp

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KDFParams sets the cost of the Argon2id function that turns a password
// into the SRP private key x. They are stored in each [Verifier] and sent
// to the client with every [Challenge], so they can be changed without
// locking anyone out.
type KDFParams struct {
	// MemoryKiB is the memory cost in KiB.
	MemoryKiB uint32 `json:"m" mapstructure:"memory_kib"`
	// Iterations is the time cost (number of passes over memory).
	Iterations uint32 `json:"t" mapstructure:"iterations"`
	// Parallelism is the number of lanes. Browsers usually compute lanes one
	// after another, so it does not make a web client faster.
	Parallelism uint8 `json:"p" mapstructure:"parallelism"`
}

// DefaultKDFParams returns the second recommended configuration from
// RFC 9106 §4, as used for passwords by [github.com/tpyle/auth/v2]: 64 MiB
// of memory, 3 iterations and 4 lanes.
func DefaultKDFParams() KDFParams {
	return KDFParams{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4}
}

// DefaultKDFLimits returns the largest parameters accepted by default: 256
// MiB of memory, 16 iterations and 255 lanes. Servers reject stored
// verifiers over the limits, and clients reject challenges over them, so a
// malicious server cannot make a client exhaust its memory.
func DefaultKDFLimits() KDFParams {
	return KDFParams{MemoryKiB: 256 * 1024, Iterations: 16, Parallelism: 255}
}

// Validate reports whether p is usable: at least one iteration and lane,
// and at least 8 KiB of memory per lane.
func (p KDFParams) Validate() error {
	switch {
	case p.Iterations < 1:
		return fmt.Errorf("srp: argon2 iterations must be at least 1")
	case p.Parallelism < 1:
		return fmt.Errorf("srp: argon2 parallelism must be at least 1")
	case p.MemoryKiB < 8*uint32(p.Parallelism):
		return fmt.Errorf("srp: argon2 memory must be at least 8 KiB per lane")
	}
	return nil
}

// within reports an error if any field of p exceeds the same field of limits.
func (p KDFParams) within(limits KDFParams) error {
	switch {
	case p.MemoryKiB > limits.MemoryKiB:
		return fmt.Errorf("argon2 memory %d KiB exceeds limit %d KiB", p.MemoryKiB, limits.MemoryKiB)
	case p.Iterations > limits.Iterations:
		return fmt.Errorf("argon2 iterations %d exceed limit %d", p.Iterations, limits.Iterations)
	case p.Parallelism > limits.Parallelism:
		return fmt.Errorf("argon2 parallelism %d exceeds limit %d", p.Parallelism, limits.Parallelism)
	}
	return nil
}

// xLength is the length of the Argon2id output used as x.
const xLength = 32

// deriveX computes x = Argon2id(password, salt) as an integer.
func deriveX(password, salt []byte, p KDFParams) *big.Int {
	return new(big.Int).SetBytes(argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, xLength))
}

// Limits on salt lengths.
const (
	minSaltLength = 16
	maxSaltLength = 64
)

// verifierScheme identifies the encoding produced by [Verifier.String].
const verifierScheme = "srp6a-sha256-argon2id"

// Verifier is what the server stores instead of a password. It cannot be
// used to log in, but like a password hash it allows offline guessing of
// the password, so keep it as private as one.
type Verifier struct {
	// Group is the group v was computed in.
	Group Group
	// KDF is the cost of deriving x from the password.
	KDF KDFParams
	// Salt is the Argon2id salt, 16 to 64 random bytes.
	Salt []byte
	// Value is v = g^x mod N, big-endian and left-padded with zeros to the
	// length of N.
	Value []byte
}

// String encodes the verifier in a PHC-like format for storage in a single
// text column, with the salt and value in unpadded standard base64:
//
//	$srp6a-sha256-argon2id$g=<Group>,m=<MemoryKiB>,t=<Iterations>,p=<Parallelism>$<salt>$<value>
//
// Decode it with [ParseVerifier].
func (v *Verifier) String() string {
	return fmt.Sprintf("$%s$g=%d,m=%d,t=%d,p=%d$%s$%s", verifierScheme,
		int(v.Group), v.KDF.MemoryKiB, v.KDF.Iterations, v.KDF.Parallelism,
		base64.RawStdEncoding.EncodeToString(v.Salt),
		base64.RawStdEncoding.EncodeToString(v.Value))
}

// validate checks that v is well formed. It does not check KDF limits.
func (v *Verifier) validate() error {
	p, ok := groups[v.Group]
	if !ok {
		return fmt.Errorf("unsupported group %d", int(v.Group))
	}
	if err := v.KDF.Validate(); err != nil {
		return err
	}
	if len(v.Salt) < minSaltLength || len(v.Salt) > maxSaltLength {
		return fmt.Errorf("salt must be %d to %d bytes, not %d", minSaltLength, maxSaltLength, len(v.Salt))
	}
	if len(v.Value) != p.size {
		return fmt.Errorf("value must be %d bytes, not %d", p.size, len(v.Value))
	}
	// v = 1 would mean x = 0, which anyone could compute.
	if val := new(big.Int).SetBytes(v.Value); val.Cmp(big.NewInt(1)) <= 0 || val.Cmp(p.n) >= 0 {
		return fmt.Errorf("value is out of range")
	}
	return nil
}

// ParseVerifier decodes a verifier encoded by [Verifier.String]. It returns
// an error wrapping [ErrInvalidVerifier] if s is malformed, uses an
// unsupported group, or has a value outside the group.
func ParseVerifier(s string) (*Verifier, error) {
	invalid := func(format string, args ...any) (*Verifier, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{ErrInvalidVerifier}, args...)...)
	}
	// SplitN bounds the allocation; a sixth element means too many fields.
	parts := strings.SplitN(s, "$", 6)
	if len(parts) != 5 || parts[0] != "" {
		return invalid("expected 4 '$'-separated fields")
	}
	if parts[1] != verifierScheme {
		return invalid("unsupported scheme %q", parts[1])
	}

	v := &Verifier{}
	seen := map[string]bool{}
	for _, kv := range strings.SplitN(parts[2], ",", 5) {
		key, val, ok := strings.Cut(kv, "=")
		if !ok || seen[key] {
			return invalid("malformed parameter %q", kv)
		}
		seen[key] = true
		bits := 32
		if key == "p" {
			bits = 8
		}
		n, err := strconv.ParseUint(val, 10, bits)
		if err != nil {
			return invalid("bad value for parameter %q", key)
		}
		switch key {
		case "g":
			v.Group = Group(n)
		case "m":
			v.KDF.MemoryKiB = uint32(n)
		case "t":
			v.KDF.Iterations = uint32(n)
		case "p":
			v.KDF.Parallelism = uint8(n)
		default:
			return invalid("unknown parameter %q", key)
		}
	}
	if len(seen) != 4 {
		return invalid("expected g, m, t and p parameters")
	}

	// The largest field is a 4096-bit value; refuse anything bigger before
	// decoding it.
	for _, field := range parts[3:] {
		if base64.RawStdEncoding.DecodedLen(len(field)) > 512 {
			return invalid("salt or value too long")
		}
	}
	var err error
	if v.Salt, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil {
		return invalid("bad salt encoding")
	}
	if v.Value, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return invalid("bad value encoding")
	}
	if err := v.validate(); err != nil {
		return invalid("%v", err)
	}
	return v, nil
}

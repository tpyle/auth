package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params controls the cost of Argon2id password hashing.
//
// The parameters used to create a hash are stored in the hash itself, so
// changing them does not break existing passwords. Use [NeedsRehash] to find
// hashes that should be upgraded.
type Argon2Params struct {
	// MemoryKiB is the memory cost in KiB. Each concurrent hash allocates
	// this much memory.
	MemoryKiB uint32 `mapstructure:"memory_kib"`
	// Iterations is the time cost (number of passes over memory).
	Iterations uint32 `mapstructure:"iterations"`
	// Parallelism is the number of lanes (threads) used per hash.
	Parallelism uint8 `mapstructure:"parallelism"`
	// SaltLength is the length of the random salt in bytes.
	SaltLength uint32 `mapstructure:"salt_length"`
	// KeyLength is the length of the derived hash in bytes.
	KeyLength uint32 `mapstructure:"key_length"`
}

// Lower bounds enforced by [Argon2Params.Validate].
const (
	minSaltLength = 8
	minKeyLength  = 16
)

// DefaultArgon2Params returns the second recommended configuration from
// RFC 9106 §4: 64 MiB of memory, 3 iterations and 4 lanes, with a 16-byte
// salt and a 32-byte hash.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Validate reports whether p is usable. Memory must be at least
// 8 KiB per lane, the salt at least 8 bytes and the hash at least 16 bytes.
func (p Argon2Params) Validate() error {
	switch {
	case p.Iterations < 1:
		return fmt.Errorf("auth: argon2 iterations must be at least 1")
	case p.Parallelism < 1:
		return fmt.Errorf("auth: argon2 parallelism must be at least 1")
	case p.MemoryKiB < 8*uint32(p.Parallelism):
		return fmt.Errorf("auth: argon2 memory must be at least 8 KiB per lane")
	case p.SaltLength < minSaltLength:
		return fmt.Errorf("auth: argon2 salt length must be at least %d bytes", minSaltLength)
	case p.KeyLength < minKeyLength:
		return fmt.Errorf("auth: argon2 key length must be at least %d bytes", minKeyLength)
	}
	return nil
}

// HashPassword hashes password with Argon2id and returns it as a PHC string:
//
//	$argon2id$v=19$m=<MemoryKiB>,t=<Iterations>,p=<Parallelism>$<salt>$<hash>
//
// Salt and hash are unpadded standard base64.
func HashPassword(password []byte, p Argon2Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generating salt: %w", err)
	}
	hash := argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLength)
	return encodePHC(p, salt, hash), nil
}

// VerifyPassword reports whether password matches the PHC-encoded Argon2id
// hash. The comparison is constant-time. The cost parameters are read from the
// hash, not from the current configuration. A malformed hash returns an error
// wrapping [ErrInvalidHash].
func VerifyPassword(password []byte, encodedHash string) (bool, error) {
	p, salt, hash, err := decodePHC(encodedHash)
	if err != nil {
		return false, err
	}
	computed := argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLength)
	return subtle.ConstantTimeCompare(hash, computed) == 1, nil
}

// NeedsRehash reports whether encodedHash was created with parameters other
// than p, in which case the password should be re-hashed with p the next time
// the plaintext is available (for example on a successful login).
func NeedsRehash(encodedHash string, p Argon2Params) (bool, error) {
	old, _, _, err := decodePHC(encodedHash)
	if err != nil {
		return false, err
	}
	return old != p, nil
}

func encodePHC(p Argon2Params, salt, hash []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// decodePHC parses an Argon2id PHC string. The returned params have
// SaltLength and KeyLength set from the decoded salt and hash.
func decodePHC(s string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	invalid := func(format string, args ...any) (Argon2Params, []byte, []byte, error) {
		return p, nil, nil, fmt.Errorf("%w: "+format, append([]any{ErrInvalidHash}, args...)...)
	}

	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" {
		return invalid("expected 5 '$'-separated fields")
	}
	if parts[1] != "argon2id" {
		return invalid("unsupported algorithm %q", parts[1])
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return invalid("unsupported version %q", parts[2])
	}

	seen := map[string]bool{}
	for _, kv := range strings.Split(parts[3], ",") {
		key, val, ok := strings.Cut(kv, "=")
		if !ok || seen[key] {
			return invalid("malformed parameter %q", kv)
		}
		seen[key] = true
		switch key {
		case "m":
			n, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return invalid("bad memory %q", val)
			}
			p.MemoryKiB = uint32(n)
		case "t":
			n, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return invalid("bad iterations %q", val)
			}
			p.Iterations = uint32(n)
		case "p":
			n, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				return invalid("bad parallelism %q", val)
			}
			p.Parallelism = uint8(n)
		default:
			return invalid("unknown parameter %q", key)
		}
	}
	if len(seen) != 3 {
		return invalid("expected m, t and p parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return invalid("bad salt encoding")
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return invalid("bad hash encoding")
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(hash))

	if err := p.Validate(); err != nil {
		return invalid("%v", err)
	}
	return p, salt, hash, nil
}

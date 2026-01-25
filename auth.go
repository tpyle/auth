package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type Authorizer struct {
	Options           *Options
	currentSigningKey *currentSigningKey
}

type currentSigningKey struct {
	ID         uuid.UUID
	PrivateKey *ecdsa.PrivateKey
}

type KeyPairWithCreationTime struct {
	ID           uuid.UUID
	PublicKey    *ecdsa.PublicKey
	CreationTime time.Time
}

func Create(opts ...Option) *Authorizer {
	options := getDefaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	return &Authorizer{
		Options:           options,
		currentSigningKey: nil,
	}
}

func (a *Authorizer) generateSalt() ([]byte, error) {
	salt := make([]byte, a.Options.SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func (a *Authorizer) getHash(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, a.Options.HashTime, a.Options.HashMemoryKiB, a.Options.HashThreads, a.Options.KeyLength)
}

func (a *Authorizer) Login(username string, password []byte) (bool, error) {
	hashedPassword, err := a.Options.LookupUserPasswordFunc(username)
	if err != nil {
		return false, err
	}

	// Parse PHC format
	salt, storedHash, err := a.parsePhcString(hashedPassword)
	if err != nil {
		return false, err
	}

	// Hash the input password with the extracted salt
	inputHash := a.getHash(password, salt)
	if subtle.ConstantTimeCompare(storedHash, inputHash) != 1 {
		return false, nil
	}

	return true, nil
}

func (a *Authorizer) HashPassword(password []byte) (string, error) {
	salt, err := a.generateSalt()
	if err != nil {
		return "", err
	}

	hash := a.getHash(password, salt)

	// Create PHC format string
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		a.Options.HashMemoryKiB,
		a.Options.HashTime,
		a.Options.HashThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func (a *Authorizer) parsePhcString(phcString string) ([]byte, []byte, error) {
	parts := strings.Split(phcString, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, fmt.Errorf("invalid PHC string format")
	}

	// Parse parameters (parts[3])
	paramStr := parts[3]
	params := strings.Split(paramStr, ",")
	if len(params) != 3 {
		return nil, nil, fmt.Errorf("invalid parameter format")
	}

	// Extract salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid hash encoding: %w", err)
	}

	return salt, hash, nil
}

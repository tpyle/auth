package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func (kp *KeyPairWithCreationTime) GetPublicKeyAsBinary() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return pubKeyBytes, nil
}

func GetECDSAPublicKeyFromBinary(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an ECDSA public key")
	}

	return pubKey, nil
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

func (a *Authorizer) LoginWithRefreshToken(tokenString string) (string, bool, error) {
	if a.Options.LookupRefreshTokenFunc == nil {
		return "", false, fmt.Errorf("lookup refresh token function is not set, cannot use refresh tokens")
	}

	tok, err := a.VerifyToken(tokenString)
	if err != nil {
		return "", false, fmt.Errorf("failed to verify refresh token: %w", err)
	}

	if !tok.Valid {
		return "", false, nil
	}

	// Type assertion to get the claims
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", false, fmt.Errorf("invalid token claims")
	}

	tokenId, err := getClaimAsString(claims, "id")
	if err != nil {
		return "", false, err
	}

	tuuid, err := uuid.Parse(tokenId)
	if err != nil {
		return "", false, fmt.Errorf("invalid UUID in token claims: %w", err)
	}

	refreshToken, err := a.Options.LookupRefreshTokenFunc(tuuid)
	if err != nil {
		return "", false, fmt.Errorf("failed to get refresh token: %w", err)
	}

	rand, err := getClaimAsString(claims, "rand")
	if err != nil {
		return "", false, err
	}

	randBytes, err := base64.RawStdEncoding.DecodeString(rand)
	if err != nil {
		return "", false, fmt.Errorf("invalid base64 encoding in rand claim: %w", err)
	}

	if subtle.ConstantTimeCompare(refreshToken.Rand, randBytes) != 1 {
		return "", false, fmt.Errorf("refresh token mismatch")
	}

	sub, err := getClaimAsString(claims, "sub")
	if err != nil {
		return "", false, err
	}

	return sub, true, nil
}

func (a *Authorizer) LoginAndGetJWT(username string, password []byte, claims map[string]any) (string, error) {
	ok, err := a.Login(username, password)
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("invalid username or password")
	}

	jwtToken, err := a.CreateJWT(username, claims)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT: %w", err)
	}

	return jwtToken, nil
}

func (a *Authorizer) LoginWithRefreshTokenAndGetJWT(tokenString string, claims map[string]any) (string, error) {
	sub, ok, err := a.LoginWithRefreshToken(tokenString)
	if err != nil {
		return "", fmt.Errorf("login with refresh token failed: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("invalid refresh token")
	}

	_, err = a.VerifyToken(tokenString)
	if err != nil {
		return "", fmt.Errorf("failed to verify refresh token: %w", err)
	}

	jwtToken, err := a.CreateJWT(sub, claims)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT: %w", err)
	}

	return jwtToken, nil
}

func (a *Authorizer) LoginAndGetJWTWithRefreshToken(username string, password []byte, claims map[string]any) (string, string, error) {
	ok, err := a.Login(username, password)
	if err != nil {
		return "", "", fmt.Errorf("login failed: %w", err)
	}
	if !ok {
		return "", "", fmt.Errorf("invalid username or password")
	}

	jwtToken, err := a.CreateJWT(username, claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to create JWT: %w", err)
	}

	refreshToken, err := a.CreateRefreshToken(username)
	if err != nil {
		return "", "", fmt.Errorf("failed to create refresh token: %w", err)
	}

	return jwtToken, refreshToken, nil
}

func (a *Authorizer) Logout(refreshTokenString string) error {
	if a.Options.DeleteRefreshTokenFunc == nil {
		return fmt.Errorf("delete refresh token function is not set, cannot delete refresh tokens")
	}

	tok, err := a.VerifyToken(refreshTokenString)
	if err != nil {
		return fmt.Errorf("failed to verify refresh token: %w", err)
	}

	// Type assertion to get the claims
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	tokenId, err := getClaimAsString(claims, "id")
	if err != nil {
		return err
	}

	tuuid, err := uuid.Parse(tokenId)
	if err != nil {
		return fmt.Errorf("invalid UUID in token claims: %w", err)
	}

	err = a.Options.DeleteRefreshTokenFunc(tuuid)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
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

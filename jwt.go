package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type RefreshToken struct {
	ID      uuid.UUID
	Rand    []byte
	Subject string `json:"sub"`
}

func (r *RefreshToken) ToMapClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"id":   r.ID.String(),
		"rand": base64.RawStdEncoding.EncodeToString(r.Rand),
		"sub":  r.Subject,
	}
}

func (a *Authorizer) generateNewKey() error {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate new signing key: %w", err)
	}

	keyPair := &KeyPairWithCreationTime{
		ID:           uuid.New(),
		PublicKey:    &newKey.PublicKey,
		CreationTime: time.Now(),
	}

	err = a.Options.StoreNewSigningKeyFunc(keyPair)
	if err != nil {
		return fmt.Errorf("failed to store new signing key: %w", err)
	}

	return nil
}

func (a *Authorizer) cleanupExpiredKeys() error {
	keys, err := a.Options.GetSigningKeysFunc()
	if err != nil {
		return fmt.Errorf("failed to get signing keys for expiration check: %w", err)
	}

	now := time.Now()
	if a.Options.DeleteExpiredSigningKeysFunc != nil {
		var expiredKeys []uuid.UUID
		for _, key := range keys {
			if now.Sub(key.CreationTime) > a.Options.SigningKeyValidity {
				expiredKeys = append(expiredKeys, key.ID)
			}
		}
		if len(expiredKeys) > 0 {
			err = a.Options.DeleteExpiredSigningKeysFunc(expiredKeys)
			if err != nil {
				return fmt.Errorf("failed to delete expired signing keys: %w", err)
			}
		}
	} else {
		for _, key := range keys {
			if now.Sub(key.CreationTime) > a.Options.SigningKeyValidity {
				err = a.Options.DeleteExpiredSigningKeyFunc(key.ID)
				if err != nil {
					return fmt.Errorf("failed to delete expired signing key with ID %s: %w", key.ID.String(), err)
				}
			}
		}
	}

	return nil
}

func (a *Authorizer) Initialize() error {
	if a.Options.SigningKeyCreationFreq > 0 {
		ticker := time.NewTicker(a.Options.SigningKeyCreationFreq)
		go func() {
			for range ticker.C {
				a.generateNewKey()
			}
		}()
	}
	if a.Options.GetSigningKeysFunc != nil && a.Options.SigningKeyValidity > 0 {
		if a.Options.DeleteExpiredSigningKeyFunc != nil || a.Options.DeleteExpiredSigningKeysFunc != nil {
			ticker := time.NewTicker(a.Options.SigningKeyValidity)
			go func() {
				for range ticker.C {
					a.cleanupExpiredKeys()
				}
			}()
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	a.currentSigningKey = &currentSigningKey{
		ID:         uuid.New(),
		PrivateKey: key,
	}

	if a.Options.StoreNewSigningKeyFunc != nil {
		keyPair := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			PublicKey:    &a.currentSigningKey.PrivateKey.PublicKey,
			CreationTime: time.Now(),
		}

		err = a.Options.StoreNewSigningKeyFunc(keyPair)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *Authorizer) CreateJWT(sub string, claims map[string]any) (string, error) {
	jwtClaims := jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(a.Options.ExpirationTime).Unix(),
		"kid": a.currentSigningKey.ID.String(),
	}

	for k, v := range claims {
		if k == "sub" || k == "iat" || k == "exp" {
			continue
		}
		jwtClaims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)
	signedToken, err := token.SignedString(a.currentSigningKey.PrivateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (a *Authorizer) CreateRefreshToken(sub string) (string, error) {
	if a.Options.StoreRefreshTokenFunc == nil {
		return "", fmt.Errorf("store refresh token function is not set, cannot create refresh tokens")
	}

	randBytes := make([]byte, a.Options.RefreshTokenLength)
	_, err := rand.Read(randBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes for refresh token: %w", err)
	}

	tok := &RefreshToken{
		ID:      uuid.New(),
		Rand:    randBytes,
		Subject: sub,
	}

	claims := tok.ToMapClaims()

	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(a.Options.RefreshTokenExpirationTime).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := token.SignedString(a.currentSigningKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	err = a.Options.StoreRefreshTokenFunc(tok)
	if err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return signedToken, nil
}

func getClaimAsString(claims jwt.MapClaims, key string) (string, error) {
	val, ok := claims[key]
	if !ok {
		return "", fmt.Errorf("claim %s not found", key)
	}
	strVal, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("claim %s is not a string", key)
	}
	return strVal, nil
}

type AuthorizerToken jwt.Token

func (t *AuthorizerToken) IsValid() bool {
	return t.Valid
}

func (a *Authorizer) KeyFunc(token *jwt.Token) (interface{}, error) {
	if a.Options.GetSigningKeyFunc == nil {
		return &a.currentSigningKey.PrivateKey.PublicKey, nil
	} else {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		kuuid, err := uuid.Parse(kid)
		if err != nil {
			return nil, fmt.Errorf("invalid kid in token header: %w", err)
		}

		return a.Options.GetSigningKeyFunc(&kuuid)
	}
}

func (a *Authorizer) VerifyToken(tokenString string) (*AuthorizerToken, error) {
	tok, err := jwt.Parse(tokenString, a.KeyFunc)
	if err != nil {
		return nil, err
	}
	return (*AuthorizerToken)(tok), nil
}

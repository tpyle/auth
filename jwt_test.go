package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Test for Initialize
func TestInitialize(t *testing.T) {
	t.Run("basic initialization", func(t *testing.T) {
		auth := Create()

		err := auth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		if auth.currentSigningKey == nil {
			t.Error("currentSigningKey should be set after initialization")
		}

		if auth.currentSigningKey.PrivateKey == nil {
			t.Error("Private key should be set after initialization")
		}
	})

	t.Run("with key storage", func(t *testing.T) {
		keyStore := newMockKeyStore()
		auth := Create(
			WithStoreNewSigningKeyFunc(keyStore.storeKey),
		)

		err := auth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		if len(keyStore.keysList) == 0 {
			t.Error("Key should be stored in key store")
		}
	})
}

// Test for CreateJWT
func TestCreateJWT(t *testing.T) {
	auth := Create(WithExpirationTime(time.Hour))
	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("create basic JWT", func(t *testing.T) {
		tokenString, err := auth.CreateJWT("user123", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		if tokenString == "" {
			t.Error("Token string should not be empty")
		}

		// Parse the token to verify its contents
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return &auth.currentSigningKey.PrivateKey.PublicKey, nil
		})

		if err != nil {
			t.Fatalf("Failed to parse generated token: %v", err)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("Failed to get claims from token")
		}

		if claims["sub"] != "user123" {
			t.Errorf("Expected sub 'user123', got %v", claims["sub"])
		}

		if claims["kid"] != auth.currentSigningKey.ID.String() {
			t.Errorf("Expected kid %s, got %v", auth.currentSigningKey.ID.String(), claims["kid"])
		}

		// Check expiration
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			expectedExp := time.Now().Add(time.Hour)
			if expTime.Before(expectedExp.Add(-time.Minute)) || expTime.After(expectedExp.Add(time.Minute)) {
				t.Errorf("Expiration time seems wrong: %v", expTime)
			}
		} else {
			t.Error("exp claim should be present and numeric")
		}
	})

	t.Run("create JWT with custom claims", func(t *testing.T) {
		customClaims := map[string]interface{}{
			"role":    "admin",
			"company": "test_corp",
			"level":   42,
		}

		tokenString, err := auth.CreateJWT("user456", customClaims)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return &auth.currentSigningKey.PrivateKey.PublicKey, nil
		})

		if err != nil {
			t.Fatalf("Failed to parse generated token: %v", err)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("Failed to get claims from token")
		}

		if claims["sub"] != "user456" {
			t.Errorf("Expected sub 'user456', got %v", claims["sub"])
		}

		if claims["role"] != "admin" {
			t.Errorf("Expected role 'admin', got %v", claims["role"])
		}

		if claims["company"] != "test_corp" {
			t.Errorf("Expected company 'test_corp', got %v", claims["company"])
		}

		if claims["level"] != float64(42) {
			t.Errorf("Expected level 42, got %v", claims["level"])
		}
	})

	t.Run("reserved claims are not overwritten", func(t *testing.T) {
		customClaims := map[string]interface{}{
			"sub":  "should_be_ignored",
			"iat":  "should_be_ignored",
			"exp":  "should_be_ignored",
			"role": "admin",
		}

		tokenString, err := auth.CreateJWT("actual_user", customClaims)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return &auth.currentSigningKey.PrivateKey.PublicKey, nil
		})

		if err != nil {
			t.Fatalf("Failed to parse generated token: %v", err)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("Failed to get claims from token")
		}

		// Should use the sub from function parameter, not from custom claims
		if claims["sub"] != "actual_user" {
			t.Errorf("Expected sub 'actual_user', got %v", claims["sub"])
		}

		// Custom claims should still be present
		if claims["role"] != "admin" {
			t.Errorf("Expected role 'admin', got %v", claims["role"])
		}
	})
}

// Test for CreateRefreshToken
func TestCreateRefreshToken(t *testing.T) {
	refreshStore := newMockRefreshTokenStore()

	auth := Create(
		WithExpirationTime(time.Hour),
		WithRefreshTokenExpirationTime(24*time.Hour),
		WithRefreshTokenLength(256),
		WithStoreRefreshTokenFunc(refreshStore.store),
	)

	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("create basic refresh token", func(t *testing.T) {
		tokenString, err := auth.CreateRefreshToken("user123")
		if err != nil {
			t.Fatalf("CreateRefreshToken() failed: %v", err)
		}

		if tokenString == "" {
			t.Error("Token string should not be empty")
		}

		// Parse the token to verify its contents
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return &auth.currentSigningKey.PrivateKey.PublicKey, nil
		})

		if err != nil {
			t.Fatalf("Failed to parse generated refresh token: %v", err)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("Failed to get claims from token")
		}

		if claims["sub"] != "user123" {
			t.Errorf("Expected sub 'user123', got %v", claims["sub"])
		}

		// Check for id claim
		if _, ok := claims["id"]; !ok {
			t.Error("Expected id claim to be present")
		}

		// Check for rand claim
		if _, ok := claims["rand"]; !ok {
			t.Error("Expected rand claim to be present")
		}

		// Check expiration
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			expectedExp := time.Now().Add(24 * time.Hour)
			if expTime.Before(expectedExp.Add(-time.Minute)) || expTime.After(expectedExp.Add(time.Minute)) {
				t.Errorf("Expiration time seems wrong: %v", expTime)
			}
		} else {
			t.Error("exp claim should be present and numeric")
		}

		// Verify token was stored
		if len(refreshStore.tokens) != 1 {
			t.Errorf("Expected 1 refresh token in store, got %d", len(refreshStore.tokens))
		}
	})

	t.Run("refresh token randomness", func(t *testing.T) {
		// Clear the store
		refreshStore.tokens = make(map[uuid.UUID]*RefreshToken)

		token1, err := auth.CreateRefreshToken("user1")
		if err != nil {
			t.Fatalf("CreateRefreshToken() failed: %v", err)
		}

		token2, err := auth.CreateRefreshToken("user2")
		if err != nil {
			t.Fatalf("CreateRefreshToken() failed: %v", err)
		}

		// Tokens should be different
		if token1 == token2 {
			t.Error("Refresh tokens should be unique")
		}

		// Verify both were stored with different IDs
		if len(refreshStore.tokens) != 2 {
			t.Errorf("Expected 2 refresh tokens in store, got %d", len(refreshStore.tokens))
		}

		// Check that random bytes are different
		var tokens []*RefreshToken
		for _, tok := range refreshStore.tokens {
			tokens = append(tokens, tok)
		}

		if len(tokens[0].Rand) != 256 {
			t.Errorf("Expected random bytes length 256, got %d", len(tokens[0].Rand))
		}

		// Check that random bytes are actually different (statistically very unlikely to be same)
		if string(tokens[0].Rand) == string(tokens[1].Rand) {
			t.Error("Random bytes should be different between tokens")
		}
	})

	t.Run("create refresh token without store function", func(t *testing.T) {
		authNoStore := Create(WithExpirationTime(time.Hour))
		err := authNoStore.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		_, err = authNoStore.CreateRefreshToken("user123")
		if err == nil {
			t.Error("CreateRefreshToken() should fail when StoreRefreshTokenFunc is not set")
		}
	})
}

// Test for getClaimAsString
func TestGetClaimAsString(t *testing.T) {
	t.Run("valid string claim", func(t *testing.T) {
		claims := jwt.MapClaims{
			"username": "testuser",
		}

		val, err := getClaimAsString(claims, "username")
		if err != nil {
			t.Fatalf("getClaimAsString() failed: %v", err)
		}

		if val != "testuser" {
			t.Errorf("Expected 'testuser', got '%s'", val)
		}
	})

	t.Run("missing claim", func(t *testing.T) {
		claims := jwt.MapClaims{}

		_, err := getClaimAsString(claims, "username")
		if err == nil {
			t.Error("getClaimAsString() should fail for missing claim")
		}
	})

	t.Run("non-string claim", func(t *testing.T) {
		claims := jwt.MapClaims{
			"count": 42,
		}

		_, err := getClaimAsString(claims, "count")
		if err == nil {
			t.Error("getClaimAsString() should fail for non-string claim")
		}
	})
}

// Test for RefreshToken.ToMapClaims
func TestRefreshTokenToMapClaims(t *testing.T) {
	randBytes := []byte("test_random_bytes_12345678901234")
	refreshToken := &RefreshToken{
		ID:   uuid.New(),
		Rand: randBytes,
	}

	claims := refreshToken.ToMapClaims()

	if claims["id"] != refreshToken.ID.String() {
		t.Errorf("Expected id '%s', got '%v'", refreshToken.ID.String(), claims["id"])
	}

	// Note: ToMapClaims uses base64.RawStdEncoding
	expectedRand := "dGVzdF9yYW5kb21fYnl0ZXNfMTIzNDU2Nzg5MDEyMzQ"
	if claims["rand"] != expectedRand {
		t.Errorf("Expected rand '%s', got '%v'", expectedRand, claims["rand"])
	}
}

// Test for VerifyToken
func TestVerifyToken(t *testing.T) {
	auth := Create(WithExpirationTime(time.Hour))
	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("verify valid token", func(t *testing.T) {
		tokenString, err := auth.CreateJWT("user123", map[string]interface{}{"role": "admin"})
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		token, err := auth.VerifyToken(tokenString)
		if err != nil {
			t.Fatalf("VerifyToken() failed: %v", err)
		}

		if !token.IsValid() {
			t.Error("Token should be valid")
		}

		claims, ok := (*jwt.Token)(token).Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("Failed to get claims from token")
		}

		if claims["sub"] != "user123" {
			t.Errorf("Expected sub 'user123', got %v", claims["sub"])
		}

		if claims["role"] != "admin" {
			t.Errorf("Expected role 'admin', got %v", claims["role"])
		}
	})

	t.Run("verify invalid token", func(t *testing.T) {
		invalidTokens := []string{
			"",
			"invalid.token.string",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.invalid",
		}

		for _, tokenString := range invalidTokens {
			_, err := auth.VerifyToken(tokenString)
			if err == nil {
				t.Errorf("VerifyToken() should have failed for token: %s", tokenString)
			}
		}
	})

	t.Run("verify expired token", func(t *testing.T) {
		// Create authorizer with very short expiration
		shortAuth := Create(WithExpirationTime(time.Millisecond * 10))
		err := shortAuth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		tokenString, err := shortAuth.CreateJWT("user123", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		// Wait for token to expire
		time.Sleep(time.Millisecond * 50)

		_, err = shortAuth.VerifyToken(tokenString)
		if err == nil {
			t.Error("VerifyToken() should have failed for expired token")
		}
	})
}

// Test for KeyFunc
func TestKeyFunc(t *testing.T) {
	t.Run("without key store", func(t *testing.T) {
		auth := Create()
		err := auth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		token := &jwt.Token{
			Header: map[string]interface{}{
				"kid": auth.currentSigningKey.ID.String(),
			},
		}

		key, err := auth.KeyFunc(token)
		if err != nil {
			t.Fatalf("KeyFunc() failed: %v", err)
		}

		expectedKey := &auth.currentSigningKey.PrivateKey.PublicKey
		if key != expectedKey {
			t.Error("KeyFunc() returned wrong key")
		}
	})

	t.Run("with key store", func(t *testing.T) {
		// Generate a test key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}

		keyID := uuid.New()
		testKey := &KeyPairWithCreationTime{
			ID:           keyID,
			PublicKey:    &privateKey.PublicKey,
			CreationTime: time.Now(),
		}

		keyStore := newMockKeyStore()
		keyStore.storeKey(testKey)

		auth := Create(
			WithGetSigningKeyFunc(keyStore.getKey),
		)

		token := &jwt.Token{
			Header: map[string]interface{}{
				"kid": keyID.String(),
			},
		}

		keys, err := auth.KeyFunc(token)
		if err != nil {
			t.Fatalf("KeyFunc() failed: %v", err)
		}

		keyList, ok := keys.([]KeyPairWithCreationTime)
		if !ok {
			t.Fatal("Expected []KeyPairWithCreationTime from KeyFunc")
		}

		if len(keyList) != 1 {
			t.Fatalf("Expected 1 key, got %d", len(keyList))
		}

		if keyList[0].ID != keyID {
			t.Errorf("Expected key ID %s, got %s", keyID.String(), keyList[0].ID.String())
		}
	})

	t.Run("missing kid header", func(t *testing.T) {
		keyStore := newMockKeyStore()
		auth := Create(
			WithGetSigningKeyFunc(keyStore.getKey),
		)

		token := &jwt.Token{
			Header: map[string]interface{}{},
		}

		_, err := auth.KeyFunc(token)
		if err == nil {
			t.Error("KeyFunc() should have failed for missing kid header")
		}
	})

	t.Run("invalid kid format", func(t *testing.T) {
		keyStore := newMockKeyStore()
		auth := Create(
			WithGetSigningKeyFunc(keyStore.getKey),
		)

		token := &jwt.Token{
			Header: map[string]interface{}{
				"kid": "invalid-uuid-format",
			},
		}

		_, err := auth.KeyFunc(token)
		if err == nil {
			t.Error("KeyFunc() should have failed for invalid kid format")
		}
	})
}

// Test for AuthorizerToken IsValid
func TestAuthorizerTokenIsValid(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		jwtToken := &jwt.Token{Valid: true}
		authToken := (*AuthorizerToken)(jwtToken)

		if !authToken.IsValid() {
			t.Error("IsValid() should return true for valid token")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		jwtToken := &jwt.Token{Valid: false}
		authToken := (*AuthorizerToken)(jwtToken)

		if authToken.IsValid() {
			t.Error("IsValid() should return false for invalid token")
		}
	})
}

// Test for generateNewKey
func TestGenerateNewKey(t *testing.T) {
	t.Run("successful key generation", func(t *testing.T) {
		keyStore := newMockKeyStore()
		auth := Create(
			WithStoreNewSigningKeyFunc(keyStore.storeKey),
		)

		err := auth.generateNewKey()
		if err != nil {
			t.Fatalf("generateNewKey() failed: %v", err)
		}

		if len(keyStore.keysList) != 1 {
			t.Errorf("Expected 1 key in store, got %d", len(keyStore.keysList))
		}

		key := keyStore.keysList[0]
		if key.PublicKey == nil {
			t.Error("Public key should not be nil")
		}

		if key.ID == uuid.Nil {
			t.Error("Key ID should not be nil")
		}
	})

	t.Run("store key error", func(t *testing.T) {
		failingStore := func(*KeyPairWithCreationTime) error {
			return fmt.Errorf("store failed")
		}

		auth := Create(
			WithStoreNewSigningKeyFunc(failingStore),
		)

		err := auth.generateNewKey()
		if err == nil {
			t.Error("generateNewKey() should have failed when store fails")
		}
	})
}

// Test for cleanupExpiredKeys
func TestCleanupExpiredKeys(t *testing.T) {
	t.Run("cleanup with individual delete function", func(t *testing.T) {
		keyStore := newMockKeyStore()

		// Test with a simple case first: 2 expired keys, 1 valid key
		now := time.Now()
		validity := time.Hour * 24

		expiredKey1 := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			CreationTime: now.Add(-validity - time.Hour), // 25h ago (expired)
		}
		expiredKey2 := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			CreationTime: now.Add(-validity - time.Hour*2), // 26h ago (expired)
		}
		validKey := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			CreationTime: now.Add(-validity + time.Hour), // 23h ago (valid)
		}

		keyStore.storeKey(expiredKey1)
		keyStore.storeKey(expiredKey2)
		keyStore.storeKey(validKey)

		auth := Create(
			WithSigningKeyValidity(validity),
			WithGetSigningKeysFunc(keyStore.getKeys),
			WithDeleteExpiredSigningKeyFunc(keyStore.deleteKey),
		)

		// Verify that DeleteExpiredSigningKeysFunc is nil
		if auth.Options.DeleteExpiredSigningKeysFunc != nil {
			t.Fatal("DeleteExpiredSigningKeysFunc should be nil")
		}

		// Verify initial state
		if len(keyStore.keysList) != 3 {
			t.Fatalf("Expected 3 initial keys, got %d", len(keyStore.keysList))
		}

		err := auth.cleanupExpiredKeys()
		if err != nil {
			t.Fatalf("cleanupExpiredKeys() failed: %v", err)
		}

		// Should have only the valid key remaining
		if len(keyStore.keysList) != 1 {
			t.Errorf("Expected 1 key remaining, got %d", len(keyStore.keysList))
		}

		if len(keyStore.keysList) > 0 && keyStore.keysList[0].ID != validKey.ID {
			t.Errorf("Wrong key remained. Expected %s, got %s",
				validKey.ID.String()[:8], keyStore.keysList[0].ID.String()[:8])
		}
	})

	t.Run("cleanup with batch delete function", func(t *testing.T) {
		now := time.Now()
		keyStore := newMockKeyStore()

		// Add some keys - some expired, some not
		expiredKey1 := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			CreationTime: now.Add(-time.Hour * 25),
		}
		expiredKey2 := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			CreationTime: now.Add(-time.Hour * 26),
		}
		validKey := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			CreationTime: now.Add(-time.Hour * 23),
		}

		keyStore.storeKey(expiredKey1)
		keyStore.storeKey(expiredKey2)
		keyStore.storeKey(validKey)

		auth := Create(
			WithSigningKeyValidity(time.Hour*24),
			WithGetSigningKeysFunc(keyStore.getKeys),
			WithDeleteExpiredSigningKeysFunc(keyStore.deleteKeys),
		)

		err := auth.cleanupExpiredKeys()
		if err != nil {
			t.Fatalf("cleanupExpiredKeys() failed: %v", err)
		}

		// Should have only the valid key remaining
		if len(keyStore.keysList) != 1 {
			t.Errorf("Expected 1 key remaining, got %d", len(keyStore.keysList))
		}

		if keyStore.keysList[0].ID != validKey.ID {
			t.Error("Wrong key remained after cleanup")
		}
	})

	t.Run("no expired keys", func(t *testing.T) {
		now := time.Now()
		keyStore := newMockKeyStore()

		validKey := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			CreationTime: now.Add(-time.Hour * 23),
		}

		keyStore.storeKey(validKey)

		auth := Create(
			WithSigningKeyValidity(time.Hour*24),
			WithGetSigningKeysFunc(keyStore.getKeys),
			WithDeleteExpiredSigningKeyFunc(keyStore.deleteKey),
		)

		err := auth.cleanupExpiredKeys()
		if err != nil {
			t.Fatalf("cleanupExpiredKeys() failed: %v", err)
		}

		// Should still have the valid key
		if len(keyStore.keysList) != 1 {
			t.Errorf("Expected 1 key remaining, got %d", len(keyStore.keysList))
		}
	})

	t.Run("get keys error", func(t *testing.T) {
		failingGetKeys := func() ([]*KeyPairWithCreationTime, error) {
			return nil, fmt.Errorf("get keys failed")
		}

		auth := Create(
			WithSigningKeyValidity(time.Hour*24),
			WithGetSigningKeysFunc(failingGetKeys),
			WithDeleteExpiredSigningKeyFunc(func(uuid.UUID) error { return nil }),
		)

		err := auth.cleanupExpiredKeys()
		if err == nil {
			t.Error("cleanupExpiredKeys() should have failed when get keys fails")
		}
	})
}

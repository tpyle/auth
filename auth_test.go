package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Test helper functions and mock data
type mockUserStore map[string]string

func (m mockUserStore) lookupUser(username string) (string, error) {
	if password, ok := m[username]; ok {
		return password, nil
	}
	return "", fmt.Errorf("user not found")
}

type mockKeyStore struct {
	keys     map[uuid.UUID]*KeyPairWithCreationTime
	keysList []*KeyPairWithCreationTime
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{
		keys:     make(map[uuid.UUID]*KeyPairWithCreationTime),
		keysList: make([]*KeyPairWithCreationTime, 0),
	}
}

func (m *mockKeyStore) storeKey(key *KeyPairWithCreationTime) error {
	m.keys[key.ID] = key
	m.keysList = append(m.keysList, key)
	return nil
}

func (m *mockKeyStore) getKey(kid *uuid.UUID) ([]KeyPairWithCreationTime, error) {
	if key, ok := m.keys[*kid]; ok {
		return []KeyPairWithCreationTime{*key}, nil
	}
	return nil, fmt.Errorf("key not found")
}

func (m *mockKeyStore) getKeys() ([]*KeyPairWithCreationTime, error) {
	// Return a copy to avoid modification during iteration
	result := make([]*KeyPairWithCreationTime, len(m.keysList))
	copy(result, m.keysList)
	return result, nil
}

func (m *mockKeyStore) deleteKey(kid uuid.UUID) error {
	if _, ok := m.keys[kid]; ok {
		delete(m.keys, kid)
		// Remove from keysList
		for i, key := range m.keysList {
			if key.ID == kid {
				m.keysList = append(m.keysList[:i], m.keysList[i+1:]...)
				break
			}
		}
		return nil
	}
	return fmt.Errorf("key not found")
}

func (m *mockKeyStore) deleteKeys(kids []uuid.UUID) error {
	for _, kid := range kids {
		if err := m.deleteKey(kid); err != nil {
			return err
		}
	}
	return nil
}

// Test for Create function
func TestCreate(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		auth := Create()

		if auth == nil {
			t.Fatal("Create() returned nil")
		}

		if auth.Options == nil {
			t.Fatal("Options is nil")
		}

		// Verify default options
		if auth.Options.SaltLength != 16 {
			t.Errorf("Expected SaltLength 16, got %d", auth.Options.SaltLength)
		}

		if auth.Options.HashTime != 4 {
			t.Errorf("Expected HashTime 4, got %d", auth.Options.HashTime)
		}

		if auth.Options.HashMemoryKiB != 128*1024 {
			t.Errorf("Expected HashMemoryKiB %d, got %d", 128*1024, auth.Options.HashMemoryKiB)
		}

		if auth.Options.HashThreads != 4 {
			t.Errorf("Expected HashThreads 4, got %d", auth.Options.HashThreads)
		}

		if auth.Options.KeyLength != 32 {
			t.Errorf("Expected KeyLength 32, got %d", auth.Options.KeyLength)
		}

		if auth.Options.ExpirationTime != time.Minute*15 {
			t.Errorf("Expected ExpirationTime 15m, got %v", auth.Options.ExpirationTime)
		}

		if auth.Options.AuthHeader == nil || *auth.Options.AuthHeader != "Authorization" {
			t.Errorf("Expected AuthHeader 'Authorization', got %v", auth.Options.AuthHeader)
		}

		if auth.Options.AuthCookie != nil {
			t.Errorf("Expected AuthCookie nil, got %v", auth.Options.AuthCookie)
		}
	})

	t.Run("with custom options", func(t *testing.T) {
		userStore := make(mockUserStore)
		keyStore := newMockKeyStore()

		auth := Create(
			WithSaltLength(32),
			WithHashTime(2),
			WithHashMemoryKiB(64*1024),
			WithHashThreads(2),
			WithKeyLength(16),
			WithExpirationTime(time.Hour*12),
			WithSigningKeyValidity(time.Hour*48),
			WithSigningKeyCreationFreq(time.Hour*24),
			WithAuthHeader(stringP("X-Auth-Token")),
			WithAuthCookie(stringP("auth_token")),
			WithLookupUserPasswordFunc(userStore.lookupUser),
			WithStoreNewSigningKeyFunc(keyStore.storeKey),
			WithGetSigningKeyFunc(keyStore.getKey),
			WithGetSigningKeysFunc(keyStore.getKeys),
			WithDeleteExpiredSigningKeyFunc(keyStore.deleteKey),
			WithDeleteExpiredSigningKeysFunc(keyStore.deleteKeys),
		)

		if auth.Options.SaltLength != 32 {
			t.Errorf("Expected SaltLength 32, got %d", auth.Options.SaltLength)
		}

		if auth.Options.HashTime != 2 {
			t.Errorf("Expected HashTime 2, got %d", auth.Options.HashTime)
		}

		if *auth.Options.AuthHeader != "X-Auth-Token" {
			t.Errorf("Expected AuthHeader 'X-Auth-Token', got %s", *auth.Options.AuthHeader)
		}

		if *auth.Options.AuthCookie != "auth_token" {
			t.Errorf("Expected AuthCookie 'auth_token', got %s", *auth.Options.AuthCookie)
		}
	})
}

// Test for HashPassword and Login
func TestPasswordHashing(t *testing.T) {
	auth := Create()

	password := []byte("test_password_123!")

	t.Run("hash password", func(t *testing.T) {
		hashedPassword, err := auth.HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword() failed: %v", err)
		}

		if !strings.HasPrefix(hashedPassword, "$argon2id$v=19$m=") {
			t.Errorf("Hashed password doesn't have expected format: %s", hashedPassword)
		}

		// Verify it contains all PHC components
		parts := strings.Split(hashedPassword, "$")
		if len(parts) != 6 {
			t.Errorf("Expected 6 parts in PHC string, got %d", len(parts))
		}

		if parts[1] != "argon2id" {
			t.Errorf("Expected 'argon2id', got '%s'", parts[1])
		}

		if parts[2] != "v=19" {
			t.Errorf("Expected 'v=19', got '%s'", parts[2])
		}
	})

	t.Run("login with correct password", func(t *testing.T) {
		hashedPassword, _ := auth.HashPassword(password)

		userStore := mockUserStore{
			"testuser": hashedPassword,
		}

		auth.Options.LookupUserPasswordFunc = userStore.lookupUser

		success, err := auth.Login("testuser", password)
		if err != nil {
			t.Fatalf("Login() failed: %v", err)
		}

		if !success {
			t.Error("Login should have succeeded with correct password")
		}
	})

	t.Run("login with incorrect password", func(t *testing.T) {
		hashedPassword, _ := auth.HashPassword(password)

		userStore := mockUserStore{
			"testuser": hashedPassword,
		}

		auth.Options.LookupUserPasswordFunc = userStore.lookupUser

		success, err := auth.Login("testuser", []byte("wrong_password"))
		if err != nil {
			t.Fatalf("Login() failed: %v", err)
		}

		if success {
			t.Error("Login should have failed with incorrect password")
		}
	})

	t.Run("login with non-existent user", func(t *testing.T) {
		userStore := mockUserStore{}
		auth.Options.LookupUserPasswordFunc = userStore.lookupUser

		success, err := auth.Login("nonexistent", password)
		if err == nil {
			t.Error("Login() should have failed for non-existent user")
		}

		if success {
			t.Error("Login should not succeed for non-existent user")
		}
	})
}

// Test for LoginAndGetJWT
func TestLoginAndGetJWT(t *testing.T) {
	password := []byte("testpassword123")
	auth := Create(WithExpirationTime(time.Hour))

	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	userStore := mockUserStore{
		"testuser": hashedPassword,
	}

	auth.Options.LookupUserPasswordFunc = userStore.lookupUser

	t.Run("successful login and jwt creation", func(t *testing.T) {
		token, err := auth.LoginAndGetJWT("testuser", password, map[string]any{
			"role": "admin",
		})
		if err != nil {
			t.Fatalf("LoginAndGetJWT() failed: %v", err)
		}

		if token == "" {
			t.Error("Token should not be empty")
		}

		// Verify the token
		parsedToken, err := auth.VerifyToken(token)
		if err != nil {
			t.Fatalf("VerifyToken() failed: %v", err)
		}

		if !parsedToken.Valid {
			t.Error("Token should be valid")
		}
	})

	t.Run("failed login with wrong password", func(t *testing.T) {
		_, err := auth.LoginAndGetJWT("testuser", []byte("wrongpassword"), nil)
		if err == nil {
			t.Error("LoginAndGetJWT() should fail with wrong password")
		}
	})

	t.Run("failed login with non-existent user", func(t *testing.T) {
		_, err := auth.LoginAndGetJWT("nonexistent", password, nil)
		if err == nil {
			t.Error("LoginAndGetJWT() should fail with non-existent user")
		}
	})
}

// Mock refresh token store
type mockRefreshTokenStore struct {
	tokens map[uuid.UUID]*RefreshToken
}

func newMockRefreshTokenStore() *mockRefreshTokenStore {
	return &mockRefreshTokenStore{
		tokens: make(map[uuid.UUID]*RefreshToken),
	}
}

func (m *mockRefreshTokenStore) store(token *RefreshToken) error {
	m.tokens[token.ID] = token
	return nil
}

func (m *mockRefreshTokenStore) lookup(id uuid.UUID) (*RefreshToken, error) {
	if token, ok := m.tokens[id]; ok {
		return token, nil
	}
	return nil, fmt.Errorf("refresh token not found")
}

func (m *mockRefreshTokenStore) delete(id uuid.UUID) error {
	if _, ok := m.tokens[id]; ok {
		delete(m.tokens, id)
		return nil
	}
	return fmt.Errorf("refresh token not found")
}

// Test for LoginAndGetJWTWithRefreshToken
func TestLoginAndGetJWTWithRefreshToken(t *testing.T) {
	password := []byte("testpassword123")
	refreshStore := newMockRefreshTokenStore()

	auth := Create(
		WithExpirationTime(time.Hour),
		WithRefreshTokenExpirationTime(24*time.Hour),
		WithRefreshTokenLength(256),
		WithStoreRefreshTokenFunc(refreshStore.store),
		WithLookupRefreshTokenFunc(refreshStore.lookup),
		WithDeleteRefreshTokenFunc(refreshStore.delete),
	)

	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	userStore := mockUserStore{
		"testuser": hashedPassword,
	}

	auth.Options.LookupUserPasswordFunc = userStore.lookupUser

	t.Run("successful login with refresh token", func(t *testing.T) {
		jwtToken, refreshToken, err := auth.LoginAndGetJWTWithRefreshToken(
			"testuser",
			password,
			map[string]any{"role": "admin"},
		)
		if err != nil {
			t.Fatalf("LoginAndGetJWTWithRefreshToken() failed: %v", err)
		}

		if jwtToken == "" {
			t.Error("JWT token should not be empty")
		}

		if refreshToken == "" {
			t.Error("Refresh token should not be empty")
		}

		// Verify the JWT token
		parsedToken, err := auth.VerifyToken(jwtToken)
		if err != nil {
			t.Fatalf("VerifyToken() failed: %v", err)
		}

		if !parsedToken.Valid {
			t.Error("JWT token should be valid")
		}

		// Verify the refresh token
		parsedRefreshToken, err := auth.VerifyToken(refreshToken)
		if err != nil {
			t.Fatalf("VerifyToken() failed for refresh token: %v", err)
		}

		if !parsedRefreshToken.Valid {
			t.Error("Refresh token should be valid")
		}

		// Check that refresh token was stored
		if len(refreshStore.tokens) != 1 {
			t.Errorf("Expected 1 refresh token in store, got %d", len(refreshStore.tokens))
		}
	})

	t.Run("failed login with wrong password", func(t *testing.T) {
		_, _, err := auth.LoginAndGetJWTWithRefreshToken("testuser", []byte("wrongpassword"), nil)
		if err == nil {
			t.Error("LoginAndGetJWTWithRefreshToken() should fail with wrong password")
		}
	})
}

// Test for LoginWithRefreshToken
func TestLoginWithRefreshToken(t *testing.T) {
	refreshStore := newMockRefreshTokenStore()

	auth := Create(
		WithExpirationTime(time.Hour),
		WithRefreshTokenExpirationTime(24*time.Hour),
		WithRefreshTokenLength(256),
		WithStoreRefreshTokenFunc(refreshStore.store),
		WithLookupRefreshTokenFunc(refreshStore.lookup),
	)

	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("successful login with valid refresh token", func(t *testing.T) {
		// Create a refresh token
		refreshToken, err := auth.CreateRefreshToken("testuser")
		if err != nil {
			t.Fatalf("CreateRefreshToken() failed: %v", err)
		}

		// Login with the refresh token
		sub, valid, err := auth.LoginWithRefreshToken(refreshToken)
		if err != nil {
			t.Fatalf("LoginWithRefreshToken() failed: %v", err)
		}

		if !valid {
			t.Error("Login should be valid")
		}

		if sub != "testuser" {
			t.Errorf("Expected sub 'testuser', got '%s'", sub)
		}
	})

	t.Run("login with invalid refresh token", func(t *testing.T) {
		_, valid, err := auth.LoginWithRefreshToken("invalid.token.string")
		if err == nil {
			t.Error("LoginWithRefreshToken() should fail with invalid token")
		}

		if valid {
			t.Error("Login should not be valid")
		}
	})

	t.Run("login without refresh token function configured", func(t *testing.T) {
		authNoRefresh := Create()
		err := authNoRefresh.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		_, _, err = authNoRefresh.LoginWithRefreshToken("any.token.string")
		if err == nil {
			t.Error("LoginWithRefreshToken() should fail when LookupRefreshTokenFunc is not set")
		}
	})
}

// Test for LoginWithRefreshTokenAndGetJWT
func TestLoginWithRefreshTokenAndGetJWT(t *testing.T) {
	refreshStore := newMockRefreshTokenStore()

	auth := Create(
		WithExpirationTime(time.Hour),
		WithRefreshTokenExpirationTime(24*time.Hour),
		WithRefreshTokenLength(256),
		WithStoreRefreshTokenFunc(refreshStore.store),
		WithLookupRefreshTokenFunc(refreshStore.lookup),
	)

	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("successful jwt creation from refresh token", func(t *testing.T) {
		// Create a refresh token
		refreshToken, err := auth.CreateRefreshToken("testuser")
		if err != nil {
			t.Fatalf("CreateRefreshToken() failed: %v", err)
		}

		// Get new JWT using refresh token
		newJWT, err := auth.LoginWithRefreshTokenAndGetJWT(
			refreshToken,
			map[string]any{"role": "user"},
		)
		if err != nil {
			t.Fatalf("LoginWithRefreshTokenAndGetJWT() failed: %v", err)
		}

		if newJWT == "" {
			t.Error("New JWT should not be empty")
		}

		// Verify the new JWT
		parsedToken, err := auth.VerifyToken(newJWT)
		if err != nil {
			t.Fatalf("VerifyToken() failed: %v", err)
		}

		if !parsedToken.Valid {
			t.Error("New JWT should be valid")
		}
	})

	t.Run("failed jwt creation with invalid refresh token", func(t *testing.T) {
		_, err := auth.LoginWithRefreshTokenAndGetJWT("invalid.token.string", nil)
		if err == nil {
			t.Error("LoginWithRefreshTokenAndGetJWT() should fail with invalid token")
		}
	})
}

// Test for Logout
func TestLogout(t *testing.T) {
	refreshStore := newMockRefreshTokenStore()

	auth := Create(
		WithExpirationTime(time.Hour),
		WithRefreshTokenExpirationTime(24*time.Hour),
		WithRefreshTokenLength(256),
		WithStoreRefreshTokenFunc(refreshStore.store),
		WithLookupRefreshTokenFunc(refreshStore.lookup),
		WithDeleteRefreshTokenFunc(refreshStore.delete),
	)

	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("successful logout", func(t *testing.T) {
		// Create a refresh token
		refreshToken, err := auth.CreateRefreshToken("testuser")
		if err != nil {
			t.Fatalf("CreateRefreshToken() failed: %v", err)
		}

		// Verify token was stored
		if len(refreshStore.tokens) != 1 {
			t.Errorf("Expected 1 refresh token in store, got %d", len(refreshStore.tokens))
		}

		// Logout (delete refresh token)
		err = auth.Logout(refreshToken)
		if err != nil {
			t.Fatalf("Logout() failed: %v", err)
		}

		// Verify token was deleted
		if len(refreshStore.tokens) != 0 {
			t.Errorf("Expected 0 refresh tokens in store after logout, got %d", len(refreshStore.tokens))
		}
	})

	t.Run("logout with invalid token", func(t *testing.T) {
		err := auth.Logout("invalid.token.string")
		if err == nil {
			t.Error("Logout() should fail with invalid token")
		}
	})

	t.Run("logout without delete function configured", func(t *testing.T) {
		authNoDelete := Create(
			WithStoreRefreshTokenFunc(refreshStore.store),
			WithLookupRefreshTokenFunc(refreshStore.lookup),
		)
		err := authNoDelete.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		// Create a token
		refreshToken, err := authNoDelete.CreateRefreshToken("testuser")
		if err != nil {
			t.Fatalf("CreateRefreshToken() failed: %v", err)
		}

		err = authNoDelete.Logout(refreshToken)
		if err == nil {
			t.Error("Logout() should fail when DeleteRefreshTokenFunc is not set")
		}
	})
}

// Test for parsePhcString
func TestParsePhcString(t *testing.T) {
	auth := Create()

	t.Run("valid PHC string", func(t *testing.T) {
		salt := []byte("testsalt12345678")
		hash := []byte("testhash12345678901234567890123")

		phcString := fmt.Sprintf("$argon2id$v=19$m=131072,t=4,p=4$%s$%s",
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(hash),
		)

		parsedSalt, parsedHash, err := auth.parsePhcString(phcString)
		if err != nil {
			t.Fatalf("parsePhcString() failed: %v", err)
		}

		if string(parsedSalt) != string(salt) {
			t.Errorf("Salt mismatch: expected %s, got %s", salt, parsedSalt)
		}

		if string(parsedHash) != string(hash) {
			t.Errorf("Hash mismatch: expected %s, got %s", hash, parsedHash)
		}
	})

	t.Run("invalid PHC string formats", func(t *testing.T) {
		testCases := []string{
			"",
			"invalid",
			"$argon2$v=19$m=131072,t=4,p=4$dGVzdA$dGVzdA",  // wrong algorithm
			"$argon2id$v=19$m=131072,t=4$dGVzdA$dGVzdA",    // wrong parameter count
			"argon2id$v=19$m=131072,t=4,p=4$dGVzdA$dGVzdA", // missing leading $
			"$argon2id$v=19$m=131072,t=4,p=4$!@#$%$dGVzdA", // invalid base64 salt
			"$argon2id$v=19$m=131072,t=4,p=4$dGVzdA$!@#$%", // invalid base64 hash
		}

		for _, tc := range testCases {
			_, _, err := auth.parsePhcString(tc)
			if err == nil {
				t.Errorf("parsePhcString() should have failed for: %s", tc)
			}
		}
	})
}

// TestGetPublicKeyAsBinary tests the GetPublicKeyAsBinary method
func TestGetPublicKeyAsBinary(t *testing.T) {
	t.Run("valid ECDSA public key", func(t *testing.T) {
		// Generate a test key pair
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		kp := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			PublicKey:    &privateKey.PublicKey,
			CreationTime: time.Now(),
		}

		// Convert to binary
		pubKeyBytes, err := kp.GetPublicKeyAsBinary()
		if err != nil {
			t.Fatalf("GetPublicKeyAsBinary() failed: %v", err)
		}

		// Verify the result is not empty
		if len(pubKeyBytes) == 0 {
			t.Error("GetPublicKeyAsBinary() returned empty byte slice")
		}

		// Verify we can parse it back
		parsedKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			t.Fatalf("Failed to parse marshaled public key: %v", err)
		}

		// Verify it's an ECDSA key
		parsedECDSAKey, ok := parsedKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Parsed key is not an ECDSA public key")
		}

		// Verify the key matches
		if parsedECDSAKey.X.Cmp(kp.PublicKey.X) != 0 || parsedECDSAKey.Y.Cmp(kp.PublicKey.Y) != 0 {
			t.Error("Parsed key does not match original key")
		}
	})
}

// TestGetECDSAPublicKeyFromBinary tests the GetECDSAPublicKeyFromBinary function
func TestGetECDSAPublicKeyFromBinary(t *testing.T) {
	t.Run("valid ECDSA public key binary", func(t *testing.T) {
		// Generate a test key pair
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		// Marshal the public key
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to marshal public key: %v", err)
		}

		// Parse it back
		parsedKey, err := GetECDSAPublicKeyFromBinary(pubKeyBytes)
		if err != nil {
			t.Fatalf("GetECDSAPublicKeyFromBinary() failed: %v", err)
		}

		// Verify the key matches
		if parsedKey.X.Cmp(privateKey.PublicKey.X) != 0 || parsedKey.Y.Cmp(privateKey.PublicKey.Y) != 0 {
			t.Error("Parsed key does not match original key")
		}

		// Verify curve matches
		if parsedKey.Curve != privateKey.PublicKey.Curve {
			t.Error("Parsed key curve does not match original")
		}
	})

	t.Run("invalid binary data", func(t *testing.T) {
		invalidData := []byte("this is not a valid key")

		_, err := GetECDSAPublicKeyFromBinary(invalidData)
		if err == nil {
			t.Error("GetECDSAPublicKeyFromBinary() should fail with invalid data")
		}
	})

	t.Run("empty binary data", func(t *testing.T) {
		_, err := GetECDSAPublicKeyFromBinary([]byte{})
		if err == nil {
			t.Error("GetECDSAPublicKeyFromBinary() should fail with empty data")
		}
	})

	t.Run("non-ECDSA key", func(t *testing.T) {
		// Generate an RSA key for testing
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Marshal the RSA public key
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to marshal RSA public key: %v", err)
		}

		// Try to parse as ECDSA
		_, err = GetECDSAPublicKeyFromBinary(pubKeyBytes)
		if err == nil {
			t.Error("GetECDSAPublicKeyFromBinary() should fail with non-ECDSA key")
		}
		if !strings.Contains(err.Error(), "not an ECDSA public key") {
			t.Errorf("Expected error about non-ECDSA key, got: %v", err)
		}
	})
}

// TestRoundTripPublicKeyConversion tests the round-trip conversion
func TestRoundTripPublicKeyConversion(t *testing.T) {
	t.Run("binary conversion round-trip", func(t *testing.T) {
		// Generate a test key pair
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		kp := &KeyPairWithCreationTime{
			ID:           uuid.New(),
			PublicKey:    &privateKey.PublicKey,
			CreationTime: time.Now(),
		}

		// Convert to binary
		pubKeyBytes, err := kp.GetPublicKeyAsBinary()
		if err != nil {
			t.Fatalf("GetPublicKeyAsBinary() failed: %v", err)
		}

		// Parse back
		parsedKey, err := GetECDSAPublicKeyFromBinary(pubKeyBytes)
		if err != nil {
			t.Fatalf("GetECDSAPublicKeyFromBinary() failed: %v", err)
		}

		// Verify the keys match
		if parsedKey.X.Cmp(kp.PublicKey.X) != 0 || parsedKey.Y.Cmp(kp.PublicKey.Y) != 0 {
			t.Error("Round-trip conversion altered the key")
		}

		// Verify curve matches
		if parsedKey.Curve != kp.PublicKey.Curve {
			t.Error("Round-trip conversion altered the curve")
		}
	})

	t.Run("multiple keys round-trip", func(t *testing.T) {
		// Test with multiple keys to ensure consistency
		for i := 0; i < 5; i++ {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key %d: %v", i, err)
			}

			kp := &KeyPairWithCreationTime{
				ID:           uuid.New(),
				PublicKey:    &privateKey.PublicKey,
				CreationTime: time.Now(),
			}

			pubKeyBytes, err := kp.GetPublicKeyAsBinary()
			if err != nil {
				t.Fatalf("GetPublicKeyAsBinary() failed for key %d: %v", i, err)
			}

			parsedKey, err := GetECDSAPublicKeyFromBinary(pubKeyBytes)
			if err != nil {
				t.Fatalf("GetECDSAPublicKeyFromBinary() failed for key %d: %v", i, err)
			}

			if parsedKey.X.Cmp(kp.PublicKey.X) != 0 || parsedKey.Y.Cmp(kp.PublicKey.Y) != 0 {
				t.Errorf("Round-trip conversion altered key %d", i)
			}
		}
	})
}

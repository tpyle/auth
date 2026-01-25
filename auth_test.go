package auth

import (
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

		if auth.Options.ExpirationTime != time.Hour*24 {
			t.Errorf("Expected ExpirationTime 24h, got %v", auth.Options.ExpirationTime)
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

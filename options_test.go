package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

// Test for all Option functions
func TestOptions(t *testing.T) {
	t.Run("WithSaltLength", func(t *testing.T) {
		auth := Create(WithSaltLength(64))

		if auth.Options.SaltLength != 64 {
			t.Errorf("Expected SaltLength 64, got %d", auth.Options.SaltLength)
		}
	})

	t.Run("WithHashTime", func(t *testing.T) {
		auth := Create(WithHashTime(8))

		if auth.Options.HashTime != 8 {
			t.Errorf("Expected HashTime 8, got %d", auth.Options.HashTime)
		}
	})

	t.Run("WithHashMemoryKiB", func(t *testing.T) {
		auth := Create(WithHashMemoryKiB(256 * 1024))

		if auth.Options.HashMemoryKiB != 256*1024 {
			t.Errorf("Expected HashMemoryKiB %d, got %d", 256*1024, auth.Options.HashMemoryKiB)
		}
	})

	t.Run("WithHashThreads", func(t *testing.T) {
		auth := Create(WithHashThreads(8))

		if auth.Options.HashThreads != 8 {
			t.Errorf("Expected HashThreads 8, got %d", auth.Options.HashThreads)
		}
	})

	t.Run("WithKeyLength", func(t *testing.T) {
		auth := Create(WithKeyLength(64))

		if auth.Options.KeyLength != 64 {
			t.Errorf("Expected KeyLength 64, got %d", auth.Options.KeyLength)
		}
	})

	t.Run("WithSigningKeyValidity", func(t *testing.T) {
		duration := time.Hour * 48
		auth := Create(WithSigningKeyValidity(duration))

		if auth.Options.SigningKeyValidity != duration {
			t.Errorf("Expected SigningKeyValidity %v, got %v", duration, auth.Options.SigningKeyValidity)
		}
	})

	t.Run("WithSigningKeyCreationFreq", func(t *testing.T) {
		duration := time.Hour * 6
		auth := Create(WithSigningKeyCreationFreq(duration))

		if auth.Options.SigningKeyCreationFreq != duration {
			t.Errorf("Expected SigningKeyCreationFreq %v, got %v", duration, auth.Options.SigningKeyCreationFreq)
		}
	})

	t.Run("WithExpirationTime", func(t *testing.T) {
		duration := time.Hour * 2
		auth := Create(WithExpirationTime(duration))

		if auth.Options.ExpirationTime != duration {
			t.Errorf("Expected ExpirationTime %v, got %v", duration, auth.Options.ExpirationTime)
		}
	})

	t.Run("WithRefreshTokenExpirationTime", func(t *testing.T) {
		duration := time.Hour * 48
		auth := Create(WithRefreshTokenExpirationTime(duration))

		if auth.Options.RefreshTokenExpirationTime != duration {
			t.Errorf("Expected RefreshTokenExpirationTime %v, got %v", duration, auth.Options.RefreshTokenExpirationTime)
		}
	})

	t.Run("WithRefreshTokenLength", func(t *testing.T) {
		auth := Create(WithRefreshTokenLength(512))

		if auth.Options.RefreshTokenLength != 512 {
			t.Errorf("Expected RefreshTokenLength 512, got %d", auth.Options.RefreshTokenLength)
		}
	})

	t.Run("WithAuthHeader", func(t *testing.T) {
		headerName := "X-Custom-Auth"
		auth := Create(WithAuthHeader(&headerName))

		if auth.Options.AuthHeader == nil {
			t.Fatal("AuthHeader should not be nil")
		}

		if *auth.Options.AuthHeader != headerName {
			t.Errorf("Expected AuthHeader '%s', got '%s'", headerName, *auth.Options.AuthHeader)
		}

		// Test with nil
		auth2 := Create(WithAuthHeader(nil))
		if auth2.Options.AuthHeader != nil {
			t.Error("AuthHeader should be nil when set to nil")
		}
	})

	t.Run("WithAuthCookie", func(t *testing.T) {
		cookieName := "custom_auth_token"
		auth := Create(WithAuthCookie(&cookieName))

		if auth.Options.AuthCookie == nil {
			t.Fatal("AuthCookie should not be nil")
		}

		if *auth.Options.AuthCookie != cookieName {
			t.Errorf("Expected AuthCookie '%s', got '%s'", cookieName, *auth.Options.AuthCookie)
		}

		// Test with nil
		auth2 := Create(WithAuthCookie(nil))
		if auth2.Options.AuthCookie != nil {
			t.Error("AuthCookie should be nil when set to nil")
		}
	})

	t.Run("WithLookupUserPasswordFunc", func(t *testing.T) {
		mockFunc := func(username string) (string, error) {
			return "test_password", nil
		}

		auth := Create(WithLookupUserPasswordFunc(mockFunc))

		if auth.Options.LookupUserPasswordFunc == nil {
			t.Fatal("LookupUserPasswordFunc should not be nil")
		}

		// Test the function works
		result, err := auth.Options.LookupUserPasswordFunc("test")
		if err != nil {
			t.Errorf("LookupUserPasswordFunc failed: %v", err)
		}

		if result != "test_password" {
			t.Errorf("Expected 'test_password', got '%s'", result)
		}
	})

	t.Run("WithStoreNewSigningKeyFunc", func(t *testing.T) {
		called := false
		mockFunc := func(key *KeyPairWithCreationTime) error {
			called = true
			return nil
		}

		auth := Create(WithStoreNewSigningKeyFunc(mockFunc))

		if auth.Options.StoreNewSigningKeyFunc == nil {
			t.Fatal("StoreNewSigningKeyFunc should not be nil")
		}

		// Test the function works
		testKey := &KeyPairWithCreationTime{ID: uuid.New()}
		err := auth.Options.StoreNewSigningKeyFunc(testKey)
		if err != nil {
			t.Errorf("StoreNewSigningKeyFunc failed: %v", err)
		}

		if !called {
			t.Error("StoreNewSigningKeyFunc was not called")
		}
	})

	t.Run("WithGetSigningKeyFunc", func(t *testing.T) {
		testID := uuid.New()
		mockFunc := func(kid uuid.UUID) ([]*KeyPairWithCreationTime, error) {
			if kid == testID {
				return []*KeyPairWithCreationTime{{ID: testID}}, nil
			}
			return nil, fmt.Errorf("key not found")
		}

		auth := Create(WithGetSigningKeyFunc(mockFunc))

		if auth.Options.GetSigningKeyFunc == nil {
			t.Fatal("GetSigningKeyFunc should not be nil")
		}

		// Test the function works
		keys, err := auth.Options.GetSigningKeyFunc(testID)
		if err != nil {
			t.Errorf("GetSigningKeyFunc failed: %v", err)
		}

		if len(keys) != 1 || keys[0].ID != testID {
			t.Error("GetSigningKeyFunc returned unexpected result")
		}
	})

	t.Run("WithGetSigningKeysFunc", func(t *testing.T) {
		testKeys := []*KeyPairWithCreationTime{
			{ID: uuid.New()},
			{ID: uuid.New()},
		}

		mockFunc := func() ([]*KeyPairWithCreationTime, error) {
			return testKeys, nil
		}

		auth := Create(WithGetSigningKeysFunc(mockFunc))

		if auth.Options.GetSigningKeysFunc == nil {
			t.Fatal("GetSigningKeysFunc should not be nil")
		}

		// Test the function works
		keys, err := auth.Options.GetSigningKeysFunc()
		if err != nil {
			t.Errorf("GetSigningKeysFunc failed: %v", err)
		}

		if len(keys) != 2 {
			t.Errorf("Expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("WithDeleteExpiredSigningKeyFunc", func(t *testing.T) {
		var deletedID uuid.UUID
		mockFunc := func(kid uuid.UUID) error {
			deletedID = kid
			return nil
		}

		auth := Create(WithDeleteExpiredSigningKeyFunc(mockFunc))

		if auth.Options.DeleteExpiredSigningKeyFunc == nil {
			t.Fatal("DeleteExpiredSigningKeyFunc should not be nil")
		}

		// Test the function works
		testID := uuid.New()
		err := auth.Options.DeleteExpiredSigningKeyFunc(testID)
		if err != nil {
			t.Errorf("DeleteExpiredSigningKeyFunc failed: %v", err)
		}

		if deletedID != testID {
			t.Error("DeleteExpiredSigningKeyFunc didn't receive correct ID")
		}
	})

	t.Run("WithDeleteExpiredSigningKeysFunc", func(t *testing.T) {
		var deletedIDs []uuid.UUID
		mockFunc := func(kids []uuid.UUID) error {
			deletedIDs = kids
			return nil
		}

		auth := Create(WithDeleteExpiredSigningKeysFunc(mockFunc))

		if auth.Options.DeleteExpiredSigningKeysFunc == nil {
			t.Fatal("DeleteExpiredSigningKeysFunc should not be nil")
		}

		// Test the function works
		testIDs := []uuid.UUID{uuid.New(), uuid.New()}
		err := auth.Options.DeleteExpiredSigningKeysFunc(testIDs)
		if err != nil {
			t.Errorf("DeleteExpiredSigningKeysFunc failed: %v", err)
		}

		if len(deletedIDs) != 2 {
			t.Errorf("Expected 2 deleted IDs, got %d", len(deletedIDs))
		}
	})

	t.Run("WithLookupRefreshTokenFunc", func(t *testing.T) {
		testID := uuid.New()
		testToken := &RefreshToken{
			ID:   testID,
			Rand: []byte("test_random_bytes"),
		}

		mockFunc := func(id uuid.UUID) (*RefreshToken, error) {
			if id == testID {
				return testToken, nil
			}
			return nil, fmt.Errorf("token not found")
		}

		auth := Create(WithLookupRefreshTokenFunc(mockFunc))

		if auth.Options.LookupRefreshTokenFunc == nil {
			t.Fatal("LookupRefreshTokenFunc should not be nil")
		}

		// Test the function works
		token, err := auth.Options.LookupRefreshTokenFunc(testID)
		if err != nil {
			t.Errorf("LookupRefreshTokenFunc failed: %v", err)
		}

		if token.ID != testID {
			t.Error("LookupRefreshTokenFunc returned unexpected token")
		}
	})

	t.Run("WithStoreRefreshTokenFunc", func(t *testing.T) {
		var storedToken *RefreshToken
		mockFunc := func(token *RefreshToken) error {
			storedToken = token
			return nil
		}

		auth := Create(WithStoreRefreshTokenFunc(mockFunc))

		if auth.Options.StoreRefreshTokenFunc == nil {
			t.Fatal("StoreRefreshTokenFunc should not be nil")
		}

		// Test the function works
		testToken := &RefreshToken{
			ID:   uuid.New(),
			Rand: []byte("test_random_bytes"),
		}
		err := auth.Options.StoreRefreshTokenFunc(testToken)
		if err != nil {
			t.Errorf("StoreRefreshTokenFunc failed: %v", err)
		}

		if storedToken.ID != testToken.ID {
			t.Error("StoreRefreshTokenFunc didn't store correct token")
		}
	})

	t.Run("WithDeleteRefreshTokenFunc", func(t *testing.T) {
		var deletedID uuid.UUID
		mockFunc := func(id uuid.UUID) error {
			deletedID = id
			return nil
		}

		auth := Create(WithDeleteRefreshTokenFunc(mockFunc))

		if auth.Options.DeleteRefreshTokenFunc == nil {
			t.Fatal("DeleteRefreshTokenFunc should not be nil")
		}

		// Test the function works
		testID := uuid.New()
		err := auth.Options.DeleteRefreshTokenFunc(testID)
		if err != nil {
			t.Errorf("DeleteRefreshTokenFunc failed: %v", err)
		}

		if deletedID != testID {
			t.Error("DeleteRefreshTokenFunc didn't receive correct ID")
		}
	})

	t.Run("WithViper", func(t *testing.T) {
		v := viper.New()
		auth := Create(WithViper(v))

		if auth.Options.ViperRef != v {
			t.Error("ViperRef was not set correctly")
		}

		// Test that defaults are set
		if v.GetInt("auth.salt_length") != 16 {
			t.Errorf("Expected default salt_length 16, got %d", v.GetInt("auth.salt_length"))
		}

		if v.GetInt("auth.hash_time") != 4 {
			t.Errorf("Expected default hash_time 4, got %d", v.GetInt("auth.hash_time"))
		}

		if v.GetInt("auth.hash_memory_kib") != 128*1024 {
			t.Errorf("Expected default hash_memory_kib %d, got %d", 128*1024, v.GetInt("auth.hash_memory_kib"))
		}

		if v.GetInt("auth.hash_threads") != 4 {
			t.Errorf("Expected default hash_threads 4, got %d", v.GetInt("auth.hash_threads"))
		}

		if v.GetInt("auth.key_length") != 32 {
			t.Errorf("Expected default key_length 32, got %d", v.GetInt("auth.key_length"))
		}

		if v.GetDuration("auth.signing_key_validity") != 0 {
			t.Errorf("Expected default signing_key_validity 0, got %v", v.GetDuration("auth.signing_key_validity"))
		}

		if v.GetDuration("auth.signing_key_creation_freq") != 0 {
			t.Errorf("Expected default signing_key_creation_freq 0, got %v", v.GetDuration("auth.signing_key_creation_freq"))
		}

		if v.GetDuration("auth.expiration_time") != time.Minute*15 {
			t.Errorf("Expected default expiration_time 15m, got %v", v.GetDuration("auth.expiration_time"))
		}

		// Test that options are read from viper
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

		if auth.Options.SigningKeyValidity != 0 {
			t.Errorf("Expected SigningKeyValidity 0, got %v", auth.Options.SigningKeyValidity)
		}

		if auth.Options.SigningKeyCreationFreq != 0 {
			t.Errorf("Expected SigningKeyCreationFreq 0, got %v", auth.Options.SigningKeyCreationFreq)
		}

		if auth.Options.ExpirationTime != time.Minute*15 {
			t.Errorf("Expected ExpirationTime 15m, got %v", auth.Options.ExpirationTime)
		}
	})

	t.Run("WithViperPrefix", func(t *testing.T) {
		v := viper.New()
		prefix := "myapp."
		auth := Create(WithViperPrefix(v, prefix))

		if auth.Options.ViperRef != v {
			t.Error("ViperRef was not set correctly")
		}

		// Test that defaults are set with prefix
		if v.GetInt(prefix+"auth.salt_length") != 16 {
			t.Errorf("Expected default salt_length 16 with prefix, got %d", v.GetInt(prefix+"auth.salt_length"))
		}

		if v.GetInt(prefix+"auth.hash_time") != 4 {
			t.Errorf("Expected default hash_time 4 with prefix, got %d", v.GetInt(prefix+"auth.hash_time"))
		}

		if v.GetInt(prefix+"auth.hash_memory_kib") != 128*1024 {
			t.Errorf("Expected default hash_memory_kib %d with prefix, got %d", 128*1024, v.GetInt(prefix+"auth.hash_memory_kib"))
		}

		if v.GetInt(prefix+"auth.hash_threads") != 4 {
			t.Errorf("Expected default hash_threads 4 with prefix, got %d", v.GetInt(prefix+"auth.hash_threads"))
		}

		if v.GetInt(prefix+"auth.key_length") != 32 {
			t.Errorf("Expected default key_length 32 with prefix, got %d", v.GetInt(prefix+"auth.key_length"))
		}

		if v.GetDuration(prefix+"auth.signing_key_validity") != 0 {
			t.Errorf("Expected default signing_key_validity 0 with prefix, got %v", v.GetDuration(prefix+"auth.signing_key_validity"))
		}

		if v.GetDuration(prefix+"auth.signing_key_creation_freq") != 0 {
			t.Errorf("Expected default signing_key_creation_freq 0 with prefix, got %v", v.GetDuration(prefix+"auth.signing_key_creation_freq"))
		}

		if v.GetDuration(prefix+"auth.expiration_time") != time.Minute*15 {
			t.Errorf("Expected default expiration_time 15m with prefix, got %v", v.GetDuration(prefix+"auth.expiration_time"))
		}
	})

	t.Run("WithViperNil", func(t *testing.T) {
		auth := Create(WithViper(nil))

		if auth.Options.ViperRef != nil {
			t.Error("ViperRef should be nil when nil is passed")
		}

		// Should still have default options
		if auth.Options.SaltLength != 16 {
			t.Errorf("Expected default SaltLength 16, got %d", auth.Options.SaltLength)
		}
	})

	t.Run("WithViperCustomValues", func(t *testing.T) {
		v := viper.New()

		// Set custom values in viper
		v.Set("auth.salt_length", 32)
		v.Set("auth.hash_time", 8)
		v.Set("auth.hash_memory_kib", 256*1024)
		v.Set("auth.hash_threads", 8)
		v.Set("auth.key_length", 64)
		v.Set("auth.signing_key_validity", time.Hour*48)
		v.Set("auth.signing_key_creation_freq", time.Hour*12)
		v.Set("auth.expiration_time", time.Hour*2)
		v.Set("auth.auth_header", "X-Custom-Auth")
		v.Set("auth.auth_cookie", "session_token")

		auth := Create(WithViper(v))

		// Test that custom values are loaded
		if auth.Options.SaltLength != 32 {
			t.Errorf("Expected SaltLength 32, got %d", auth.Options.SaltLength)
		}

		if auth.Options.HashTime != 8 {
			t.Errorf("Expected HashTime 8, got %d", auth.Options.HashTime)
		}

		if auth.Options.HashMemoryKiB != 256*1024 {
			t.Errorf("Expected HashMemoryKiB %d, got %d", 256*1024, auth.Options.HashMemoryKiB)
		}

		if auth.Options.HashThreads != 8 {
			t.Errorf("Expected HashThreads 8, got %d", auth.Options.HashThreads)
		}

		if auth.Options.KeyLength != 64 {
			t.Errorf("Expected KeyLength 64, got %d", auth.Options.KeyLength)
		}

		if auth.Options.SigningKeyValidity != time.Hour*48 {
			t.Errorf("Expected SigningKeyValidity 48h, got %v", auth.Options.SigningKeyValidity)
		}

		if auth.Options.SigningKeyCreationFreq != time.Hour*12 {
			t.Errorf("Expected SigningKeyCreationFreq 12h, got %v", auth.Options.SigningKeyCreationFreq)
		}

		if auth.Options.ExpirationTime != time.Hour*2 {
			t.Errorf("Expected ExpirationTime 2h, got %v", auth.Options.ExpirationTime)
		}

		if auth.Options.AuthHeader == nil || *auth.Options.AuthHeader != "X-Custom-Auth" {
			t.Errorf("Expected AuthHeader 'X-Custom-Auth', got %s", *auth.Options.AuthHeader)
		}

		if auth.Options.AuthCookie == nil || *auth.Options.AuthCookie != "session_token" {
			t.Errorf("Expected AuthCookie 'session_token', got %s", *auth.Options.AuthCookie)
		}
	})

	t.Run("WithViperPrefixCustomValues", func(t *testing.T) {
		v := viper.New()
		prefix := "app."

		// Set custom values in viper with prefix
		v.Set(prefix+"auth.salt_length", 48)
		v.Set(prefix+"auth.hash_time", 6)
		v.Set(prefix+"auth.expiration_time", time.Hour*3)
		v.Set(prefix+"auth.auth_header", "X-App-Token")

		auth := Create(WithViperPrefix(v, prefix))

		// Test that custom values are loaded with prefix
		if auth.Options.SaltLength != 48 {
			t.Errorf("Expected SaltLength 48 with prefix, got %d", auth.Options.SaltLength)
		}

		if auth.Options.HashTime != 6 {
			t.Errorf("Expected HashTime 6 with prefix, got %d", auth.Options.HashTime)
		}

		if auth.Options.ExpirationTime != time.Hour*3 {
			t.Errorf("Expected ExpirationTime 3h with prefix, got %v", auth.Options.ExpirationTime)
		}

		if auth.Options.AuthHeader == nil || *auth.Options.AuthHeader != "X-App-Token" {
			t.Errorf("Expected AuthHeader 'X-App-Token' with prefix, got %v", auth.Options.AuthHeader)
		}
	})

	t.Run("WithViperAuthHeaderCookieHandling", func(t *testing.T) {
		v := viper.New()

		// Test header and cookie when not set in viper (should be nil)
		auth1 := Create(WithViper(v))
		if auth1.Options.AuthHeader == nil {
			t.Error("AuthHeader should not be nil when not set in viper")
		}
		if auth1.Options.AuthCookie != nil {
			t.Error("AuthCookie should be nil when not set in viper")
		}

		// Test header and cookie when explicitly set in viper
		v2 := viper.New()
		v2.Set("auth.auth_header", "Bearer")
		v2.Set("auth.auth_cookie", "token")
		auth2 := Create(WithViper(v2))

		if auth2.Options.AuthHeader == nil || *auth2.Options.AuthHeader != "Bearer" {
			t.Errorf("Expected AuthHeader 'Bearer', got %v", auth2.Options.AuthHeader)
		}
		if auth2.Options.AuthCookie == nil || *auth2.Options.AuthCookie != "token" {
			t.Errorf("Expected AuthCookie 'token', got %v", auth2.Options.AuthCookie)
		}
	})
}

// Test for getDefaultOptions
func TestGetDefaultOptions(t *testing.T) {
	opts := getDefaultOptions()

	if opts.SaltLength != 16 {
		t.Errorf("Expected default SaltLength 16, got %d", opts.SaltLength)
	}

	if opts.HashTime != 4 {
		t.Errorf("Expected default HashTime 4, got %d", opts.HashTime)
	}

	if opts.HashMemoryKiB != 128*1024 {
		t.Errorf("Expected default HashMemoryKiB %d, got %d", 128*1024, opts.HashMemoryKiB)
	}

	if opts.HashThreads != 4 {
		t.Errorf("Expected default HashThreads 4, got %d", opts.HashThreads)
	}

	if opts.KeyLength != 32 {
		t.Errorf("Expected default KeyLength 32, got %d", opts.KeyLength)
	}

	if opts.SigningKeyValidity != 0 {
		t.Errorf("Expected default SigningKeyValidity 0, got %v", opts.SigningKeyValidity)
	}

	if opts.SigningKeyCreationFreq != 0 {
		t.Errorf("Expected default SigningKeyCreationFreq 0, got %v", opts.SigningKeyCreationFreq)
	}

	if opts.ExpirationTime != time.Minute*15 {
		t.Errorf("Expected default ExpirationTime 15m, got %v", opts.ExpirationTime)
	}

	if opts.RefreshTokenExpirationTime != time.Hour*24*7 {
		t.Errorf("Expected default RefreshTokenExpirationTime 168h (7 days), got %v", opts.RefreshTokenExpirationTime)
	}

	if opts.RefreshTokenLength != 256 {
		t.Errorf("Expected default RefreshTokenLength 256, got %d", opts.RefreshTokenLength)
	}

	if opts.AuthHeader == nil || *opts.AuthHeader != "Authorization" {
		t.Errorf("Expected default AuthHeader 'Authorization', got %v", opts.AuthHeader)
	}

	if opts.AuthCookie != nil {
		t.Errorf("Expected default AuthCookie nil, got %v", opts.AuthCookie)
	}
}

// Test for stringP helper
func TestStringP(t *testing.T) {
	testStr := "test_string"
	ptr := stringP(testStr)

	if ptr == nil {
		t.Fatal("stringP should not return nil")
	}

	if *ptr != testStr {
		t.Errorf("Expected '%s', got '%s'", testStr, *ptr)
	}
}

// Test combining multiple options
func TestCombinedOptions(t *testing.T) {
	userStore := make(mockUserStore)
	keyStore := newMockKeyStore()

	auth := Create(
		WithSaltLength(24),
		WithHashTime(3),
		WithHashMemoryKiB(96*1024),
		WithHashThreads(6),
		WithKeyLength(48),
		WithExpirationTime(time.Hour*6),
		WithSigningKeyValidity(time.Hour*72),
		WithSigningKeyCreationFreq(time.Hour*12),
		WithAuthHeader(stringP("X-Token")),
		WithAuthCookie(stringP("session")),
		WithLookupUserPasswordFunc(userStore.lookupUser),
		WithStoreNewSigningKeyFunc(keyStore.storeKey),
		WithGetSigningKeyFunc(keyStore.getKey),
		WithGetSigningKeysFunc(keyStore.getKeys),
		WithDeleteExpiredSigningKeyFunc(keyStore.deleteKey),
		WithDeleteExpiredSigningKeysFunc(keyStore.deleteKeys),
	)

	// Verify all options were applied
	opts := auth.Options

	if opts.SaltLength != 24 {
		t.Errorf("SaltLength not applied correctly")
	}
	if opts.HashTime != 3 {
		t.Errorf("HashTime not applied correctly")
	}
	if opts.HashMemoryKiB != 96*1024 {
		t.Errorf("HashMemoryKiB not applied correctly")
	}
	if opts.HashThreads != 6 {
		t.Errorf("HashThreads not applied correctly")
	}
	if opts.KeyLength != 48 {
		t.Errorf("KeyLength not applied correctly")
	}
	if opts.ExpirationTime != time.Hour*6 {
		t.Errorf("ExpirationTime not applied correctly")
	}
	if opts.SigningKeyValidity != time.Hour*72 {
		t.Errorf("SigningKeyValidity not applied correctly")
	}
	if opts.SigningKeyCreationFreq != time.Hour*12 {
		t.Errorf("SigningKeyCreationFreq not applied correctly")
	}
	if opts.AuthHeader == nil || *opts.AuthHeader != "X-Token" {
		t.Errorf("AuthHeader not applied correctly")
	}
	if opts.AuthCookie == nil || *opts.AuthCookie != "session" {
		t.Errorf("AuthCookie not applied correctly")
	}
	if opts.LookupUserPasswordFunc == nil {
		t.Errorf("LookupUserPasswordFunc not applied correctly")
	}
	if opts.StoreNewSigningKeyFunc == nil {
		t.Errorf("StoreNewSigningKeyFunc not applied correctly")
	}
	if opts.GetSigningKeyFunc == nil {
		t.Errorf("GetSigningKeyFunc not applied correctly")
	}
	if opts.GetSigningKeysFunc == nil {
		t.Errorf("GetSigningKeysFunc not applied correctly")
	}
	if opts.DeleteExpiredSigningKeyFunc == nil {
		t.Errorf("DeleteExpiredSigningKeyFunc not applied correctly")
	}
	if opts.DeleteExpiredSigningKeysFunc == nil {
		t.Errorf("DeleteExpiredSigningKeysFunc not applied correctly")
	}
}

// Test that multiple calls to the same option override correctly
func TestOptionOverride(t *testing.T) {
	auth := Create(
		WithSaltLength(16),
		WithSaltLength(32), // This should override the previous one
		WithSaltLength(64), // This should override both previous ones
	)

	if auth.Options.SaltLength != 64 {
		t.Errorf("Expected SaltLength 64 (last override), got %d", auth.Options.SaltLength)
	}
}

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test for parseAuthHeader
func TestParseAuthHeader(t *testing.T) {
	testCases := []struct {
		header        string
		expectedType  string
		expectedToken string
	}{
		{"Bearer abc123", "bearer", "abc123"},
		{"Basic dGVzdDp0ZXN0", "basic", "dGVzdDp0ZXN0"},
		{"bearer token123", "bearer", "token123"},
		{"BEARER TOKEN456", "bearer", "TOKEN456"},
		{"", "", ""},
		{"OnePart", "", ""},
		{"Type Token With Spaces", "type", "Token With Spaces"},
	}

	for _, tc := range testCases {
		t.Run(tc.header, func(t *testing.T) {
			tokenType, token := parseAuthHeader(tc.header)

			if tokenType != tc.expectedType {
				t.Errorf("Expected type '%s', got '%s'", tc.expectedType, tokenType)
			}

			if token != tc.expectedToken {
				t.Errorf("Expected token '%s', got '%s'", tc.expectedToken, token)
			}
		})
	}
}

// Test for GetToken and WithToken
func TestContextTokens(t *testing.T) {
	t.Run("get token from context", func(t *testing.T) {
		auth := Create()
		err := auth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		// Create a token
		tokenString, err := auth.CreateJWT("user123", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		token, err := auth.VerifyToken(tokenString)
		if err != nil {
			t.Fatalf("VerifyToken() failed: %v", err)
		}

		// Test empty context
		ctx := context.Background()
		retrievedToken := GetToken(ctx)
		if retrievedToken != nil {
			t.Error("GetToken() should return nil for empty context")
		}

		// Test context with token
		ctxWithToken := WithToken(ctx, token)
		retrievedToken = GetToken(ctxWithToken)
		if retrievedToken == nil {
			t.Error("GetToken() should return token from context")
		}

		if retrievedToken != token {
			t.Error("Retrieved token should match the stored token")
		}
	})
}

// Test for GetTokenFromRequest
func TestGetTokenFromRequest(t *testing.T) {
	auth := Create()
	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	// Create a valid token
	tokenString, err := auth.CreateJWT("user123", nil)
	if err != nil {
		t.Fatalf("CreateJWT() failed: %v", err)
	}

	t.Run("token from Authorization header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		token := auth.GetTokenFromRequest(req)
		if token == nil {
			t.Error("Should extract token from Authorization header")
		}

		if !token.IsValid() {
			t.Error("Token should be valid")
		}
	})

	t.Run("token from custom header", func(t *testing.T) {
		customAuth := Create(WithAuthHeader(stringP("X-Auth-Token")))
		err := customAuth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		customTokenString, err := customAuth.CreateJWT("user456", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Auth-Token", "Bearer "+customTokenString)

		token := customAuth.GetTokenFromRequest(req)
		if token == nil {
			t.Error("Should extract token from custom header")
		}
	})

	t.Run("token from cookie", func(t *testing.T) {
		cookieAuth := Create(WithAuthCookie(stringP("auth_token")))
		err := cookieAuth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		cookieTokenString, err := cookieAuth.CreateJWT("user789", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  "auth_token",
			Value: cookieTokenString,
		})

		token := cookieAuth.GetTokenFromRequest(req)
		if token == nil {
			t.Error("Should extract token from cookie")
		}
	})

	t.Run("no token found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		token := auth.GetTokenFromRequest(req)
		if token != nil {
			t.Error("Should return nil when no token found")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")

		token := auth.GetTokenFromRequest(req)
		if token != nil {
			t.Error("Should return nil for invalid token")
		}
	})

	t.Run("non-bearer token type", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")

		token := auth.GetTokenFromRequest(req)
		if token != nil {
			t.Error("Should return nil for non-bearer token")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		expiredAuth := Create(WithExpirationTime(time.Millisecond * 10))
		err := expiredAuth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		expiredTokenString, err := expiredAuth.CreateJWT("user_expired", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		// Wait for token to expire
		time.Sleep(time.Millisecond * 50)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+expiredTokenString)

		token := expiredAuth.GetTokenFromRequest(req)
		if token != nil {
			t.Error("Should return nil for expired token")
		}
	})

	t.Run("both header and cookie disabled", func(t *testing.T) {
		noAuth := Create(
			WithAuthHeader(nil),
			WithAuthCookie(nil),
		)
		err := noAuth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		// This should be ignored since both header and cookie are disabled
		req.Header.Set("Authorization", "Bearer "+tokenString)

		token := noAuth.GetTokenFromRequest(req)
		if token != nil {
			t.Error("Should return nil when both auth methods are disabled")
		}
	})
}

// Test for AuthHandler middleware
func TestAuthHandler(t *testing.T) {
	auth := Create()
	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	// Create a test handler that checks for token in context
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := GetToken(r.Context())
		if token != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("authenticated"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not authenticated"))
		}
	})

	handler := auth.AuthHandler(testHandler)

	t.Run("with valid token", func(t *testing.T) {
		tokenString, err := auth.CreateJWT("user123", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		if rr.Body.String() != "authenticated" {
			t.Errorf("Expected 'authenticated', got '%s'", rr.Body.String())
		}
	})

	t.Run("without token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		if rr.Body.String() != "not authenticated" {
			t.Errorf("Expected 'not authenticated', got '%s'", rr.Body.String())
		}
	})

	t.Run("with invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid.token")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		if rr.Body.String() != "not authenticated" {
			t.Errorf("Expected 'not authenticated', got '%s'", rr.Body.String())
		}
	})
}

// Test for RequireAuthHandler middleware
func TestRequireAuthHandler(t *testing.T) {
	auth := Create()
	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	// Create a test handler that should only be reached with valid auth
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	handler := auth.RequireAuthHandler(testHandler)

	t.Run("with valid token", func(t *testing.T) {
		tokenString, err := auth.CreateJWT("user123", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		if rr.Body.String() != "success" {
			t.Errorf("Expected 'success', got '%s'", rr.Body.String())
		}
	})

	t.Run("without token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}

		expectedBody := `{"message": "missing token"}`
		if rr.Body.String() != expectedBody {
			t.Errorf("Expected '%s', got '%s'", expectedBody, rr.Body.String())
		}
	})

	t.Run("with invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid.token")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}

		expectedBody := `{"message": "missing token"}`
		if rr.Body.String() != expectedBody {
			t.Errorf("Expected '%s', got '%s'", expectedBody, rr.Body.String())
		}
	})

	t.Run("with expired token", func(t *testing.T) {
		expiredAuth := Create(WithExpirationTime(time.Millisecond * 10))
		err := expiredAuth.Initialize()
		if err != nil {
			t.Fatalf("Initialize() failed: %v", err)
		}

		expiredTokenString, err := expiredAuth.CreateJWT("user_expired", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		// Wait for token to expire
		time.Sleep(time.Millisecond * 50)

		expiredHandler := expiredAuth.RequireAuthHandler(testHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+expiredTokenString)

		rr := httptest.NewRecorder()
		expiredHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})
}

// Test for HasToken
func TestHasToken(t *testing.T) {
	auth := Create()
	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("request with token", func(t *testing.T) {
		tokenString, err := auth.CreateJWT("user123", nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		token, err := auth.VerifyToken(tokenString)
		if err != nil {
			t.Fatalf("VerifyToken() failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		ctx := WithToken(req.Context(), token)
		req = req.WithContext(ctx)

		if !HasToken(req) {
			t.Error("HasToken() should return true for request with token")
		}
	})

	t.Run("request without token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		if HasToken(req) {
			t.Error("HasToken() should return false for request without token")
		}
	})
}

// Test for GetSub
func TestGetSub(t *testing.T) {
	auth := Create()
	err := auth.Initialize()
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("get sub from request with token", func(t *testing.T) {
		expectedSub := "user123"
		tokenString, err := auth.CreateJWT(expectedSub, nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		token, err := auth.VerifyToken(tokenString)
		if err != nil {
			t.Fatalf("VerifyToken() failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		ctx := WithToken(req.Context(), token)
		req = req.WithContext(ctx)

		sub, err := GetSub(req)
		if err != nil {
			t.Fatalf("GetSub() failed: %v", err)
		}

		if sub != expectedSub {
			t.Errorf("Expected sub '%s', got '%s'", expectedSub, sub)
		}
	})

	t.Run("get sub with different subject", func(t *testing.T) {
		expectedSub := "admin@example.com"
		tokenString, err := auth.CreateJWT(expectedSub, nil)
		if err != nil {
			t.Fatalf("CreateJWT() failed: %v", err)
		}

		token, err := auth.VerifyToken(tokenString)
		if err != nil {
			t.Fatalf("VerifyToken() failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		ctx := WithToken(req.Context(), token)
		req = req.WithContext(ctx)

		sub, err := GetSub(req)
		if err != nil {
			t.Fatalf("GetSub() failed: %v", err)
		}

		if sub != expectedSub {
			t.Errorf("Expected sub '%s', got '%s'", expectedSub, sub)
		}
	})

	t.Run("request without token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		sub, err := GetSub(req)
		if err == nil {
			t.Error("GetSub() should return error for request without token")
		}

		if sub != "" {
			t.Errorf("Expected empty string, got '%s'", sub)
		}

		expectedError := "no token in context"
		if err.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
		}
	})

	t.Run("request with nil token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := WithToken(req.Context(), nil)
		req = req.WithContext(ctx)

		sub, err := GetSub(req)
		if err == nil {
			t.Error("GetSub() should return error for nil token")
		}

		if sub != "" {
			t.Errorf("Expected empty string, got '%s'", sub)
		}
	})
}

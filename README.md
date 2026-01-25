# auth

A Go authentication library that provides secure JWT token-based authentication with Argon2 password hashing, ECDSA key management, and flexible HTTP integration.

## Overview

`auth` is designed to provide production-ready authentication features including:

- **Secure Password Hashing**: Argon2id implementation with configurable parameters
- **JWT Token Management**: ECDSA-signed JWT tokens with automatic key rotation
- **Flexible Integration**: HTTP middleware support with header and cookie authentication
- **Key Management**: Automatic signing key generation, rotation, and cleanup
- **Production Ready**: Secure defaults, constant-time comparisons, and proper error handling

## Installation

```bash
go get github.com/tpyle/auth
```

## Quick Start

### Basic Authentication Setup

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/tpyle/auth"
)

func main() {
    // Create a simple user store (in production, use a database)
    users := map[string]string{
        "admin": "$argon2id$v=19$m=131072,t=4,p=4$...", // hashed password
    }

    // Create authorizer with user lookup function
    authorizer := auth.Create(
        auth.WithLookupUserPasswordFunc(func(username string) (string, error) {
            if hashedPassword, ok := users[username]; ok {
                return hashedPassword, nil
            }
            return "", fmt.Errorf("user not found")
        }),
        auth.WithExpirationTime(24 * time.Hour),
    )

    // Hash a new password
    hashedPassword, err := authorizer.HashPassword([]byte("mypassword"))
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Hashed password:", hashedPassword)

    // Verify login
    valid, err := authorizer.Login("admin", []byte("mypassword"))
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Login valid:", valid)
}
```

### JWT Token Generation and Validation

```go
// Initialize authorizer with key management
authorizer := auth.Create(
    auth.WithLookupUserPasswordFunc(lookupUserFunc),
    auth.WithStoreNewSigningKeyFunc(storeKeyFunc),
    auth.WithGetSigningKeysFunc(getKeysFunc),
    auth.WithSigningKeyCreationFreq(24 * time.Hour), // Rotate keys daily
    auth.WithExpirationTime(time.Hour),              // Tokens expire in 1 hour
)

// Create a token for a user
token, err := authorizer.CreateToken("username", map[string]interface{}{
    "role": "admin",
    "permissions": []string{"read", "write"},
})
if err != nil {
    log.Fatal(err)
}

// Verify and parse the token
parsedToken, err := authorizer.VerifyToken(token)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Token valid, user: %s\n", parsedToken.Username)
```

### HTTP Middleware Integration

The library provides built-in middleware for HTTP authentication:

```go
import (
    "net/http"
    "github.com/gorilla/mux"
    "github.com/tpyle/auth"
)

func main() {
    authorizer := auth.Create(/* your options */)

    router := mux.NewRouter()

    // AuthHandler extracts and validates tokens, adding them to context if valid
    // Requests without tokens continue processing (optional authentication)
    router.Use(authorizer.AuthHandler)

    // Public endpoint - no authentication required
    router.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
        if auth.HasToken(r) {
            token := auth.GetToken(r.Context())
            fmt.Fprintf(w, "Hello, %s! (authenticated)", token.Username)
        } else {
            w.Write([]byte("Hello, anonymous user!"))
        }
    })

    // Protected routes - require authentication
    protected := router.PathPrefix("/api").Subrouter()
    protected.Use(authorizer.RequireAuthHandler) // Returns 401 if no valid token

    protected.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
        token := auth.GetToken(r.Context())
        fmt.Fprintf(w, "Hello, %s!", token.Username)
    })

    http.ListenAndServe(":8080", router)
}
```

## Features

### Password Hashing

Uses Argon2id with secure defaults:
- **Memory**: 128MB (configurable)
- **Iterations**: 4 (configurable)
- **Parallelism**: 4 threads (configurable)
- **Salt**: 16 bytes (configurable)
- **Output**: PHC string format for easy storage

### JWT Token Management

- **Algorithm**: ECDSA with P-256 curve
- **Key Rotation**: Automatic generation and rotation of signing keys
- **Validation**: Comprehensive token validation with expiry checks
- **Claims**: Custom claims support with username and additional data

### HTTP Integration

- **Header Authentication**: `Authorization: Bearer <token>` (default)
- **Cookie Authentication**: Configurable cookie-based auth
- **Context Integration**: Token data accessible via request context
- **Middleware Ready**: Easy integration with existing HTTP frameworks

## Configuration Options

The library uses functional options for flexible configuration:

### Password Hashing Options

```go
auth.WithSaltLength(16)                    // Salt length in bytes
auth.WithHashTime(4)                       // Number of iterations
auth.WithHashMemoryKiB(128 * 1024)        // Memory usage in KiB
auth.WithHashThreads(4)                    // Number of parallel threads
auth.WithKeyLength(32)                     // Output key length
```

### JWT Configuration

```go
auth.WithExpirationTime(24 * time.Hour)            // Token validity period
auth.WithSigningKeyValidity(7 * 24 * time.Hour)    // How long keys are valid
auth.WithSigningKeyCreationFreq(24 * time.Hour)    // Key rotation frequency
```

### Authentication Methods

```go
auth.WithAuthHeader("Authorization")        // Header name for Bearer tokens
auth.WithAuthCookie("session_token")        // Cookie name for token auth
```

### Storage Functions

```go
// User password lookup (required)
auth.WithLookupUserPasswordFunc(func(username string) (string, error) {
    // Return PHC-formatted hashed password for user
    return userDB.GetHashedPassword(username)
})

// Key storage functions (required for JWT)
auth.WithStoreNewSigningKeyFunc(func(key *auth.KeyPairWithCreationTime) error {
    // Store new signing key
    return keyDB.Store(key)
})

auth.WithGetSigningKeysFunc(func() ([]*auth.KeyPairWithCreationTime, error) {
    // Get all signing keys
    return keyDB.GetAll()
})

auth.WithDeleteExpiredSigningKeysFunc(func(keyIDs []uuid.UUID) error {
    // Delete expired keys
    return keyDB.DeleteMany(keyIDs)
})
```

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/tpyle/auth"
    "github.com/google/uuid"
)

// Mock storage implementations
type UserStore struct {
    users map[string]string
}

func (us *UserStore) GetHashedPassword(username string) (string, error) {
    if password, exists := us.users[username]; exists {
        return password, nil
    }
    return "", fmt.Errorf("user not found")
}

type KeyStore struct {
    keys map[uuid.UUID]*auth.KeyPairWithCreationTime
}

func (ks *KeyStore) Store(key *auth.KeyPairWithCreationTime) error {
    ks.keys[key.ID] = key
    return nil
}

func (ks *KeyStore) GetAll() ([]*auth.KeyPairWithCreationTime, error) {
    var keys []*auth.KeyPairWithCreationTime
    for _, key := range ks.keys {
        keys = append(keys, key)
    }
    return keys, nil
}

func (ks *KeyStore) DeleteMany(keyIDs []uuid.UUID) error {
    for _, id := range keyIDs {
        delete(ks.keys, id)
    }
    return nil
}

func main() {
    // Initialize stores
    userStore := &UserStore{
        users: make(map[string]string),
    }
    keyStore := &KeyStore{
        keys: make(map[uuid.UUID]*auth.KeyPairWithCreationTime),
    }

    // Create authorizer
    authorizer := auth.Create(
        // Password hashing configuration
        auth.WithHashMemoryKiB(64*1024), // 64MB for faster hashing in dev
        auth.WithHashTime(2),            // Fewer iterations for dev

        // JWT configuration
        auth.WithExpirationTime(time.Hour),                      // 1 hour tokens
        auth.WithSigningKeyCreationFreq(24 * time.Hour),         // Daily key rotation
        auth.WithSigningKeyValidity(7 * 24 * time.Hour),         // Keys valid for 1 week

        // Storage functions
        auth.WithLookupUserPasswordFunc(userStore.GetHashedPassword),
        auth.WithStoreNewSigningKeyFunc(keyStore.Store),
        auth.WithGetSigningKeysFunc(keyStore.GetAll),
        auth.WithDeleteExpiredSigningKeysFunc(keyStore.DeleteMany),

        // Authentication methods
        auth.WithAuthHeader("Authorization"), // Bearer tokens in header
        auth.WithAuthCookie("session"),       // Also check session cookie
    )

    // Create test user
    hashedPassword, err := authorizer.HashPassword([]byte("password123"))
    if err != nil {
        log.Fatal(err)
    }
    userStore.users["testuser"] = hashedPassword

    // Initialize key management
    if err := authorizer.Initialize(); err != nil {
        log.Fatal(err)
    }

    // HTTP handlers
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        username := r.FormValue("username")
        password := r.FormValue("password")

        valid, err := authorizer.Login(username, []byte(password))
        if err != nil {
            http.Error(w, "Login error", http.StatusInternalServerError)
            return
        }

        if !valid {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }

        // Create token
        token, err := authorizer.CreateToken(username, map[string]interface{}{
            "role": "user",
        })
        if err != nil {
            http.Error(w, "Token creation failed", http.StatusInternalServerError)
            return
        }

        fmt.Fprintf(w, "Token: %s", token)
    })

    http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
        token := authorizer.GetTokenFromRequest(r)
        if token == nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        fmt.Fprintf(w, "Hello, %s! Role: %v", token.Username, token.Claims["role"])
    })

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## API Reference

### Core Types

```go
type Authorizer struct {
    Options *Options
    // Internal fields...
}

type AuthorizerToken jwt.Token // Consult https://pkg.go.dev/github.com/golang-jwt/jwt/v5#Token for details

type KeyPairWithCreationTime struct {
    ID           uuid.UUID
    PublicKey    *ecdsa.PublicKey
    CreationTime time.Time
}
```

### Main Methods

```go
// Password operations
func (a *Authorizer) HashPassword(password []byte) (string, error)
func (a *Authorizer) Login(username string, password []byte) (bool, error)

// JWT operations
func (a *Authorizer) CreateJWT(username string, claims map[string]interface{}) (string, error)
func (a *Authorizer) VerifyToken(tokenString string) (*AuthorizerToken, error)

// HTTP integration
func (a *Authorizer) GetTokenFromRequest(r *http.Request) *AuthorizerToken
func (a *Authorizer) AuthHandler(next http.Handler) http.Handler // Optional authentication
func (a *Authorizer) RequireAuthHandler(next http.Handler) http.Handler // Mandatory authentication

// Key management
func (a *Authorizer) Initialize() error
```

### Context Helpers

```go
// Get token from request context
func GetToken(ctx context.Context) *AuthorizerToken

// Add token to context
func WithToken(ctx context.Context, token *AuthorizerToken) context.Context
```

## Configuration with Viper

The library includes built-in support for [Viper](https://github.com/spf13/viper) configuration management. You can configure all authentication parameters through configuration files, environment variables, or any other Viper-supported source.

### Using Viper Configuration

```go
import (
    "github.com/spf13/viper"
    "github.com/tpyle/auth"
)

func main() {
    // Set up Viper configuration
    v := viper.New()
    v.SetConfigName("config")
    v.SetConfigType("yaml")
    v.AddConfigPath(".")
    v.ReadInConfig()

    // Create authorizer with Viper configuration
    authorizer := auth.Create(
        auth.WithViper(v),
        auth.WithLookupUserPasswordFunc(lookupUser),
        // Other options...
    )
}
```

### Configuration with Prefix

You can use a prefix to namespace the auth configuration within your larger application config:

```go
authorizer := auth.Create(
    auth.WithViperPrefix(v, "myapp."),
    auth.WithLookupUserPasswordFunc(lookupUser),
)
```

### Supported Configuration Keys

The following configuration keys are supported (shown with default values):

```yaml
auth:
  salt_length: 16                    # Salt length for password hashing
  hash_time: 4                       # Argon2 time parameter
  hash_memory_kib: 131072            # Argon2 memory parameter in KiB
  hash_threads: 4                    # Argon2 parallelism parameter
  key_length: 32                     # Key length for password hashing
  signing_key_validity: 0s           # How long signing keys are valid (0 = never expire)
  signing_key_creation_freq: 0s      # How often to create new signing keys (0 = never)
  expiration_time: 24h               # JWT token expiration time
  auth_header: "Authorization"       # HTTP header name for tokens (omit for none)
  auth_cookie: ""                    # Cookie name for tokens (omit for none)
```

With prefix "myapp.":
```yaml
myapp:
  auth:
    salt_length: 32
    expiration_time: 1h
    auth_header: "X-App-Token"
```

### Environment Variables

When using Viper with environment variable support:

```bash
export AUTH_SALT_LENGTH=32
export AUTH_EXPIRATION_TIME=1h
export AUTH_AUTH_HEADER=X-Token
```

Or with prefix:
```bash
export MYAPP_AUTH_SALT_LENGTH=32
export MYAPP_AUTH_EXPIRATION_TIME=1h
```

## Security Considerations

- **Constant Time Comparisons**: Password verification uses `crypto/subtle` for timing attack protection
- **Secure Random Generation**: All random values use `crypto/rand`
- **Key Rotation**: Automatic signing key rotation prevents long-term key compromise
- **PHC Format**: Password hashes use the standard PHC string format
- **ECDSA P-256**: Industry-standard elliptic curve for JWT signing
- **Configurable Parameters**: Argon2 parameters can be tuned for your security/performance requirements

## Requirements

- Go 1.21 or later
- Dependencies managed via Go modules

## License

See [LICENSE](LICENSE) file for details.
- [Viper](https://github.com/spf13/viper) - Configuration management

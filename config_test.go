package auth

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestDefaultConfigIsValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := map[string]func(*Config){
		"argon2":         func(c *Config) { c.Argon2.Iterations = 0 },
		"max hashes":     func(c *Config) { c.MaxConcurrentHashes = 0 },
		"access ttl":     func(c *Config) { c.AccessTokenTTL = 0 },
		"refresh ttl":    func(c *Config) { c.RefreshTokenTTL = -time.Second },
		"rotation":       func(c *Config) { c.KeyRotationInterval = -time.Second },
		"key cache ttl":  func(c *Config) { c.KeyCacheTTL = -time.Second },
		"leeway":         func(c *Config) { c.Leeway = -time.Second },
		"rotation zero":  nil, // valid: disables rotation
		"cache ttl zero": nil, // valid: disables caching
	}
	for name, modify := range tests {
		t.Run(name, func(t *testing.T) {
			c := DefaultConfig()
			if modify == nil {
				c.KeyRotationInterval, c.KeyCacheTTL = 0, 0
				if err := c.Validate(); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			modify(&c)
			if err := c.Validate(); err == nil {
				t.Error("expected error")
			}
			if _, err := New(context.Background(), WithConfig(c)); err == nil {
				t.Error("New accepted invalid config")
			}
		})
	}
}

func TestBuildSettingsDefaults(t *testing.T) {
	s, err := buildSettings(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Config, DefaultConfig()) {
		t.Errorf("Config = %+v; want defaults", s.Config)
	}
	if _, ok := s.keyStore.(*MemoryKeyStore); !ok {
		t.Errorf("default key store = %T", s.keyStore)
	}
	if s.logger == nil || s.now == nil || s.unauthorized == nil {
		t.Error("defaults not filled in")
	}
	if s.userStore != nil || s.refreshStore != nil || s.claimsProvider != nil {
		t.Error("optional stores should default to nil")
	}
}

func TestOptions(t *testing.T) {
	users := NewMemoryUserStore()
	keys := NewMemoryKeyStore()
	refresh := NewMemoryRefreshTokenStore()
	clock := newFakeClock()
	provider := func(context.Context, string) (map[string]any, error) { return nil, nil }
	unauthorized := func(http.ResponseWriter, *http.Request, error) {}

	s, err := buildSettings([]Option{
		WithUserStore(users),
		WithKeyStore(keys),
		WithRefreshTokenStore(refresh),
		WithClaimsProvider(provider),
		WithArgon2Params(testArgon2),
		WithMaxConcurrentHashes(3),
		WithAccessTokenTTL(time.Minute),
		WithRefreshTokenTTL(time.Hour),
		WithKeyRotationInterval(2 * time.Hour),
		WithKeyCacheTTL(time.Second),
		WithIssuer("iss"),
		WithAudience("a", "b"),
		WithLeeway(5 * time.Second),
		WithAuthHeader("X-Token"),
		WithAuthCookie("session"),
		WithUnauthorizedHandler(unauthorized),
		WithLogger(discardLogger),
		WithClock(clock.Now),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Argon2:              testArgon2,
		MaxConcurrentHashes: 3,
		AccessTokenTTL:      time.Minute,
		RefreshTokenTTL:     time.Hour,
		KeyRotationInterval: 2 * time.Hour,
		KeyCacheTTL:         time.Second,
		Issuer:              "iss",
		Audience:            []string{"a", "b"},
		Leeway:              5 * time.Second,
		AuthHeader:          "X-Token",
		AuthCookie:          "session",
	}
	if !reflect.DeepEqual(s.Config, want) {
		t.Errorf("Config = %+v\nwant %+v", s.Config, want)
	}
	if s.userStore != users || s.keyStore != keys || s.refreshStore != refresh {
		t.Error("stores not applied")
	}
	if s.claimsProvider == nil || s.unauthorized == nil || s.logger != discardLogger {
		t.Error("funcs not applied")
	}
	if !s.now().Equal(clock.Now()) {
		t.Error("clock not applied")
	}
	if got := s.maxTokenTTL(); got != time.Hour {
		t.Errorf("maxTokenTTL = %v", got)
	}
}

func TestWithConfigThenOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = "from-config"
	cfg.AccessTokenTTL = time.Hour
	s, err := buildSettings([]Option{WithConfig(cfg), WithIssuer("override")})
	if err != nil {
		t.Fatal(err)
	}
	if s.Issuer != "override" || s.AccessTokenTTL != time.Hour {
		t.Errorf("got issuer %q ttl %v", s.Issuer, s.AccessTokenTTL)
	}
}

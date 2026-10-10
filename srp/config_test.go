package srp

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tpyle/auth/v2"
)

func TestDefaultConfigValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := map[string]func(*Config){
		"group":           func(c *Config) { c.Group = 1024 },
		"zero group":      func(c *Config) { c.Group = 0 },
		"invalid kdf":     func(c *Config) { c.KDF = KDFParams{} },
		"kdf over limits": func(c *Config) { c.KDFLimits = KDFParams{MemoryKiB: 8, Iterations: 1, Parallelism: 1} },
		"short salt":      func(c *Config) { c.SaltLength = 15 },
		"long salt":       func(c *Config) { c.SaltLength = 65 },
		"short ttl":       func(c *Config) { c.SessionTTL = 9 * time.Second },
		"long ttl":        func(c *Config) { c.SessionTTL = 11 * time.Minute },
		"unitless ttl":    func(c *Config) { c.SessionTTL = 120 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := DefaultConfig()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Error("Validate() = nil")
			}
		})
	}
	for name, mutate := range map[string]func(*Config){
		"2048":     func(c *Config) { c.Group = Group2048 },
		"4096":     func(c *Config) { c.Group = Group4096 },
		"salt 64":  func(c *Config) { c.SaltLength = 64 },
		"ttl 10s":  func(c *Config) { c.SessionTTL = 10 * time.Second },
		"ttl 10m":  func(c *Config) { c.SessionTTL = 10 * time.Minute },
		"test kdf": func(c *Config) { c.KDF = testKDF },
	} {
		t.Run("ok "+name, func(t *testing.T) {
			c := DefaultConfig()
			mutate(&c)
			if err := c.Validate(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestNewRejects(t *testing.T) {
	users := NewMemoryUserStore()
	tests := map[string]struct {
		opts []Option
		is   error
	}{
		"no user store":   {nil, auth.ErrNotConfigured},
		"bad config":      {[]Option{WithUserStore(users), WithGroup(1)}, nil},
		"short decoy key": {[]Option{WithUserStore(users), WithDecoyKey(make([]byte, 31))}, nil},
		"empty decoy key": {[]Option{WithUserStore(users), WithDecoyKey([]byte{})}, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(tt.opts...)
			if err == nil || (tt.is != nil && !errors.Is(err, tt.is)) {
				t.Errorf("New() = %v", err)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	cfg := Config{
		Group:      Group4096,
		KDF:        testKDF,
		KDFLimits:  KDFParams{MemoryKiB: 128, Iterations: 2, Parallelism: 2},
		SaltLength: 32,
		SessionTTL: time.Minute,
	}
	key := make([]byte, 32)
	srv, err := New(WithUserStore(NewMemoryUserStore()), WithConfig(cfg), WithSessionTTL(3*time.Minute),
		WithSaltLength(24), WithKDFLimits(DefaultKDFLimits()), WithDecoyKey(key))
	if err != nil {
		t.Fatal(err)
	}
	want := cfg
	want.SessionTTL, want.SaltLength, want.KDFLimits = 3*time.Minute, 24, DefaultKDFLimits()
	if srv.s.Config != want {
		t.Errorf("config = %+v, want %+v", srv.s.Config, want)
	}
	key[0] = 1
	if srv.s.decoyKey[0] != 0 {
		t.Error("decoy key not copied")
	}
	if srv.s.logger == nil || srv.s.sessions == nil {
		t.Error("defaults not filled in")
	}
	if strings.Contains(srv.s.now().String(), "m=") {
		t.Error("clock has a monotonic reading")
	}
}

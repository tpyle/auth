package passkey

import (
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	c := DefaultConfig()
	c.RPID = testRPID
	c.RPDisplayName = "Example"
	c.RPOrigins = []string{testOrigin}
	return c
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string // substring of the error; empty means valid
	}{
		{"valid", func(*Config) {}, ""},
		{"subdomain origin", func(c *Config) { c.RPOrigins = []string{"https://login.example.com"} }, ""},
		{"origin with port", func(c *Config) { c.RPOrigins = []string{"https://example.com:8443"} }, ""},
		{"origin with trailing slash", func(c *Config) { c.RPOrigins = []string{"https://example.com/"} }, ""},
		{"localhost http", func(c *Config) { c.RPID = "localhost"; c.RPOrigins = []string{"http://localhost:8080"} }, ""},
		{"several origins", func(c *Config) { c.RPOrigins = []string{testOrigin, "https://app.example.com"} }, ""},
		{"min ttl", func(c *Config) { c.CeremonyTTL = 30 * time.Second }, ""},
		{"max ttl", func(c *Config) { c.CeremonyTTL = 10 * time.Minute }, ""},
		{"preferred", func(c *Config) { c.UserVerification = Preferred; c.ResidentKey = Discouraged }, ""},

		{"no rp id", func(c *Config) { c.RPID = "" }, "RPID is required"},
		{"no display name", func(c *Config) { c.RPDisplayName = "" }, "RPDisplayName is required"},
		{"no origins", func(c *Config) { c.RPOrigins = nil }, "at least one RPOrigin"},
		{"origin on other domain", func(c *Config) { c.RPOrigins = []string{"https://example.org"} }, "not on RPID"},
		{"origin suffix but not subdomain", func(c *Config) { c.RPOrigins = []string{"https://badexample.com"} }, "not on RPID"},
		{"http non-localhost", func(c *Config) { c.RPOrigins = []string{"http://example.com"} }, "must use https"},
		{"origin with path", func(c *Config) { c.RPOrigins = []string{"https://example.com/login"} }, "scheme and host"},
		{"origin with query", func(c *Config) { c.RPOrigins = []string{"https://example.com?x=1"} }, "scheme and host"},
		{"origin with user", func(c *Config) { c.RPOrigins = []string{"https://u@example.com"} }, "scheme and host"},
		{"bare host", func(c *Config) { c.RPOrigins = []string{"example.com"} }, "scheme and host"},
		{"other scheme", func(c *Config) { c.RPOrigins = []string{"ftp://example.com"} }, "scheme and host"},
		{"unparsable", func(c *Config) { c.RPOrigins = []string{"https://exa mple.com"} }, "scheme and host"},
		{"ttl too short", func(c *Config) { c.CeremonyTTL = time.Second }, "CeremonyTTL"},
		{"ttl too long", func(c *Config) { c.CeremonyTTL = time.Hour }, "CeremonyTTL"},
		{"bad user verification", func(c *Config) { c.UserVerification = "always" }, "UserVerification"},
		{"empty resident key", func(c *Config) { c.ResidentKey = "" }, "ResidentKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)
			err := c.Validate()
			if tt.want == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestConfigValidateReportsAllErrors(t *testing.T) {
	err := Config{}.Validate()
	if err == nil {
		t.Fatal("Validate() = nil")
	}
	for _, want := range []string{"RPID", "RPDisplayName", "RPOrigin", "CeremonyTTL", "UserVerification", "ResidentKey"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestOptions(t *testing.T) {
	s, err := buildSettings([]Option{
		WithConfig(validConfig()),
		WithRelyingParty("localhost", "Dev", "http://localhost:8080"),
		WithCeremonyTTL(time.Minute),
		WithUserVerification(Discouraged),
		WithResidentKey(Preferred),
		WithAllowCloneWarning(true),
		WithUserStore(NewMemoryUserStore()),
		WithCredentialStore(NewMemoryCredentialStore()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.RPID != "localhost" || s.RPDisplayName != "Dev" || s.RPOrigins[0] != "http://localhost:8080" ||
		s.CeremonyTTL != time.Minute || s.UserVerification != Discouraged || s.ResidentKey != Preferred || !s.AllowCloneWarning {
		t.Errorf("settings = %+v", s.Config)
	}
	if s.now().IsZero() {
		t.Error("default clock not set")
	}
}

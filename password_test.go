package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	for _, pw := range []string{"", "hunter2", "pässwörd 🔑", strings.Repeat("x", 4096)} {
		h := mustHash(t, pw)
		if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
			t.Errorf("unexpected encoding %q", h)
		}
		ok, err := VerifyPassword([]byte(pw), h)
		if err != nil || !ok {
			t.Errorf("VerifyPassword(%q) = %v, %v; want true, nil", pw, ok, err)
		}
		ok, err = VerifyPassword([]byte(pw+"x"), h)
		if err != nil || ok {
			t.Errorf("VerifyPassword(wrong) = %v, %v; want false, nil", ok, err)
		}
	}
}

func TestHashPasswordUsesUniqueSalts(t *testing.T) {
	if mustHash(t, "same") == mustHash(t, "same") {
		t.Error("two hashes of the same password are identical")
	}
}

func TestHashPasswordRejectsInvalidParams(t *testing.T) {
	if _, err := HashPassword([]byte("pw"), Argon2Params{}); err == nil {
		t.Error("expected error for zero params")
	}
}

// Changing the configured parameters must not break existing hashes.
func TestVerifyPasswordUsesStoredParams(t *testing.T) {
	other := testArgon2
	other.MemoryKiB = 128
	other.Iterations = 2
	other.KeyLength = 16
	other.SaltLength = 8
	h, err := HashPassword([]byte("pw"), other)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword([]byte("pw"), h)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword = %v, %v", ok, err)
	}
}

func TestNeedsRehash(t *testing.T) {
	h := mustHash(t, "pw")
	tests := []struct {
		name   string
		modify func(*Argon2Params)
		want   bool
	}{
		{"same", func(*Argon2Params) {}, false},
		{"memory", func(p *Argon2Params) { p.MemoryKiB *= 2 }, true},
		{"iterations", func(p *Argon2Params) { p.Iterations++ }, true},
		{"parallelism", func(p *Argon2Params) { p.Parallelism++ }, true},
		{"salt length", func(p *Argon2Params) { p.SaltLength++ }, true},
		{"key length", func(p *Argon2Params) { p.KeyLength++ }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testArgon2
			tt.modify(&p)
			got, err := NeedsRehash(h, p)
			if err != nil || got != tt.want {
				t.Errorf("NeedsRehash = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
	if _, err := NeedsRehash("garbage", testArgon2); !errors.Is(err, ErrInvalidHash) {
		t.Errorf("NeedsRehash(garbage) err = %v", err)
	}
}

func TestDecodePHCErrors(t *testing.T) {
	const salt = "c29tZXNhbHRzb21lc2FsdA"                      // 16 bytes
	const hash = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g" // 32 bytes
	valid := "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + hash
	if _, _, _, err := decodePHC(valid); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}

	tests := map[string]string{
		"empty":             "",
		"too few fields":    "$argon2id$v=19$m=64,t=1,p=1$" + salt,
		"leading text":      "x$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + hash,
		"argon2i":           "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + hash,
		"old version":       "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + hash,
		"missing param":     "$argon2id$v=19$m=64,t=1$" + salt + "$" + hash,
		"duplicate param":   "$argon2id$v=19$m=64,m=64,t=1$" + salt + "$" + hash,
		"unknown param":     "$argon2id$v=19$m=64,t=1,p=1,x=1$" + salt + "$" + hash,
		"no equals":         "$argon2id$v=19$m64,t=1,p=1$" + salt + "$" + hash,
		"bad memory":        "$argon2id$v=19$m=lots,t=1,p=1$" + salt + "$" + hash,
		"bad iterations":    "$argon2id$v=19$m=64,t=-1,p=1$" + salt + "$" + hash,
		"parallelism > 255": "$argon2id$v=19$m=64,t=1,p=256$" + salt + "$" + hash,
		"zero iterations":   "$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + hash,
		"bad salt":          "$argon2id$v=19$m=64,t=1,p=1$!!!$" + hash,
		"bad hash":          "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$!!!",
		"short salt":        "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$" + hash,
		"short hash":        "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$aGFzaA",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyPassword([]byte("pw"), in); !errors.Is(err, ErrInvalidHash) {
				t.Errorf("err = %v; want ErrInvalidHash", err)
			}
		})
	}
}

func TestArgon2ParamsValidate(t *testing.T) {
	if err := DefaultArgon2Params().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	tests := map[string]func(*Argon2Params){
		"iterations":  func(p *Argon2Params) { p.Iterations = 0 },
		"parallelism": func(p *Argon2Params) { p.Parallelism = 0 },
		"memory":      func(p *Argon2Params) { p.Parallelism = 4; p.MemoryKiB = 31 },
		"salt":        func(p *Argon2Params) { p.SaltLength = 7 },
		"key":         func(p *Argon2Params) { p.KeyLength = 15 },
	}
	for name, modify := range tests {
		t.Run(name, func(t *testing.T) {
			p := testArgon2
			modify(&p)
			if err := p.Validate(); err == nil {
				t.Error("expected error")
			}
		})
	}
}

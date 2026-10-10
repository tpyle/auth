package srp

import (
	"context"
	"errors"
	"testing"
	"time"

	"uuid"

	"github.com/tpyle/auth/v2"
)

func TestMemoryUserStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryUserStore()
	if _, err := s.LookupVerifier(ctx, "alice"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	v1, v2 := testVerifier(t, Group2048), testVerifier(t, Group3072)
	s.SetVerifier("alice", v1)
	if got, err := s.LookupVerifier(ctx, "alice"); err != nil || got != v1.String() {
		t.Errorf("lookup = %q, %v", got, err)
	}
	s.SetVerifier("alice", v2)
	if got, _ := s.LookupVerifier(ctx, "alice"); got != v2.String() {
		t.Error("SetVerifier did not replace")
	}
}

func TestMemorySessionStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemorySessionStore()
	now := time.Now()
	id := uuid.New()
	data := []byte("data")
	if err := s.SaveSession(ctx, id, data, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	if s.Len() != 1 {
		t.Errorf("Len = %d", s.Len())
	}

	if _, err := s.ConsumeSession(ctx, uuid.New(), now); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("unknown id: %v", err)
	}
	got, err := s.ConsumeSession(ctx, id, now)
	if err != nil || string(got) != "data" {
		t.Errorf("consume = %q, %v", got, err)
	}
	if _, err := s.ConsumeSession(ctx, id, now); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("second consume: %v", err)
	}

	// Expired sessions are not returned, and are consumed anyway.
	id = uuid.New()
	_ = s.SaveSession(ctx, id, data, now.Add(time.Minute))
	if _, err := s.ConsumeSession(ctx, id, now.Add(time.Minute)); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expired: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d after expired consume", s.Len())
	}
}

func TestMemorySessionStorePurgesOnSave(t *testing.T) {
	ctx := context.Background()
	s := NewMemorySessionStore()
	_ = s.SaveSession(ctx, uuid.New(), nil, time.Now().Add(-time.Second))
	_ = s.SaveSession(ctx, uuid.New(), nil, time.Now().Add(time.Minute))
	if s.Len() != 1 {
		t.Errorf("Len = %d, want the expired session purged", s.Len())
	}
}

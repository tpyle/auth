package passkey

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

func TestMemoryUserStore(t *testing.T) {
	s := NewMemoryUserStore()
	u := s.AddUser("alice", "alice@example.com")
	if len(u.Handle) != UserHandleLength || u.Subject != "alice" || u.Name != "alice@example.com" {
		t.Fatalf("AddUser = %+v", u)
	}
	if again := s.AddUser("alice", "other"); !bytes.Equal(again.Handle, u.Handle) || again.Name != u.Name {
		t.Errorf("AddUser twice = %+v, want %+v", again, u)
	}
	got, err := s.LookupUser(ctx, "alice")
	if err != nil || !bytes.Equal(got.Handle, u.Handle) {
		t.Errorf("LookupUser = %+v, %v", got, err)
	}
	got.Handle[0] ^= 0xff
	if again, _ := s.LookupUser(ctx, "alice"); !bytes.Equal(again.Handle, u.Handle) {
		t.Error("LookupUser result aliases stored handle")
	}
	if got, err := s.LookupUserByHandle(ctx, u.Handle); err != nil || got.Subject != "alice" {
		t.Errorf("LookupUserByHandle = %+v, %v", got, err)
	}
	if _, err := s.LookupUser(ctx, "nobody"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("LookupUser(nobody) err = %v", err)
	}
	if _, err := s.LookupUserByHandle(ctx, []byte("nope")); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("LookupUserByHandle(unknown) err = %v", err)
	}
}

func TestNewUserHandleIsRandom(t *testing.T) {
	a, b := NewUserHandle(), NewUserHandle()
	if len(a) != UserHandleLength || bytes.Equal(a, b) {
		t.Errorf("handles %x, %x", a, b)
	}
}

func TestMemoryCredentialStore(t *testing.T) {
	s := NewMemoryCredentialStore()
	now := time.Now()
	c1 := Credential{ID: []byte{1}, Subject: "alice", PublicKey: []byte{9}, SignCount: 5, Transports: []string{"usb"}, CreatedAt: now}
	c2 := Credential{ID: []byte{2}, Subject: "alice", CreatedAt: now.Add(-time.Hour)}
	c3 := Credential{ID: []byte{3}, Subject: "bob", CreatedAt: now}
	for _, c := range []Credential{c1, c2, c3} {
		if err := s.CreateCredential(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateCredential(ctx, Credential{ID: []byte{1}, Subject: "bob"}); !errors.Is(err, ErrCredentialExists) {
		t.Errorf("duplicate ID: err = %v", err)
	}

	list, err := s.ListCredentials(ctx, "alice")
	if err != nil || len(list) != 2 || list[0].ID[0] != 2 || list[1].ID[0] != 1 {
		t.Fatalf("ListCredentials = %+v, %v (want ordered by CreatedAt)", list, err)
	}
	list[1].Transports[0] = "changed"
	list[1].PublicKey[0] = 0
	if again, _ := s.ListCredentials(ctx, "alice"); again[1].Transports[0] != "usb" || again[1].PublicKey[0] != 9 {
		t.Error("ListCredentials result aliases stored credential")
	}
	if list, _ := s.ListCredentials(ctx, "nobody"); len(list) != 0 {
		t.Errorf("ListCredentials(nobody) = %+v", list)
	}

	// Counters never go down, and the sticky flags never clear.
	used := now.Add(time.Minute)
	if err := s.RecordCredentialUse(ctx, CredentialUse{ID: []byte{1}, SignCount: 3, BackupState: true, UserVerified: true, CloneWarning: true, UsedAt: used}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCredentialUse(ctx, CredentialUse{ID: []byte{1}, SignCount: 7, UsedAt: used}); err != nil {
		t.Fatal(err)
	}
	got := findCredential(t, s, "alice", 1)
	if got.SignCount != 7 || got.BackupState || !got.UserVerified || !got.CloneWarning || !got.LastUsedAt.Equal(used) {
		t.Errorf("after use: %+v", got)
	}
	// A zero UsedAt (a refused login recording a clone warning) keeps LastUsedAt.
	if err := s.RecordCredentialUse(ctx, CredentialUse{ID: []byte{1}, SignCount: 7, CloneWarning: true}); err != nil {
		t.Fatal(err)
	}
	if got := findCredential(t, s, "alice", 1); !got.LastUsedAt.Equal(used) {
		t.Errorf("zero UsedAt changed LastUsedAt to %v", got.LastUsedAt)
	}
	if err := s.RecordCredentialUse(ctx, CredentialUse{ID: []byte{42}}); err != nil {
		t.Errorf("RecordCredentialUse(missing) = %v", err)
	}

	if err := s.DeleteCredential(ctx, "bob", []byte{1}); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("delete other user's: err = %v", err)
	}
	if err := s.DeleteCredential(ctx, "alice", []byte{42}); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("delete missing: err = %v", err)
	}
	if err := s.DeleteCredential(ctx, "alice", []byte{1}); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListCredentials(ctx, "alice"); len(list) != 1 {
		t.Errorf("after delete: %+v", list)
	}
}

func findCredential(t *testing.T, s *MemoryCredentialStore, subject string, id byte) Credential {
	t.Helper()
	list, _ := s.ListCredentials(ctx, subject)
	for _, c := range list {
		if c.ID[0] == id {
			return c
		}
	}
	t.Fatalf("credential %d not found", id)
	return Credential{}
}

func TestMemoryCeremonyStore(t *testing.T) {
	s := NewMemoryCeremonyStore()
	now := time.Now()
	id := uuid.New()
	data := []byte("data")
	if err := s.SaveCeremony(ctx, id, data, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	got, err := s.ConsumeCeremony(ctx, id, now)
	if err != nil || string(got) != "data" {
		t.Fatalf("ConsumeCeremony = %q, %v", got, err)
	}
	if _, err := s.ConsumeCeremony(ctx, id, now); !errors.Is(err, ErrCeremonyNotFound) {
		t.Errorf("second consume: err = %v", err)
	}

	expired := uuid.New()
	_ = s.SaveCeremony(ctx, expired, data, now.Add(time.Minute))
	if _, err := s.ConsumeCeremony(ctx, expired, now.Add(time.Minute)); !errors.Is(err, ErrCeremonyNotFound) {
		t.Errorf("expired: err = %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d after consuming expired ceremony", s.Len())
	}
}

func TestMemoryCeremonyStorePurgesOnSave(t *testing.T) {
	s := NewMemoryCeremonyStore()
	for range 5 {
		_ = s.SaveCeremony(ctx, uuid.New(), nil, time.Now().Add(-time.Second))
	}
	_ = s.SaveCeremony(ctx, uuid.New(), nil, time.Now().Add(time.Minute))
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}
}

func TestMemoryCeremonyStoreConcurrentConsume(t *testing.T) {
	s := NewMemoryCeremonyStore()
	id := uuid.New()
	_ = s.SaveCeremony(ctx, id, []byte("x"), time.Now().Add(time.Minute))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := s.ConsumeCeremony(ctx, id, time.Now()); err == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Errorf("%d consumers won, want 1", wins.Load())
	}
}

func TestConcurrentLoginsOneCeremony(t *testing.T) {
	e := newEnv(t)
	cred := e.register("alice")
	ch := e.beginLogin()
	resp := e.va.get(ch, cred, true)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := e.p.Authenticate(ctx, ch.CeremonyID, resp); err == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Errorf("%d logins succeeded, want 1", wins.Load())
	}
}

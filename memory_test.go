package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMemoryUserStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryUserStore()
	if _, err := s.LookupPasswordHash(ctx, "bob"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v; want ErrUserNotFound", err)
	}
	s.SetPasswordHash("bob", "h1")
	if h, err := s.LookupPasswordHash(ctx, "bob"); err != nil || h != "h1" {
		t.Errorf("got %q, %v", h, err)
	}
	if err := s.UpdatePasswordHash(ctx, "bob", "h1", "h2"); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.LookupPasswordHash(ctx, "bob"); h != "h2" {
		t.Errorf("got %q after update", h)
	}
	// A stale old hash must not overwrite the current one.
	if err := s.UpdatePasswordHash(ctx, "bob", "h1", "h3"); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.LookupPasswordHash(ctx, "bob"); h != "h2" {
		t.Errorf("compare-and-swap overwrote a changed hash: got %q", h)
	}
	if err := s.UpdatePasswordHash(ctx, "nobody", "", "h"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupPasswordHash(ctx, "nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Error("update created a user")
	}
}

func TestMemoryKeyStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryKeyStore()
	id := uuid.New()
	if storedKey(t, s, id) != nil {
		t.Fatal("empty store returned a key")
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := &VerificationKey{ID: id, PublicKey: &priv.PublicKey, CreatedAt: time.Unix(1, 0)}
	if err := s.StoreKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	k.CreatedAt = time.Unix(2, 0) // the store must hold its own copy
	got := storedKey(t, s, id)
	if got == nil || !got.CreatedAt.Equal(time.Unix(1, 0)) {
		t.Errorf("stored key = %+v", got)
	}
	if !got.PublicKey.Equal(&priv.PublicKey) {
		t.Error("public key changed in storage")
	}
	got.CreatedAt = time.Unix(3, 0)
	list, _ := s.ListKeys(ctx)
	if len(list) != 1 || !list[0].CreatedAt.Equal(time.Unix(1, 0)) {
		t.Errorf("ListKeys = %+v", list)
	}
	if err := s.DeleteKeys(ctx, []uuid.UUID{id, uuid.New()}); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListKeys(ctx); len(list) != 0 {
		t.Errorf("keys left after delete: %d", len(list))
	}
}

func TestMemoryRefreshTokenStore(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	s := NewMemoryRefreshTokenStore()

	fam, other := uuid.New(), uuid.New()
	a := RefreshTokenRecord{ID: uuid.New(), FamilyID: fam, Subject: "bob", IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Hour)}
	b := RefreshTokenRecord{ID: uuid.New(), FamilyID: fam, Subject: "bob", IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(2 * time.Hour)}
	c := RefreshTokenRecord{ID: uuid.New(), FamilyID: other, Subject: "eve", IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(2 * time.Hour)}
	for _, r := range []RefreshTokenRecord{a, b, c} {
		if err := s.CreateRefreshToken(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	firstUse := clock.Now()
	first, err := s.ConsumeRefreshToken(ctx, a.ID, firstUse)
	if err != nil || first.Used() || first.Subject != "bob" {
		t.Errorf("first consume = %+v, %v", first, err)
	}
	// A later consume reports the first use time and does not overwrite it.
	second, err := s.ConsumeRefreshToken(ctx, a.ID, firstUse.Add(time.Minute))
	if err != nil || !second.Used() || !second.UsedAt.Equal(firstUse) {
		t.Errorf("second consume = %+v, %v; want UsedAt %v", second, err, firstUse)
	}
	third, _ := s.ConsumeRefreshToken(ctx, a.ID, firstUse.Add(2*time.Minute))
	if !third.UsedAt.Equal(firstUse) {
		t.Errorf("UsedAt overwritten: %v", third.UsedAt)
	}
	if _, err := s.ConsumeRefreshToken(ctx, uuid.New(), firstUse); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("err = %v; want ErrRefreshTokenNotFound", err)
	}

	// Creating a token after a's expiry purges it.
	clock.Advance(90 * time.Minute)
	if err := s.CreateRefreshToken(ctx, RefreshTokenRecord{ID: uuid.New(), FamilyID: uuid.New(), Subject: "zed", IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 3 {
		t.Errorf("Len = %d after purge; want 3", s.Len())
	}

	if err := s.RevokeRefreshTokenFamily(ctx, fam); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeRefreshToken(ctx, b.ID, clock.Now()); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("revoked token still present: %v", err)
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d after revoke; want 2", s.Len())
	}
	if err := s.RevokeRefreshTokenFamily(ctx, uuid.New()); err != nil {
		t.Errorf("revoking unknown family: %v", err)
	}

	// c (eve) remains along with the unnamed record; revoke eve's.
	if err := s.RevokeRefreshTokensForSubject(ctx, "eve"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeRefreshToken(ctx, c.ID, clock.Now()); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("eve's token survived subject revocation: %v", err)
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d after subject revoke; want 1", s.Len())
	}
	if err := s.RevokeRefreshTokensForSubject(ctx, "nobody"); err != nil {
		t.Errorf("revoking unknown subject: %v", err)
	}

	// A continuation of an unknown (e.g. purged) family is rejected.
	if err := s.CreateRefreshToken(ctx, RefreshTokenRecord{ID: uuid.New(), ParentID: uuid.New(), FamilyID: uuid.New(), IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Hour)}); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("continuation of unknown family: err = %v; want ErrTokenRevoked", err)
	}

	// Revoked families accept no new tokens until they expire.
	for name, family := range map[string]uuid.UUID{"by family": fam, "by subject": other} {
		err := s.CreateRefreshToken(ctx, RefreshTokenRecord{ID: uuid.New(), FamilyID: family, IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Hour)})
		if !errors.Is(err, ErrTokenRevoked) {
			t.Errorf("%s: create in revoked family: err = %v; want ErrTokenRevoked", name, err)
		}
	}
	clock.Advance(3 * time.Hour) // every family's tokens have expired
	if err := s.CreateRefreshToken(ctx, RefreshTokenRecord{ID: uuid.New(), FamilyID: uuid.New(), IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if len(s.families) != 1 {
		t.Errorf("%d families after expiry; want only the new one", len(s.families))
	}
}

func TestParsePublicKey(t *testing.T) {
	a := newTestAuthorizer(t)
	cur := a.keys.current.Load()
	vk := &VerificationKey{ID: cur.id, PublicKey: &cur.private.PublicKey}
	der, err := vk.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(der)
	if err != nil || !pub.Equal(vk.PublicKey) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := ParsePublicKey([]byte("junk")); err == nil {
		t.Error("expected error for junk")
	}
	if _, err := (&VerificationKey{}).MarshalPublicKey(); err == nil {
		t.Error("expected error marshaling nil key")
	}
	if err := NewMemoryKeyStore().StoreKey(context.Background(), &VerificationKey{ID: uuid.New()}); err == nil {
		t.Error("MemoryKeyStore accepted a key without a public key")
	}
}

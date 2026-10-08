package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Challenge is the result of a Begin method, to be sent to the browser.
type Challenge struct {
	// CeremonyID identifies the ceremony. The client sends it back with its
	// response, and it is passed to the matching Finish method.
	CeremonyID uuid.UUID `json:"ceremonyId"`
	// Options is a JSON object whose "publicKey" member is the
	// PublicKeyCredentialCreationOptionsJSON (for registration) or
	// PublicKeyCredentialRequestOptionsJSON (for login) to give the browser.
	Options json.RawMessage `json:"options"`
	// ExpiresAt is when the ceremony can no longer be finished.
	ExpiresAt time.Time `json:"expiresAt"`
}

type ceremonyKind string

const (
	kindRegistration ceremonyKind = "registration"
	kindLogin        ceremonyKind = "login"
)

// ceremonyRecord is what the CeremonyStore holds.
type ceremonyRecord struct {
	Kind ceremonyKind `json:"kind"`
	// Subject is who a registration is for, or who a BeginLoginFor login is
	// restricted to. Empty for a discoverable login.
	Subject   string               `json:"sub,omitempty"`
	ExpiresAt time.Time            `json:"exp"`
	Session   webauthn.SessionData `json:"session"`
}

// newChallenge stores the ceremony and returns it with its browser options.
func (p *Passkeys) newChallenge(ctx context.Context, kind ceremonyKind, subject string, session *webauthn.SessionData, options any) (*Challenge, error) {
	opts, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("passkey: encoding options: %w", err)
	}
	expires := p.s.now().Add(p.s.CeremonyTTL)
	data, err := json.Marshal(ceremonyRecord{Kind: kind, Subject: subject, ExpiresAt: expires, Session: *session})
	if err != nil {
		return nil, fmt.Errorf("passkey: encoding ceremony: %w", err)
	}
	id := uuid.New()
	if err := p.s.ceremonies.SaveCeremony(ctx, id, data, expires); err != nil {
		return nil, fmt.Errorf("passkey: saving ceremony: %w", err)
	}
	return &Challenge{CeremonyID: id, Options: opts, ExpiresAt: expires}, nil
}

// consumeCeremony takes the ceremony out of the store and checks that it is
// the kind the caller expects and has not expired. The ceremony is consumed
// even when the checks fail, so every Finish attempt needs a new Begin.
func (p *Passkeys) consumeCeremony(ctx context.Context, id uuid.UUID, kind ceremonyKind) (*ceremonyRecord, error) {
	now := p.s.now()
	data, err := p.s.ceremonies.ConsumeCeremony(ctx, id, now)
	if errors.Is(err, ErrCeremonyNotFound) {
		return nil, ErrInvalidCeremony
	}
	if err != nil {
		return nil, fmt.Errorf("passkey: consuming ceremony: %w", err)
	}
	var rec ceremonyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("passkey: decoding ceremony: %w", err)
	}
	// The store is trusted to expire ceremonies, but the time is checked
	// again so a store that ignores now cannot extend the window.
	if rec.Kind != kind || !now.Before(rec.ExpiresAt) {
		return nil, ErrInvalidCeremony
	}
	return &rec, nil
}

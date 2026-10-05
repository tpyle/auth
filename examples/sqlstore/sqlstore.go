// Package sqlstore shows how to back the auth stores with a SQL database
// using only database/sql. The queries target PostgreSQL; adapt the
// placeholders and types for other databases. Bring your own driver (for
// example github.com/jackc/pgx/v5/stdlib).
//
// Schema:
//
//	CREATE TABLE users (
//	    username      TEXT PRIMARY KEY,
//	    password_hash TEXT NOT NULL
//	);
//
//	CREATE TABLE signing_keys (
//	    id         UUID PRIMARY KEY,
//	    public_key BYTEA NOT NULL,      -- PKIX DER
//	    created_at TIMESTAMPTZ NOT NULL,
//	    expires_at TIMESTAMPTZ          -- NULL = never
//	);
//
//	CREATE TABLE refresh_tokens (
//	    id         UUID PRIMARY KEY,
//	    family_id  UUID NOT NULL,
//	    subject    TEXT NOT NULL,
//	    issued_at  TIMESTAMPTZ NOT NULL,
//	    expires_at TIMESTAMPTZ NOT NULL,
//	    used_at    TIMESTAMPTZ          -- NULL = unused
//	);
//	CREATE INDEX ON refresh_tokens (family_id);
//	CREATE INDEX ON refresh_tokens (subject);
//	CREATE INDEX ON refresh_tokens (expires_at);
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tpyle/auth/v2"
)

// Interface checks.
var (
	_ auth.UserStore           = (*Store)(nil)
	_ auth.PasswordHashUpdater = (*Store)(nil)
	_ auth.KeyStore            = (*Store)(nil)
	_ auth.RefreshTokenStore   = (*Store)(nil)
)

// Store implements every auth store interface on one *sql.DB.
type Store struct {
	DB *sql.DB
}

// LookupPasswordHash implements auth.UserStore.
func (s *Store) LookupPasswordHash(ctx context.Context, username string) (string, error) {
	var h string
	err := s.DB.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE username = $1`, username).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", auth.ErrUserNotFound
	}
	return h, err
}

// UpdatePasswordHash implements auth.PasswordHashUpdater.
func (s *Store) UpdatePasswordHash(ctx context.Context, username, encodedHash string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET password_hash = $2 WHERE username = $1`, username, encodedHash)
	return err
}

// StoreKey implements auth.KeyStore.
func (s *Store) StoreKey(ctx context.Context, k *auth.VerificationKey) error {
	der, err := k.MarshalPublicKey()
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO signing_keys (id, public_key, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		k.ID, der, k.CreatedAt, nullTime(k.ExpiresAt))
	return err
}

// ListKeys implements auth.KeyStore.
func (s *Store) ListKeys(ctx context.Context) ([]*auth.VerificationKey, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, public_key, created_at, expires_at FROM signing_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*auth.VerificationKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// DeleteKeys implements auth.KeyStore.
func (s *Store) DeleteKeys(ctx context.Context, ids []uuid.UUID) error {
	for _, id := range ids {
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM signing_keys WHERE id = $1`, id); err != nil {
			return err
		}
	}
	return nil
}

// CreateRefreshToken implements auth.RefreshTokenStore.
func (s *Store) CreateRefreshToken(ctx context.Context, r auth.RefreshTokenRecord) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, family_id, subject, issued_at, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		r.ID, r.FamilyID, r.Subject, r.IssuedAt, r.ExpiresAt)
	return err
}

// ConsumeRefreshToken implements auth.RefreshTokenStore.
//
// The conditional UPDATE is what makes this atomic: a concurrent caller
// blocks on the row lock and then re-checks "used_at IS NULL" against the
// committed row, so exactly one caller sees the token as unused. Everyone
// else reads the record, including the first use time.
func (s *Store) ConsumeRefreshToken(ctx context.Context, id uuid.UUID, now time.Time) (auth.RefreshTokenRecord, error) {
	var r auth.RefreshTokenRecord
	err := s.DB.QueryRowContext(ctx, `
		UPDATE refresh_tokens SET used_at = $2
		WHERE id = $1 AND used_at IS NULL
		RETURNING id, family_id, subject, issued_at, expires_at`, id, now,
	).Scan(&r.ID, &r.FamilyID, &r.Subject, &r.IssuedAt, &r.ExpiresAt)
	if err == nil {
		return r, nil // was unused; UsedAt stays zero in the returned record
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}

	var usedAt sql.NullTime
	err = s.DB.QueryRowContext(ctx, `
		SELECT id, family_id, subject, issued_at, expires_at, used_at
		FROM refresh_tokens WHERE id = $1`, id,
	).Scan(&r.ID, &r.FamilyID, &r.Subject, &r.IssuedAt, &r.ExpiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return r, auth.ErrRefreshTokenNotFound
	}
	r.UsedAt = usedAt.Time
	return r, err
}

// RevokeRefreshTokenFamily implements auth.RefreshTokenStore.
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE family_id = $1`, familyID)
	return err
}

// RevokeRefreshTokensForSubject implements auth.RefreshTokenStore.
func (s *Store) RevokeRefreshTokensForSubject(ctx context.Context, subject string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE subject = $1`, subject)
	return err
}

// PurgeExpiredRefreshTokens deletes expired records. Run it periodically
// (for example hourly); the auth package never deletes expired records itself.
func (s *Store) PurgeExpiredRefreshTokens(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type scanner interface{ Scan(dest ...any) error }

func scanKey(row scanner) (*auth.VerificationKey, error) {
	var (
		k   auth.VerificationKey
		der []byte
		exp sql.NullTime
	)
	if err := row.Scan(&k.ID, &der, &k.CreatedAt, &exp); err != nil {
		return nil, err
	}
	pub, err := auth.ParsePublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", k.ID, err)
	}
	k.PublicKey = pub
	k.ExpiresAt = exp.Time
	return &k, nil
}

func nullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

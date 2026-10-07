package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenType distinguishes access tokens from refresh tokens. It is stored in
// the "typ" claim, and each kind of token is rejected where the other is
// expected.
type TokenType string

// Token types.
const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// JWT "typ" header values. Access tokens use the RFC 9068 media type so
// generic JWT libraries can tell them apart from refresh tokens.
const (
	headerTypeAccess  = "at+jwt"
	headerTypeRefresh = "rt+jwt"
)

// Claim names managed by this package.
const (
	claimIssuer    = "iss"
	claimSubject   = "sub"
	claimAudience  = "aud"
	claimExpires   = "exp"
	claimNotBefore = "nbf"
	claimIssuedAt  = "iat"
	claimID        = "jti"
	claimType      = "typ"
	claimFamily    = "fam"
)

var reservedClaims = map[string]bool{
	claimIssuer: true, claimSubject: true, claimAudience: true,
	claimExpires: true, claimNotBefore: true, claimIssuedAt: true,
	claimID: true, claimType: true, claimFamily: true,
}

// IsReservedClaim reports whether name is a claim managed by this package
// ("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "typ" and "fam"). Extra
// claims with these names are rejected with [ErrReservedClaim].
func IsReservedClaim(name string) bool {
	return reservedClaims[name]
}

// Claims is the verified content of a token.
type Claims struct {
	// ID is the unique token ID ("jti").
	ID string
	// Subject identifies the user ("sub").
	Subject string
	// Issuer is the "iss" claim, if any.
	Issuer string
	// Audience is the "aud" claim, if any.
	Audience []string
	// IssuedAt is the "iat" claim.
	IssuedAt time.Time
	// ExpiresAt is the "exp" claim.
	ExpiresAt time.Time
	// Type is the "typ" claim.
	Type TokenType
	// Extra holds every non-reserved claim. Values are decoded from JSON, so
	// numbers are float64, arrays are []any and objects are map[string]any.
	Extra map[string]any

	familyID string
}

// GetString returns the extra claim name if it is present and a string.
func (c *Claims) GetString(name string) (string, bool) {
	s, ok := c.Extra[name].(string)
	return s, ok
}

// TokenPair is the result of a login or refresh.
type TokenPair struct {
	AccessToken          string
	AccessTokenExpiresAt time.Time
	// RefreshToken is empty if no [RefreshTokenStore] is configured.
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

func checkExtraClaims(extra map[string]any) error {
	for k := range extra {
		if IsReservedClaim(k) {
			return fmt.Errorf("%w: %q", ErrReservedClaim, k)
		}
	}
	return nil
}

// toNumericDate truncates t to the whole second, the resolution of JWT time
// claims, so reported expiry times match what is encoded in the token.
func toNumericDate(t time.Time) time.Time {
	return time.Unix(t.Unix(), 0)
}

func (a *Authorizer) baseClaims(subject string, typ TokenType, id uuid.UUID, now, exp time.Time) jwt.MapClaims {
	mc := jwt.MapClaims{
		claimSubject:  subject,
		claimIssuedAt: now.Unix(),
		claimExpires:  exp.Unix(),
		claimID:       id.String(),
		claimType:     string(typ),
	}
	if a.s.Issuer != "" {
		mc[claimIssuer] = a.s.Issuer
	}
	if len(a.s.Audience) > 0 {
		mc[claimAudience] = a.s.Audience
	}
	return mc
}

func headerType(typ TokenType) string {
	if typ == TokenTypeAccess {
		return headerTypeAccess
	}
	return headerTypeRefresh
}

func (a *Authorizer) sign(ctx context.Context, typ TokenType, mc jwt.MapClaims) (string, error) {
	k, err := a.keys.signer(ctx)
	if err != nil {
		return "", err
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, mc)
	t.Header["kid"] = k.id.String()
	t.Header["typ"] = headerType(typ)
	s, err := t.SignedString(k.private)
	if err != nil {
		return "", fmt.Errorf("auth: signing token: %w", err)
	}
	return s, nil
}

func (a *Authorizer) issueAccess(ctx context.Context, subject string, extra map[string]any) (string, time.Time, error) {
	if subject == "" {
		return "", time.Time{}, errors.New("auth: subject must not be empty")
	}
	if err := checkExtraClaims(extra); err != nil {
		return "", time.Time{}, err
	}
	// Truncate before adding the TTL so the token lives for the full TTL.
	now := toNumericDate(a.s.now())
	exp := now.Add(a.s.AccessTokenTTL)
	mc := a.baseClaims(subject, TokenTypeAccess, uuid.New(), now, exp)
	for k, v := range extra {
		mc[k] = v
	}
	tok, err := a.sign(ctx, TokenTypeAccess, mc)
	return tok, exp, err
}

// issueRefresh records and signs a new refresh token in the given family,
// replacing parent (uuid.Nil for the first token of a login).
func (a *Authorizer) issueRefresh(ctx context.Context, subject string, family, parent uuid.UUID) (string, time.Time, error) {
	now := toNumericDate(a.s.now())
	exp := now.Add(a.s.RefreshTokenTTL)
	rec := RefreshTokenRecord{
		ID:       uuid.New(),
		ParentID: parent,
		FamilyID: family,
		Subject:  subject,
		IssuedAt: now,
		// The parser accepts the token until exp + Leeway, so the record
		// must survive that long.
		ExpiresAt: exp.Add(a.s.Leeway),
	}
	if err := a.s.refreshStore.CreateRefreshToken(ctx, rec); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: storing refresh token: %w", err)
	}
	mc := a.baseClaims(subject, TokenTypeRefresh, rec.ID, now, exp)
	mc[claimFamily] = family.String()
	tok, err := a.sign(ctx, TokenTypeRefresh, mc)
	return tok, exp, err
}

// issuePair issues an access token and, if refresh tokens are enabled, a
// refresh token in family.
func (a *Authorizer) issuePair(ctx context.Context, subject string, extra map[string]any, family, parent uuid.UUID) (*TokenPair, error) {
	if err := a.checkOpen(); err != nil {
		return nil, err
	}
	access, accessExp, err := a.issueAccess(ctx, subject, extra)
	if err != nil {
		return nil, err
	}
	pair := &TokenPair{AccessToken: access, AccessTokenExpiresAt: accessExp}
	if a.s.refreshStore == nil {
		return pair, nil
	}
	pair.RefreshToken, pair.RefreshTokenExpiresAt, err = a.issueRefresh(ctx, subject, family, parent)
	if err != nil {
		return nil, err
	}
	return pair, nil
}

// parse verifies tokenString and checks that it has type want. If
// validateTimes is false, expiry and issued-at are not checked; the
// signature, issuer and audience always are.
func (a *Authorizer) parse(ctx context.Context, tokenString string, want TokenType, validateTimes bool) (*Claims, error) {
	var internalErr error
	keyFunc := func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("%w: missing kid header", ErrInvalidToken)
		}
		id, err := uuid.Parse(kid)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed kid header", ErrInvalidToken)
		}
		key, err := a.keys.lookup(ctx, id)
		if err != nil && !errors.Is(err, ErrInvalidToken) {
			internalErr = err
		}
		return key, err
	}

	parser := a.parser
	if !validateTimes {
		parser = a.lenientParser
	}
	tok, err := parser.Parse(tokenString, keyFunc)
	switch {
	case internalErr != nil:
		return nil, internalErr
	case errors.Is(err, jwt.ErrTokenExpired) && validateTimes && !failedOtherClaimChecks(err):
		// Only a token that would otherwise be valid is merely expired. The
		// parser reported no claim failure besides expiry; re-check this
		// package's own requirements (type, required claims) too.
		if _, lenientErr := a.parse(ctx, tokenString, want, false); lenientErr != nil {
			return nil, lenientErr
		}
		return nil, fmt.Errorf("%w: %w", ErrTokenExpired, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if err := checkTokenType(tok, want); err != nil {
		return nil, err
	}
	mc := tok.Claims.(jwt.MapClaims)
	c, err := claimsFromMap(mc)
	if err != nil {
		return nil, err
	}
	if !validateTimes {
		// The lenient parser skips all claim validation, so check these here.
		if a.s.Issuer != "" && c.Issuer != a.s.Issuer {
			return nil, fmt.Errorf("%w: issuer mismatch", ErrInvalidToken)
		}
		if len(a.s.Audience) > 0 && !slices.ContainsFunc(c.Audience, func(s string) bool { return slices.Contains(a.s.Audience, s) }) {
			return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
		}
	}
	return c, nil
}

// otherClaimErrors are the claim validation failures besides expiry that the
// parser can report. It reports every failure at once, joined.
var otherClaimErrors = []error{
	jwt.ErrTokenNotValidYet,
	jwt.ErrTokenUsedBeforeIssued,
	jwt.ErrTokenInvalidIssuer,
	jwt.ErrTokenInvalidAudience,
	jwt.ErrTokenInvalidSubject,
	jwt.ErrTokenRequiredClaimMissing,
}

// failedOtherClaimChecks reports whether err includes a claim validation
// failure other than expiry.
func failedOtherClaimChecks(err error) bool {
	for _, e := range otherClaimErrors {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// checkTokenType verifies that both the "typ" header and the "typ" claim
// match want.
func checkTokenType(tok *jwt.Token, want TokenType) error {
	if h, _ := tok.Header["typ"].(string); h != headerType(want) {
		return fmt.Errorf("%w: expected %s header type, got %q", ErrInvalidToken, headerType(want), h)
	}
	mc, _ := tok.Claims.(jwt.MapClaims)
	if typ, _ := mc[claimType].(string); typ != string(want) {
		return fmt.Errorf("%w: expected %s token, got %q", ErrInvalidToken, want, typ)
	}
	return nil
}

func claimsFromMap(mc jwt.MapClaims) (*Claims, error) {
	invalid := func(what string) (*Claims, error) {
		return nil, fmt.Errorf("%w: missing or malformed %s claim", ErrInvalidToken, what)
	}
	var c Claims
	var ok bool
	var err error

	if c.Subject, err = mc.GetSubject(); err != nil || c.Subject == "" {
		return invalid(claimSubject)
	}
	if c.ID, ok = mc[claimID].(string); !ok || c.ID == "" {
		return invalid(claimID)
	}
	typ, ok := mc[claimType].(string)
	if !ok {
		return invalid(claimType)
	}
	c.Type = TokenType(typ)
	if fam, present := mc[claimFamily]; present {
		if c.familyID, ok = fam.(string); !ok {
			return invalid(claimFamily)
		}
	}
	if c.Issuer, err = mc.GetIssuer(); err != nil {
		return invalid(claimIssuer)
	}
	// GetAudience silently ignores values that are neither strings nor arrays.
	switch mc[claimAudience].(type) {
	case nil, string, []any:
	default:
		return invalid(claimAudience)
	}
	aud, err := mc.GetAudience()
	if err != nil {
		return invalid(claimAudience)
	}
	c.Audience = []string(aud)
	if iat, err := mc.GetIssuedAt(); err != nil {
		return invalid(claimIssuedAt)
	} else if iat != nil {
		c.IssuedAt = iat.Time
	}
	if exp, err := mc.GetExpirationTime(); err != nil || exp == nil {
		return invalid(claimExpires)
	} else {
		c.ExpiresAt = exp.Time
	}

	c.Extra = map[string]any{}
	for k, v := range mc {
		if !IsReservedClaim(k) {
			c.Extra[k] = v
		}
	}
	return &c, nil
}

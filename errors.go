package auth

import "errors"

// Errors returned by the package. They may be wrapped, so compare them with
// [errors.Is].
var (
	// ErrInvalidCredentials means the username or password was wrong. It is
	// returned for unknown users too, so callers cannot tell the two apart.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrInvalidToken means a token was malformed, had a bad signature, was
	// signed by an unknown key, failed issuer/audience checks, or was the
	// wrong kind of token (for example a refresh token used as an access token).
	ErrInvalidToken = errors.New("auth: invalid token")

	// ErrTokenExpired means a token was otherwise valid but has expired.
	ErrTokenExpired = errors.New("auth: token expired")

	// ErrNoToken means a request carried no token in the configured header
	// or cookie.
	ErrNoToken = errors.New("auth: no token")

	// ErrTokenRevoked means a refresh token was validly signed but no longer
	// exists in the [RefreshTokenStore] (logged out, or its family was revoked).
	ErrTokenRevoked = errors.New("auth: token revoked")

	// ErrRefreshTokenReused means an already-used refresh token was presented
	// again. This indicates the token was likely stolen, so the whole token
	// family has been revoked.
	ErrRefreshTokenReused = errors.New("auth: refresh token reused")

	// ErrReservedClaim means a caller-supplied claim used a name the package
	// manages itself (see [IsReservedClaim]).
	ErrReservedClaim = errors.New("auth: reserved claim name")

	// ErrNotConfigured means an operation needs a store or option that was
	// not supplied to [New].
	ErrNotConfigured = errors.New("auth: not configured")

	// ErrClosed means the [Authorizer] has been closed.
	ErrClosed = errors.New("auth: authorizer closed")

	// ErrInvalidHash means a stored password hash could not be parsed.
	ErrInvalidHash = errors.New("auth: invalid password hash")

	// ErrUserNotFound must be returned (optionally wrapped) by
	// [UserStore.LookupPasswordHash] when the user does not exist.
	ErrUserNotFound = errors.New("auth: user not found")

	// ErrKeyNotFound must be returned (optionally wrapped) by
	// [KeyStore.GetKey] when the key does not exist.
	ErrKeyNotFound = errors.New("auth: key not found")

	// ErrRefreshTokenNotFound must be returned (optionally wrapped) by
	// [RefreshTokenStore.ConsumeRefreshToken] when the token does not exist.
	ErrRefreshTokenNotFound = errors.New("auth: refresh token not found")
)

package auth

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"time"
)

// refreshPurgeMargin is how long past its ExpiresAt a refresh-token record or
// family is kept before the Authorizer purges it. A refresh accepted just
// before expiry consumes the old record and then creates the new one; the
// margin keeps the family alive in between, even if another instance's clock
// runs ahead of this one.
const refreshPurgeMargin = 5 * time.Minute

// maxJitterBase caps the duration jitter randomizes, so its result cannot
// overflow time.Duration.
const maxJitterBase = time.Duration(math.MaxInt64 / 2)

// PurgeExpiredRefreshTokens deletes expired refresh-token records and
// forgets expired families now, and returns how many the store removed. Use
// it to purge from a scheduled job instead of, or as well as, the background
// purge controlled by [Config.RefreshPurgeInterval].
//
// Records are kept for a few minutes past their ExpiresAt, so a refresh
// accepted just before expiry, or on an instance whose clock lags, still
// completes.
//
// It returns an error wrapping [ErrNotConfigured] if there is no
// [RefreshTokenStore] or the store does not implement [RefreshTokenPurger].
// It works after [Authorizer.Close].
func (a *Authorizer) PurgeExpiredRefreshTokens(ctx context.Context) (int64, error) {
	if err := a.s.requireRefreshStore(); err != nil {
		return 0, err
	}
	purger, ok := a.s.refreshStore.(RefreshTokenPurger)
	if !ok {
		return 0, fmt.Errorf("%w: RefreshTokenStore does not implement RefreshTokenPurger", ErrNotConfigured)
	}
	return a.purge(ctx, purger)
}

// purge removes what expired more than refreshPurgeMargin ago.
func (a *Authorizer) purge(ctx context.Context, p RefreshTokenPurger) (int64, error) {
	n, err := p.PurgeExpiredRefreshTokens(ctx, a.s.now().Add(-refreshPurgeMargin))
	if err != nil {
		return n, fmt.Errorf("auth: purging expired refresh tokens: %w", err)
	}
	return n, nil
}

// backgroundPurger returns the store to purge in the background, and whether
// background purging should run.
func (s *settings) backgroundPurger() (RefreshTokenPurger, bool) {
	if s.refreshStore == nil || s.RefreshPurgeInterval <= 0 {
		return nil, false
	}
	p, ok := s.refreshStore.(RefreshTokenPurger)
	return p, ok
}

// runPurge purges p about every RefreshPurgeInterval until ctx is cancelled.
// Failures are logged and retried on the next run.
func (a *Authorizer) runPurge(ctx context.Context, p RefreshTokenPurger, jitter func(time.Duration) time.Duration) {
	timer := time.NewTimer(jitter(a.s.RefreshPurgeInterval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		n, err := a.purge(ctx, p)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			a.s.logger.WarnContext(ctx, "auth: background refresh-token purge failed", "error", err)
		case n > 0:
			a.s.logger.DebugContext(ctx, "auth: purged expired refresh tokens", "count", n)
		}
		timer.Reset(jitter(a.s.RefreshPurgeInterval))
	}
}

// jitter returns a random duration in [0.75d, 1.25d). Durations over
// maxJitterBase are treated as maxJitterBase.
func jitter(d time.Duration) time.Duration {
	d = min(d, maxJitterBase)
	if spread := d / 2; spread > 0 {
		return d - d/4 + rand.N(spread)
	}
	return d
}

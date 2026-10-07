package auth

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"
)

// PurgeExpiredRefreshTokens deletes expired refresh-token records and
// forgets expired families now, and returns how many the store removed. Use
// it to purge from a scheduled job instead of, or as well as, the background
// purge controlled by [Config.RefreshPurgeInterval].
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
	n, err := purger.PurgeExpiredRefreshTokens(ctx, a.s.now())
	if err != nil {
		return n, fmt.Errorf("auth: purging expired refresh tokens: %w", err)
	}
	return n, nil
}

// backgroundPurger reports whether background purging should run, and the
// store to purge.
func (s *settings) backgroundPurger() (RefreshTokenPurger, bool) {
	if s.refreshStore == nil || s.RefreshPurgeInterval <= 0 {
		return nil, false
	}
	p, ok := s.refreshStore.(RefreshTokenPurger)
	return p, ok
}

// runPurge calls PurgeExpiredRefreshTokens about every RefreshPurgeInterval
// until ctx is cancelled. Failures are logged and retried on the next run.
func (a *Authorizer) runPurge(ctx context.Context, jitter func(time.Duration) time.Duration) {
	timer := time.NewTimer(jitter(a.s.RefreshPurgeInterval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		n, err := a.PurgeExpiredRefreshTokens(ctx)
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

// jitter returns a random duration in [0.75d, 1.25d).
func jitter(d time.Duration) time.Duration {
	if spread := d / 2; spread > 0 {
		return d - d/4 + rand.N(spread)
	}
	return d
}

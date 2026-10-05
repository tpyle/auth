# Configuration

You configure an `Authorizer` with functional options passed to `auth.New`. The options fall into two groups:

- **Plain-data settings** live in `auth.Config`. You can set them all at once with `WithConfig`, or one at a time with the matching `With*` option.
- **Behavior** (stores, callbacks, logger, clock) can be set only through options.

`New` starts from `DefaultConfig()`, applies the options in order, and then calls `Config.Validate`. If any setting is invalid, `New` returns every problem at once, joined with `errors.Join`.

## Config fields

| Field | mapstructure key | Default | Meaning |
|---|---|---|---|
| `Argon2.MemoryKiB` | `argon2.memory_kib` | `65536` (64 MiB) | Argon2id memory cost for new hashes. Each running hash allocates this much. |
| `Argon2.Iterations` | `argon2.iterations` | `3` | Argon2id time cost (passes over memory). |
| `Argon2.Parallelism` | `argon2.parallelism` | `4` | Lanes (threads) per hash. |
| `Argon2.SaltLength` | `argon2.salt_length` | `16` | Salt length in bytes. Minimum 8. |
| `Argon2.KeyLength` | `argon2.key_length` | `32` | Hash output length in bytes. Minimum 16. |
| `MaxConcurrentHashes` | `max_concurrent_hashes` | `max(1, runtime.NumCPU() / 4)` | Maximum number of Argon2 computations at once. Extra callers wait or give up when their `ctx` is cancelled. Peak hashing memory is about this × `MemoryKiB`. Must be ≥ 1. |
| `AccessTokenTTL` | `access_token_ttl` | `15m` | Lifetime of access tokens. Must be > 0. |
| `RefreshTokenTTL` | `refresh_token_ttl` | `168h` (7 days) | Lifetime of each refresh token. Each refresh issues a new one, so a session lasts as long as it is refreshed at least this often. Must be > 0. |
| `RefreshReuseGrace` | `refresh_reuse_grace` | `30s` | How long after a refresh token's **first** use it may be presented again and still get a new pair in the same session, instead of being treated as stolen. Covers concurrent refreshes (several tabs) and retries after a lost response. `0` is strict: any reuse revokes the session. Must be ≥ 0. See [reuse detection](Tokens-and-Keys.md#reuse-detection). |
| `KeyRotationInterval` | `key_rotation_interval` | `24h` | How often this process switches to a new signing key. Each key is stored one interval before it starts signing. `0` turns rotation off: the process signs with one key for its whole life, and stored keys never expire, so they pile up across restarts. Must be ≥ 0. |
| `KeyCacheTTL` | `key_cache_ttl` | `5m` | How often each instance reloads its in-memory copy of the key set from the `KeyStore` with `ListKeys`. Unknown key IDs also trigger a reload, at most once per second. A key deleted from the store can keep working for up to this long. `0` reloads on every verification of another instance's token, still at most once per second. Must be ≥ 0. |
| `Issuer` | `issuer` | `""` | If set, written to `iss` and required on verification. |
| `Audience` | `audience` | `nil` | If set, written to `aud`. Verification requires the token's `aud` to contain at least one of these values. |
| `Leeway` | `leeway` | `0` | Allowed clock skew when checking `exp` and `iat`. Must be ≥ 0. |
| `AuthHeader` | `auth_header` | `"Authorization"` | Request header that carries `Bearer <token>`. `""` turns header authentication off. |
| `AuthCookie` | `auth_cookie` | `""` | Cookie that carries a raw access token. `""` turns cookie authentication off. If both are on, the header wins. |

`Argon2Params.Validate` also requires `Iterations ≥ 1`, `Parallelism ≥ 1`, and `MemoryKiB ≥ 8 × Parallelism`.

## Options

| Option | Effect |
|---|---|
| `WithConfig(cfg Config)` | Replaces **all** plain-data settings with `cfg`. |
| `WithArgon2Params(p Argon2Params)` | Sets `Config.Argon2`. |
| `WithMaxConcurrentHashes(n int)` | Sets `Config.MaxConcurrentHashes`. |
| `WithAccessTokenTTL(d)` | Sets `Config.AccessTokenTTL`. |
| `WithRefreshTokenTTL(d)` | Sets `Config.RefreshTokenTTL`. |
| `WithRefreshReuseGrace(d)` | Sets `Config.RefreshReuseGrace`. |
| `WithKeyRotationInterval(d)` | Sets `Config.KeyRotationInterval`. |
| `WithKeyCacheTTL(d)` | Sets `Config.KeyCacheTTL`. |
| `WithIssuer(iss string)` | Sets `Config.Issuer`. |
| `WithAudience(aud ...string)` | Sets `Config.Audience`. |
| `WithLeeway(d)` | Sets `Config.Leeway`. |
| `WithAuthHeader(name string)` | Sets `Config.AuthHeader`. `""` turns it off. |
| `WithAuthCookie(name string)` | Sets `Config.AuthCookie`. `""` turns it off. |
| `WithUserStore(UserStore)` | Needed by `Authenticate` and `Login`. |
| `WithKeyStore(KeyStore)` | Where public signing keys are persisted. Default: a private `MemoryKeyStore`. |
| `WithRefreshTokenStore(RefreshTokenStore)` | Turns on refresh tokens, `Refresh`, `Logout` and `RevokeAllSessions`. |
| `WithClaimsProvider(ClaimsProvider)` | Adds extra access-token claims on `Login` and `Refresh`. |
| `WithUnauthorizedHandler(UnauthorizedHandler)` | Replaces the response written by `RequireAuthHandler` when it rejects a request. See [HTTP Middleware](HTTP-Middleware.md). |
| `WithLogger(*slog.Logger)` | Logger for background errors (key rotation), failed hash upgrades and middleware internal errors. Default: `slog.Default()`. |
| `WithClock(func() time.Time)` | Replaces the time source. Meant for tests. |

The two callback types are:

```go
type ClaimsProvider func(ctx context.Context, subject string) (map[string]any, error)
type UnauthorizedHandler func(w http.ResponseWriter, r *http.Request, err error)
```

A `ClaimsProvider` must not return reserved claim names (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `typ`, `fam`). If it does, the call fails with `ErrReservedClaim`.

## Option ordering and WithConfig

Options run in the order given. `WithConfig` overwrites every plain-data field, including fields that earlier options set. Put it **first** and add individual overrides after it:

```go
cfg := auth.DefaultConfig()
cfg.Issuer = "https://auth.example.com"

a, err := auth.New(ctx,
	auth.WithConfig(cfg),
	auth.WithAccessTokenTTL(5*time.Minute), // overrides cfg.AccessTokenTTL
	auth.WithUserStore(users),              // stores are not part of Config; order does not matter
)
```

If `WithAccessTokenTTL` came before `WithConfig`, its value would be lost.

Always build the `Config` you pass to `WithConfig` from `DefaultConfig()`. A zero `Config{}` fails validation because the TTLs, `MaxConcurrentHashes` and Argon2 parameters are all zero. It would also turn off header authentication.

## Loading configuration with Viper

The library does not depend on Viper or any other configuration library. `Config` and `Argon2Params` have `mapstructure` tags, so Viper (or anything else built on mapstructure) can decode straight into them. Start from the defaults so that keys left out of the file keep their default values:

```go
package main

import (
	"context"
	"log"

	"github.com/spf13/viper"
	"github.com/tpyle/auth/v2"
)

func main() {
	ctx := context.Background()

	v := viper.New()
	v.SetConfigFile("config.yaml")
	if err := v.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	cfg := auth.DefaultConfig()
	if err := v.UnmarshalKey("auth", &cfg); err != nil {
		log.Fatal(err)
	}

	a, err := auth.New(ctx, auth.WithConfig(cfg))
	if err != nil {
		log.Fatal(err) // includes validation errors from the file
	}
	defer a.Close()
}
```

`config.yaml`:

```yaml
auth:
  argon2:
    memory_kib: 65536
    iterations: 3
    parallelism: 4
    salt_length: 16
    key_length: 32
  max_concurrent_hashes: 8
  access_token_ttl: 15m
  refresh_token_ttl: 168h      # Go durations have no "d" unit
  refresh_reuse_grace: 30s     # 0 = strict reuse detection
  key_rotation_interval: 24h
  key_cache_ttl: 5m
  issuer: https://auth.example.com
  audience:
    - https://api.example.com
  leeway: 30s
  auth_header: Authorization
  auth_cookie: ""              # empty disables cookie auth
```

Durations are written as Go duration strings (`"15m"`, `"168h"`, `"1h30m"`). Viper's default decode hooks turn them into `time.Duration`. Every key is optional. Keys you leave out keep the value from `DefaultConfig()`.

package auth

import (
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

type Option func(*Options)

type Options struct {
	SaltLength    uint32
	HashTime      uint32
	HashMemoryKiB uint32
	HashThreads   uint8
	KeyLength     uint32

	SigningKeyValidity     time.Duration // How long signing keys are valid for. If zero, keys never expire. Keys are still rotated if SigningKeyCreationFreq is set.
	SigningKeyCreationFreq time.Duration // How often new signing keys are created. If zero, no new keys are created. To avoid storing signing keys, new keys will be created on startup always.
	ExpirationTime         time.Duration // How long tokens are valid for. Must not be zero.

	AuthHeader *string
	AuthCookie *string

	StoreNewSigningKeyFunc       func(*KeyPairWithCreationTime) error
	GetSigningKeyFunc            func(kid *uuid.UUID) ([]KeyPairWithCreationTime, error)
	GetSigningKeysFunc           func() ([]*KeyPairWithCreationTime, error)
	DeleteExpiredSigningKeyFunc  func(uuid.UUID) error
	DeleteExpiredSigningKeysFunc func([]uuid.UUID) error
	LookupUserPasswordFunc       func(username string) (string, error)

	ViperRef *viper.Viper
}

func stringP(s string) *string {
	return &s
}

func getDefaultOptions() *Options {
	return &Options{
		SaltLength:    16,
		HashTime:      4,
		HashMemoryKiB: 128 * 1024,
		HashThreads:   4,
		KeyLength:     32,

		SigningKeyValidity:     0,
		SigningKeyCreationFreq: 0,
		ExpirationTime:         time.Hour * 24,

		AuthHeader: stringP("Authorization"),
		AuthCookie: nil,
	}
}

func WithSaltLength(length uint32) Option {
	return func(o *Options) {
		o.SaltLength = length
	}
}

func WithHashTime(time uint32) Option {
	return func(o *Options) {
		o.HashTime = time
	}
}

func WithHashMemoryKiB(memory uint32) Option {
	return func(o *Options) {
		o.HashMemoryKiB = memory
	}
}

func WithHashThreads(threads uint8) Option {
	return func(o *Options) {
		o.HashThreads = threads
	}
}

func WithKeyLength(length uint32) Option {
	return func(o *Options) {
		o.KeyLength = length
	}
}

func WithSigningKeyValidity(d time.Duration) Option {
	return func(o *Options) {
		o.SigningKeyValidity = d
	}
}

func WithSigningKeyCreationFreq(d time.Duration) Option {
	return func(o *Options) {
		o.SigningKeyCreationFreq = d
	}
}

func WithExpirationTime(d time.Duration) Option {
	return func(o *Options) {
		o.ExpirationTime = d
	}
}

// Set the name of the HTTP header to look for the authorization token in.
// If nil, no header is used.
func WithAuthHeader(header *string) Option {
	return func(o *Options) {
		o.AuthHeader = header
	}
}

// Set the name of the cookie to look for the authorization token in.
// If nil, no cookie is used.
func WithAuthCookie(cookie *string) Option {
	return func(o *Options) {
		o.AuthCookie = cookie
	}
}

func WithLookupUserPasswordFunc(f func(username string) (string, error)) Option {
	return func(o *Options) {
		o.LookupUserPasswordFunc = f
	}
}

func WithStoreNewSigningKeyFunc(f func(*KeyPairWithCreationTime) error) Option {
	return func(o *Options) {
		o.StoreNewSigningKeyFunc = f
	}
}

func WithGetSigningKeyFunc(f func(kid *uuid.UUID) ([]KeyPairWithCreationTime, error)) Option {
	return func(o *Options) {
		o.GetSigningKeyFunc = f
	}
}

func WithGetSigningKeysFunc(f func() ([]*KeyPairWithCreationTime, error)) Option {
	return func(o *Options) {
		o.GetSigningKeysFunc = f
	}
}

func WithDeleteExpiredSigningKeyFunc(f func(uuid.UUID) error) Option {
	return func(o *Options) {
		o.DeleteExpiredSigningKeyFunc = f
	}
}

func WithDeleteExpiredSigningKeysFunc(f func([]uuid.UUID) error) Option {
	return func(o *Options) {
		o.DeleteExpiredSigningKeysFunc = f
	}
}

func WithViper(v *viper.Viper) Option {
	return WithViperPrefix(v, "")
}

func WithViperPrefix(v *viper.Viper, prefix string) Option {
	return func(o *Options) {
		o.ViperRef = v

		if v != nil {
			v.SetDefault(prefix+"auth.salt_length", o.SaltLength)
			v.SetDefault(prefix+"auth.hash_time", o.HashTime)
			v.SetDefault(prefix+"auth.hash_memory_kib", o.HashMemoryKiB)
			v.SetDefault(prefix+"auth.hash_threads", o.HashThreads)
			v.SetDefault(prefix+"auth.key_length", o.KeyLength)
			v.SetDefault(prefix+"auth.signing_key_validity", o.SigningKeyValidity)
			v.SetDefault(prefix+"auth.signing_key_creation_freq", o.SigningKeyCreationFreq)
			v.SetDefault(prefix+"auth.expiration_time", o.ExpirationTime)
			v.SetDefault(prefix+"auth.auth_header", o.AuthHeader)
			v.SetDefault(prefix+"auth.auth_cookie", o.AuthCookie)

			o.SaltLength = uint32(v.GetInt(prefix + "auth.salt_length"))
			o.HashTime = uint32(v.GetInt(prefix + "auth.hash_time"))
			o.HashMemoryKiB = uint32(v.GetInt(prefix + "auth.hash_memory_kib"))
			o.HashThreads = uint8(v.GetInt(prefix + "auth.hash_threads"))
			o.KeyLength = uint32(v.GetInt(prefix + "auth.key_length"))
			o.SigningKeyValidity = v.GetDuration(prefix + "auth.signing_key_validity")
			o.SigningKeyCreationFreq = v.GetDuration(prefix + "auth.signing_key_creation_freq")
			o.ExpirationTime = v.GetDuration(prefix + "auth.expiration_time")

			s := v.GetString(prefix + "auth.auth_header")
			if s != "" {
				o.AuthHeader = stringP(s)
			} else {
				o.AuthHeader = nil
			}

			sc := v.GetString(prefix + "auth.auth_cookie")
			if sc != "" {
				o.AuthCookie = stringP(sc)
			} else {
				o.AuthCookie = nil
			}
		}
	}
}

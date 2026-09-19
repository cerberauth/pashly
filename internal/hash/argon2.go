package hash

import (
	"fmt"
	"regexp"
	"strconv"

	"golang.org/x/crypto/argon2"
)

// argon2RE matches $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash> and the
// argon2i equivalent.
var argon2RE = regexp.MustCompile(`^\$(argon2id|argon2i)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$`)

const argon2Version = argon2.Version // 19

// Defaults follow the current OWASP Password Storage Cheat Sheet:
// argon2id: m=19MiB (19456 KiB), t=2, p=1; argon2i: m=12MiB (12288 KiB), t=3, p=1.
var argon2Defaults = map[string]Params{
	IDArgon2id: {Memory: 19456, Time: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32},
	IDArgon2i:  {Memory: 12288, Time: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32},
}

type argon2Algorithm struct {
	variant string // "argon2id" or "argon2i"
}

func (a argon2Algorithm) ID() string     { return a.variant }
func (argon2Algorithm) LegacyOnly() bool { return false }

func (a argon2Algorithm) DefaultParams() Params {
	return argon2Defaults[a.variant]
}

func (a argon2Algorithm) Hash(password []byte, params Params) (Result, error) {
	p := fillArgon2Defaults(a.variant, params)
	if p.Parallelism > 255 {
		return Result{}, fmt.Errorf("argon2 parallelism must be between 1 and 255, got %d", p.Parallelism)
	}
	salt, err := randomSalt(p.SaltLength)
	if err != nil {
		return Result{}, err
	}
	key := deriveArgon2(a.variant, password, salt, p)
	return Result{Algorithm: a.ID(), Params: p, Salt: salt, Key: key}, nil
}

func fillArgon2Defaults(variant string, p Params) Params {
	d := argon2Defaults[variant]
	if p.Memory == 0 {
		p.Memory = d.Memory
	}
	if p.Time == 0 {
		p.Time = d.Time
	}
	if p.Parallelism == 0 {
		p.Parallelism = d.Parallelism
	}
	if p.SaltLength == 0 {
		p.SaltLength = d.SaltLength
	}
	if p.KeyLength == 0 {
		p.KeyLength = d.KeyLength
	}
	return p
}

// deriveArgon2 assumes p.Parallelism has already been validated to fit in
// a uint8 by every caller (Hash and Decode).
func deriveArgon2(variant string, password, salt []byte, p Params) []byte {
	parallelism := uint8(p.Parallelism) // #nosec G115 -- validated <= 255 by callers
	keyLen := uint32(p.KeyLength)       // #nosec G115 -- KeyLength is always a small positive constant or CLI-validated non-negative
	if variant == IDArgon2id {
		return argon2.IDKey(password, salt, p.Time, p.Memory, parallelism, keyLen)
	}
	return argon2.Key(password, salt, p.Time, p.Memory, parallelism, keyLen)
}

func (a argon2Algorithm) Encode(r Result) (string, error) {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		a.variant, argon2Version, r.Params.Memory, r.Params.Time, r.Params.Parallelism,
		b64Encode(r.Salt), b64Encode(r.Key)), nil
}

func (a argon2Algorithm) Decode(encoded string) (Result, error) {
	m := argon2RE.FindStringSubmatch(encoded)
	if m == nil || m[1] != a.variant {
		return Result{}, fmt.Errorf("not a valid %s hash", a.variant)
	}
	memory, _ := strconv.Atoi(m[3])
	time, _ := strconv.Atoi(m[4])
	parallelism, _ := strconv.Atoi(m[5])
	if parallelism < 0 || parallelism > 255 {
		return Result{}, fmt.Errorf("parallelism out of range: %d", parallelism)
	}
	salt, err := b64Decode(m[6])
	if err != nil {
		return Result{}, fmt.Errorf("decoding salt: %w", err)
	}
	key, err := b64Decode(m[7])
	if err != nil {
		return Result{}, fmt.Errorf("decoding hash: %w", err)
	}
	// memory/time/parallelism were matched by `\d+` in argon2RE, so
	// strconv.Atoi cannot have returned a negative value here.
	return Result{
		Algorithm: a.ID(),
		Params: Params{
			Memory:      uint32(memory),      // #nosec G115
			Time:        uint32(time),        // #nosec G115
			Parallelism: uint32(parallelism), // #nosec G115
			SaltLength:  len(salt),
			KeyLength:   len(key),
		},
		Salt: salt,
		Key:  key,
	}, nil
}

func (a argon2Algorithm) Detect(encoded string) bool {
	m := argon2RE.FindStringSubmatch(encoded)
	return m != nil && m[1] == a.variant
}

func (a argon2Algorithm) Verify(password []byte, encoded string) (bool, error) {
	r, err := a.Decode(encoded)
	if err != nil {
		return false, err
	}
	derived := deriveArgon2(a.variant, password, r.Salt, r.Params)
	return constantTimeEqual(derived, r.Key), nil
}

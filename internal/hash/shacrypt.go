package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"strings"
)

// shaCryptRE matches the glibc/Drepper sha256-crypt and sha512-crypt
// format: $5$[rounds=N$]salt$hash or $6$[rounds=N$]salt$hash.
// The salt field itself may be longer than 16 characters in the wild (see
// TestSha256CryptKnownVectors' "toolongsaltstring" vector); only the first
// 16 bytes are actually used when computing the digest (shaCryptSalt).
var shaCryptRE = regexp.MustCompile(`^\$([56])\$(?:rounds=([0-9]+)\$)?([./0-9A-Za-z]{1,64})\$([./0-9A-Za-z]+)$`)

const shaCryptMaxSaltLen = 16

const (
	shaCryptDefaultRounds = 5000
	shaCryptMinRounds     = 1000
	shaCryptMaxRounds     = 999999999
)

// shaCryptAlgorithm implements the legacy sha256-crypt/sha512-crypt formats
// for verify/info only; it is never offered as a hash target.
type shaCryptAlgorithm struct {
	id         string
	prefix     string
	newHash    func() hash.Hash
	encodedLen int
	encode     func(final []byte) string
}

func (a shaCryptAlgorithm) ID() string          { return a.id }
func (shaCryptAlgorithm) LegacyOnly() bool      { return true }
func (shaCryptAlgorithm) DefaultParams() Params { return Params{} }
func (shaCryptAlgorithm) Hash([]byte, Params) (Result, error) {
	return Result{}, ErrLegacyHashTarget
}

func (shaCryptAlgorithm) Encode(Result) (string, error) {
	return "", ErrLegacyHashTarget
}

func (a shaCryptAlgorithm) Detect(encoded string) bool {
	m := shaCryptRE.FindStringSubmatch(encoded)
	return m != nil && m[1] == a.prefix && len(m[4]) == a.encodedLen
}

func (a shaCryptAlgorithm) Decode(encoded string) (Result, error) {
	m := shaCryptRE.FindStringSubmatch(encoded)
	if m == nil || m[1] != a.prefix {
		return Result{}, fmt.Errorf("not a valid $%s$ sha-crypt hash", a.prefix)
	}
	if len(m[4]) != a.encodedLen {
		return Result{}, fmt.Errorf("unexpected hash length for $%s$ sha-crypt", a.prefix)
	}

	rounds := shaCryptDefaultRounds
	if m[2] != "" {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			return Result{}, fmt.Errorf("invalid rounds value")
		}
		rounds = n
	}
	if rounds < shaCryptMinRounds {
		rounds = shaCryptMinRounds
	}
	if rounds > shaCryptMaxRounds {
		rounds = shaCryptMaxRounds
	}

	return Result{
		Algorithm: a.ID(),
		Params:    Params{Iterations: rounds},
		Salt:      []byte(m[3]),
		Key:       []byte(m[4]),
	}, nil
}

func (a shaCryptAlgorithm) Verify(password []byte, encoded string) (bool, error) {
	r, err := a.Decode(encoded)
	if err != nil {
		return false, err
	}
	salt := r.Salt
	if len(salt) > shaCryptMaxSaltLen {
		salt = salt[:shaCryptMaxSaltLen]
	}
	final := shaCryptDigest(a.newHash, password, salt, r.Params.Iterations)
	computed := a.encode(final)
	return constantTimeEqual([]byte(computed), r.Key), nil
}

// shaCryptDigest implements the core of the Drepper sha256-crypt/
// sha512-crypt algorithm: an md5crypt-like iterated construction,
// generalized to a configurable round count and digest size.
func shaCryptDigest(newHash func() hash.Hash, password, salt []byte, rounds int) []byte {
	pwLen := len(password)
	digestSize := newHash().Size()

	ctxB := newHash()
	ctxB.Write(password)
	ctxB.Write(salt)
	ctxB.Write(password)
	digestB := ctxB.Sum(nil)

	ctxA := newHash()
	ctxA.Write(password)
	ctxA.Write(salt)
	for i := pwLen; i > 0; i -= digestSize {
		n := i
		if n > digestSize {
			n = digestSize
		}
		ctxA.Write(digestB[:n])
	}
	for i := pwLen; i > 0; i >>= 1 {
		if i&1 != 0 {
			ctxA.Write(digestB)
		} else {
			ctxA.Write(password)
		}
	}
	digestA := ctxA.Sum(nil)

	ctxDP := newHash()
	for i := 0; i < pwLen; i++ {
		ctxDP.Write(password)
	}
	dp := ctxDP.Sum(nil)
	p := shaCryptStretch(dp, pwLen)

	ctxDS := newHash()
	dsCount := 16 + int(digestA[0])
	for i := 0; i < dsCount; i++ {
		ctxDS.Write(salt)
	}
	ds := ctxDS.Sum(nil)
	s := shaCryptStretch(ds, len(salt))

	current := digestA
	for round := 0; round < rounds; round++ {
		ctxC := newHash()
		if round%2 != 0 {
			ctxC.Write(p)
		} else {
			ctxC.Write(current)
		}
		if round%3 != 0 {
			ctxC.Write(s)
		}
		if round%7 != 0 {
			ctxC.Write(p)
		}
		if round%2 != 0 {
			ctxC.Write(current)
		} else {
			ctxC.Write(p)
		}
		current = ctxC.Sum(nil)
	}

	return current
}

// shaCryptStretch produces a byte sequence of length by cycling through
// digest's bytes, per the DP/DS-sequence step of the sha-crypt algorithm.
func shaCryptStretch(digest []byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = digest[i%len(digest)]
	}
	return out
}

// shaCryptTo64 appends n itoa64-encoded characters of v's low bits to out.
func shaCryptTo64(out *strings.Builder, v uint32, n int) {
	for ; n > 0; n-- {
		out.WriteByte(itoa64[v&0x3f])
		v >>= 6
	}
}

// sha256CryptEncode implements sha256-crypt's specific permuted byte
// grouping and itoa64 encoding of the final 32-byte digest.
func sha256CryptEncode(final []byte) string {
	groups := [][3]int{
		{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14},
		{15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29},
	}
	var out strings.Builder
	for _, g := range groups {
		v := uint32(final[g[0]])<<16 | uint32(final[g[1]])<<8 | uint32(final[g[2]])
		shaCryptTo64(&out, v, 4)
	}
	v := uint32(final[31])<<8 | uint32(final[30])
	shaCryptTo64(&out, v, 3)
	return out.String()
}

// sha512CryptEncode implements sha512-crypt's specific permuted byte
// grouping and itoa64 encoding of the final 64-byte digest.
func sha512CryptEncode(final []byte) string {
	groups := [][3]int{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4},
		{47, 5, 26}, {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51},
		{31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35},
		{15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19},
		{62, 20, 41},
	}
	var out strings.Builder
	for _, g := range groups {
		v := uint32(final[g[0]])<<16 | uint32(final[g[1]])<<8 | uint32(final[g[2]])
		shaCryptTo64(&out, v, 4)
	}
	v := uint32(final[63])
	shaCryptTo64(&out, v, 2)
	return out.String()
}

func newSha256CryptAlgorithm() shaCryptAlgorithm {
	return shaCryptAlgorithm{
		id:         IDSha256Crypt,
		prefix:     "5",
		newHash:    sha256.New,
		encodedLen: 43,
		encode:     sha256CryptEncode,
	}
}

func newSha512CryptAlgorithm() shaCryptAlgorithm {
	return shaCryptAlgorithm{
		id:         IDSha512Crypt,
		prefix:     "6",
		newHash:    sha512.New,
		encodedLen: 86,
		encode:     sha512CryptEncode,
	}
}

package hash

import (
	"crypto/md5" //nolint:gosec // md5-crypt is a legacy, verify/info-only format (see threat model)
	"fmt"
	"regexp"
)

// md5CryptRE matches the classic $1$<salt>$<hash> format
// (Poul-Henning Kamp, 1994/1995 FreeBSD md5crypt).
var md5CryptRE = regexp.MustCompile(`^\$1\$([^$]{1,8})\$([./0-9A-Za-z]{22})$`)

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// md5CryptAlgorithm implements the legacy md5-crypt format for verify/info
// only; it is never offered as a hash target.
type md5CryptAlgorithm struct{}

func (md5CryptAlgorithm) ID() string            { return IDMD5Crypt }
func (md5CryptAlgorithm) LegacyOnly() bool      { return true }
func (md5CryptAlgorithm) DefaultParams() Params { return Params{} }

func (md5CryptAlgorithm) Hash([]byte, Params) (Result, error) {
	return Result{}, ErrLegacyHashTarget
}

func (md5CryptAlgorithm) Encode(Result) (string, error) {
	return "", ErrLegacyHashTarget
}

func (a md5CryptAlgorithm) Decode(encoded string) (Result, error) {
	m := md5CryptRE.FindStringSubmatch(encoded)
	if m == nil {
		return Result{}, fmt.Errorf("not a valid md5-crypt hash")
	}
	return Result{
		Algorithm: a.ID(),
		Salt:      []byte(m[1]),
		Key:       []byte(m[2]),
	}, nil
}

func (md5CryptAlgorithm) Detect(encoded string) bool {
	return md5CryptRE.MatchString(encoded)
}

func (a md5CryptAlgorithm) Verify(password []byte, encoded string) (bool, error) {
	r, err := a.Decode(encoded)
	if err != nil {
		return false, err
	}
	computed := md5CryptDigest(password, r.Salt)
	return constantTimeEqual([]byte(computed), r.Key), nil
}

// md5CryptDigest reproduces the classic md5crypt algorithm's 22-character
// itoa64-encoded digest, given a plaintext password and salt.
func md5CryptDigest(password, salt []byte) string {
	magic := []byte("$1$")

	ctx1 := md5.New() //nolint:gosec
	ctx1.Write(password)
	ctx1.Write(magic)
	ctx1.Write(salt)

	ctx2 := md5.New() //nolint:gosec
	ctx2.Write(password)
	ctx2.Write(salt)
	ctx2.Write(password)
	final := ctx2.Sum(nil)

	for pl := len(password); pl > 0; pl -= 16 {
		n := pl
		if n > 16 {
			n = 16
		}
		ctx1.Write(final[:n])
	}

	for i := len(password); i != 0; i >>= 1 {
		if i&1 != 0 {
			ctx1.Write([]byte{0})
		} else {
			ctx1.Write(password[:1])
		}
	}

	final = ctx1.Sum(nil)

	for i := 0; i < 1000; i++ {
		ctx3 := md5.New() //nolint:gosec
		if i&1 != 0 {
			ctx3.Write(password)
		} else {
			ctx3.Write(final)
		}
		if i%3 != 0 {
			ctx3.Write(salt)
		}
		if i%7 != 0 {
			ctx3.Write(password)
		}
		if i&1 != 0 {
			ctx3.Write(final)
		} else {
			ctx3.Write(password)
		}
		final = ctx3.Sum(nil)
	}

	to64 := func(v uint32, n int) string {
		out := make([]byte, 0, n)
		for ; n > 0; n-- {
			out = append(out, itoa64[v&0x3f])
			v >>= 6
		}
		return string(out)
	}

	var out string
	out += to64(uint32(final[0])<<16|uint32(final[6])<<8|uint32(final[12]), 4)
	out += to64(uint32(final[1])<<16|uint32(final[7])<<8|uint32(final[13]), 4)
	out += to64(uint32(final[2])<<16|uint32(final[8])<<8|uint32(final[14]), 4)
	out += to64(uint32(final[3])<<16|uint32(final[9])<<8|uint32(final[15]), 4)
	out += to64(uint32(final[4])<<16|uint32(final[10])<<8|uint32(final[5]), 4)
	out += to64(uint32(final[11]), 2)

	return out
}

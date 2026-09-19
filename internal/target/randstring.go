package target

import (
	"crypto/rand"
	"math/big"
)

// base62Alphabet matches Django's default RANDOM_STRING_CHARS.
const base62Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomASCIIString generates a CSPRNG string of printable base62
// characters, safe to embed directly in a $-delimited text format (used by
// the django adapter, whose salt is stored as literal text rather than
// base64).
func randomASCIIString(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(base62Alphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = base62Alphabet[idx.Int64()]
	}
	return string(out), nil
}

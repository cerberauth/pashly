// Package genpass generates cryptographically random passwords.
package genpass

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*()-_=+[]{}<>?"

	// ambiguous characters that are easily confused with one another when
	// read aloud or in some fonts (il1Lo0O and a few symbol lookalikes).
	ambiguous = "il1Lo0O|"
)

// Charset selects which character classes generated passwords draw from.
type Charset struct {
	// Custom, when non-empty, is used verbatim instead of a named preset.
	Custom      string
	NoAmbiguous bool
}

// Alphabet returns the resolved, de-duplicated set of characters a
// password may be drawn from for the given preset name
// ("alnum" | "alnum-symbols" | "custom:...").
func Alphabet(preset string, noAmbiguous bool) (string, error) {
	var chars string
	switch {
	case preset == "alnum":
		chars = lower + upper + digits
	case preset == "alnum-symbols" || preset == "":
		chars = lower + upper + digits + symbols
	case strings.HasPrefix(preset, "custom:"):
		chars = strings.TrimPrefix(preset, "custom:")
		if chars == "" {
			return "", fmt.Errorf("custom charset must not be empty")
		}
	default:
		return "", fmt.Errorf("unknown charset %q (expected alnum, alnum-symbols, or custom:\"...\")", preset)
	}

	if noAmbiguous {
		chars = strings.Map(func(r rune) rune {
			if strings.ContainsRune(ambiguous, r) {
				return -1
			}
			return r
		}, chars)
	}

	chars = dedupe(chars)
	if len(chars) == 0 {
		return "", fmt.Errorf("resolved charset is empty")
	}
	return chars, nil
}

func dedupe(s string) string {
	seen := make(map[rune]bool, len(s))
	var out strings.Builder
	for _, r := range s {
		if !seen[r] {
			seen[r] = true
			out.WriteRune(r)
		}
	}
	return out.String()
}

// Generate returns a single CSPRNG password of the given length drawn from
// alphabet.
func Generate(length int, alphabet string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be positive")
	}
	runes := []rune(alphabet)
	max := big.NewInt(int64(len(runes)))

	out := make([]rune, length)
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = runes[idx.Int64()]
	}
	return string(out), nil
}

// GenerateMany returns count independently generated passwords.
func GenerateMany(count, length int, alphabet string) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("count must be positive")
	}
	out := make([]string, count)
	for i := range out {
		p, err := Generate(length, alphabet)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}

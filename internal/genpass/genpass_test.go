package genpass

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlphabetPresets(t *testing.T) {
	alnum, err := Alphabet("alnum", false)
	require.NoError(t, err)
	assert.NotContains(t, alnum, "!")

	withSymbols, err := Alphabet("alnum-symbols", false)
	require.NoError(t, err)
	assert.Contains(t, withSymbols, "!")

	custom, err := Alphabet("custom:ab", false)
	require.NoError(t, err)
	assert.Equal(t, "ab", custom)

	_, err = Alphabet("bogus", false)
	assert.Error(t, err)
}

func TestAlphabetNoAmbiguous(t *testing.T) {
	chars, err := Alphabet("alnum", true)
	require.NoError(t, err)
	for _, r := range ambiguous {
		assert.NotContains(t, chars, string(r))
	}
}

func TestGenerateLengthAndAlphabet(t *testing.T) {
	pw, err := Generate(20, "ab")
	require.NoError(t, err)
	assert.Len(t, pw, 20)
	for _, r := range pw {
		assert.Contains(t, "ab", string(r))
	}
}

func TestGenerateRejectsNonPositiveLength(t *testing.T) {
	_, err := Generate(0, "ab")
	assert.Error(t, err)
}

func TestGenerateManyProducesDistinctPasswords(t *testing.T) {
	pws, err := GenerateMany(5, 16, "abcdefghijklmnopqrstuvwxyz0123456789")
	require.NoError(t, err)
	require.Len(t, pws, 5)
	seen := map[string]bool{}
	for _, pw := range pws {
		assert.False(t, seen[pw], "duplicate password generated: %s", pw)
		seen[pw] = true
	}
}

package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMD5CryptKnownVectors cross-validates against vectors generated with
// glibc's crypt(3) (an independent reference implementation of the
// classic Poul-Henning Kamp md5crypt algorithm).
func TestMD5CryptKnownVectors(t *testing.T) {
	algo, err := Get("md5-crypt")
	require.NoError(t, err)

	cases := []struct {
		password string
		encoded  string
	}{
		{"mypassword", "$1$saltsalt$//251epTQaKpm7/bnAD.Z."},
		{"correct horse battery staple", "$1$abcdefgh$4/U5.w6NPtLkJ2WyrTwm91"},
		{"password123", "$1$12345678$tkslP1BQNfbrS2CGOUX.a."},
	}

	for _, c := range cases {
		assert.True(t, algo.Detect(c.encoded))

		ok, err := algo.Verify([]byte(c.password), c.encoded)
		require.NoError(t, err)
		assert.True(t, ok, "expected %q to verify against %q", c.password, c.encoded)

		ok, err = algo.Verify([]byte("wrong password"), c.encoded)
		require.NoError(t, err)
		assert.False(t, ok)
	}
}

func TestMD5CryptIsLegacyOnly(t *testing.T) {
	algo, err := Get("md5-crypt")
	require.NoError(t, err)
	assert.True(t, algo.LegacyOnly())

	_, err = algo.Hash([]byte("pw"), Params{})
	assert.ErrorIs(t, err, ErrLegacyHashTarget)
}

// TestPhpassKnownVectors cross-validates against vectors generated with
// Python's passlib (github.com/glic3rinu/passlib successor,
// passlib.hash.phpass).
func TestPhpassKnownVectors(t *testing.T) {
	algo, err := Get("phpass")
	require.NoError(t, err)

	cases := []struct {
		password string
		encoded  string
	}{
		{"correct horse battery staple", "$P$616oJgEUyLNuWon9U5H4XwjiWXpPji/"},
		{"password123", "$P$8xlGKZ9Yi4zVwcnoxCvCD.X88JEFJY0"},
	}

	for _, c := range cases {
		assert.True(t, algo.Detect(c.encoded))

		ok, err := algo.Verify([]byte(c.password), c.encoded)
		require.NoError(t, err)
		assert.True(t, ok, "expected %q to verify against %q", c.password, c.encoded)

		ok, err = algo.Verify([]byte("wrong password"), c.encoded)
		require.NoError(t, err)
		assert.False(t, ok)
	}
}

func TestPhpassIsLegacyOnly(t *testing.T) {
	algo, err := Get("phpass")
	require.NoError(t, err)
	assert.True(t, algo.LegacyOnly())

	_, err = algo.Hash([]byte("pw"), Params{})
	assert.ErrorIs(t, err, ErrLegacyHashTarget)
}

func TestDetectAcrossAlgorithms(t *testing.T) {
	cases := map[string]string{
		"bcrypt":        "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga",
		"md5-crypt":     "$1$saltsalt$//251epTQaKpm7/bnAD.Z.",
		"phpass":        "$P$616oJgEUyLNuWon9U5H4XwjiWXpPji/",
		"pbkdf2-sha256": "$pbkdf2-sha256$i=600000$c2FsdHNhbHQ$aGFzaGhhc2g",
	}
	for wantID, encoded := range cases {
		algo, err := Detect(encoded)
		require.NoError(t, err, "encoded=%s", encoded)
		assert.Equal(t, wantID, algo.ID(), "encoded=%s", encoded)
	}
}

package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBcryptKnownVector validates against a known-correct bcrypt vector
// (also used by golang.org/x/crypto/bcrypt's own test suite).
func TestBcryptKnownVector(t *testing.T) {
	algo, err := Get("bcrypt")
	require.NoError(t, err)

	const encoded = "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"

	assert.True(t, algo.Detect(encoded))

	ok, err := algo.Verify([]byte("allmine"), encoded)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = algo.Verify([]byte("wrong"), encoded)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestBcryptHashEncodeVerifyRoundtrip(t *testing.T) {
	algo, err := Get("bcrypt")
	require.NoError(t, err)

	r, err := algo.Hash([]byte("correct horse battery staple"), Params{Cost: 4})
	require.NoError(t, err)

	encoded, err := algo.Encode(r)
	require.NoError(t, err)
	assert.Regexp(t, `^\$2[ab]\$04\$`, encoded)

	ok, err := algo.Verify([]byte("correct horse battery staple"), encoded)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBcryptSplitSaltHash(t *testing.T) {
	const encoded = "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"
	salt, hashPart, cost, ok := BcryptSplitSaltHash(encoded)
	require.True(t, ok)
	assert.Equal(t, "XajjQvNhvvRt5GSeFk1xFe", salt)
	assert.Equal(t, "yqRrsxkhBkUiQeg0dt.wU1qD4aFDcga", hashPart)
	assert.Equal(t, 10, cost)
}

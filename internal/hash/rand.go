package hash

import "crypto/rand"

func randomSalt(n int) ([]byte, error) {
	salt := make([]byte, n)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

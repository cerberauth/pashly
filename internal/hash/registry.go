package hash

import "fmt"

// registryOrder fixes Detect() iteration order so detection is deterministic.
var registryOrder = []string{
	IDBcrypt,
	IDArgon2id,
	IDArgon2i,
	IDScrypt,
	IDPbkdf2Sha256,
	IDPbkdf2Sha512,
	IDPbkdf2Sha1,
	IDPhpass,
	IDMD5Crypt,
}

var registry = map[string]Algorithm{
	IDBcrypt:       bcryptAlgorithm{},
	IDArgon2id:     argon2Algorithm{variant: IDArgon2id},
	IDArgon2i:      argon2Algorithm{variant: IDArgon2i},
	IDScrypt:       scryptAlgorithm{},
	IDPbkdf2Sha1:   pbkdf2Algorithm{hashName: HashSHA1},
	IDPbkdf2Sha256: pbkdf2Algorithm{hashName: HashSHA256},
	IDPbkdf2Sha512: pbkdf2Algorithm{hashName: HashSHA512},
	IDMD5Crypt:     md5CryptAlgorithm{},
	IDPhpass:       phpassAlgorithm{},
}

// Get returns the Algorithm registered under id.
func Get(id string) (Algorithm, error) {
	a, ok := registry[id]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm %q", id)
	}
	return a, nil
}

// Detect finds the algorithm whose canonical format matches encoded.
func Detect(encoded string) (Algorithm, error) {
	for _, id := range registryOrder {
		a := registry[id]
		if a.Detect(encoded) {
			return a, nil
		}
	}
	return nil, fmt.Errorf("unable to detect algorithm for the given hash")
}

// IDs returns every registered algorithm identifier, hashable ones first,
// in a stable order suitable for --help text.
func IDs() []string {
	out := make([]string, 0, len(registryOrder))
	out = append(out, registryOrder...)
	return out
}

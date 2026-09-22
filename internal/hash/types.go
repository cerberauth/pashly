// Package hash implements pashly's canonical password hashing algorithms:
// generation, PHC-style/native string encoding, and verification.
package hash

import "fmt"

// Algorithm identifiers used on the CLI (-a/--algorithm) and as the
// registry's map keys.
const (
	IDBcrypt       = "bcrypt"
	IDArgon2id     = "argon2id"
	IDArgon2i      = "argon2i"
	IDScrypt       = "scrypt"
	IDPbkdf2Sha1   = "pbkdf2-sha1"
	IDPbkdf2Sha256 = "pbkdf2-sha256"
	IDPbkdf2Sha512 = "pbkdf2-sha512"
	IDPhpass       = "phpass"
	IDMD5Crypt     = "md5-crypt"
	IDSha256Crypt  = "sha256-crypt"
	IDSha512Crypt  = "sha512-crypt"
)

// Hash function names used by pbkdf2's variants.
const (
	HashSHA1   = "sha1"
	HashSHA256 = "sha256"
	HashSHA512 = "sha512"
)

// Params carries the tunable parameters for every supported algorithm. Only
// the fields relevant to a given algorithm are read; the rest are ignored.
type Params struct {
	// bcrypt
	Cost int

	// scrypt
	N, R, P int

	// argon2id / argon2i
	Memory, Time, Parallelism uint32

	// pbkdf2-*
	Iterations int

	// common
	SaltLength int
	KeyLength  int
}

// Result is the canonical, algorithm-agnostic shape of a derived password
// hash. Target adapters (internal/target) convert a Result to and from a
// specific IAM/CIAM platform's on-disk representation.
type Result struct {
	Algorithm string
	Params    Params
	Salt      []byte
	Key       []byte
}

// Algorithm is implemented once per supported password hashing algorithm.
type Algorithm interface {
	// ID returns the algorithm identifier used on the CLI (-a/--algorithm).
	ID() string

	// LegacyOnly reports whether this algorithm may only be used for
	// verify/info, never as a hash target (see project threat model).
	LegacyOnly() bool

	// DefaultParams returns the current OWASP-recommended parameters.
	DefaultParams() Params

	// Hash derives a Result from a plaintext password and parameters,
	// generating a fresh random salt.
	Hash(password []byte, params Params) (Result, error)

	// Encode renders a Result as this algorithm's canonical string form.
	Encode(Result) (string, error)

	// Decode parses an encoded string back into a Result.
	Decode(encoded string) (Result, error)

	// Detect reports whether encoded looks like this algorithm's format.
	Detect(encoded string) bool

	// Verify derives a key from password using the parameters embedded in
	// encoded and compares it in constant time against the stored key.
	Verify(password []byte, encoded string) (bool, error)
}

// ErrLegacyHashTarget is returned when a legacy, verify-only algorithm is
// used as a hash target.
var ErrLegacyHashTarget = fmt.Errorf("algorithm is supported for verify/info only, never as a hash target")

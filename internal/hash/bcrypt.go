package hash

import (
	"crypto/subtle"
	"fmt"
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

// bcryptRE matches bcrypt's own native encoding, e.g. $2b$12$<22-char
// salt><31-char hash>. $2a$/$2y$ are legacy prefixes accepted on decode.
var bcryptRE = regexp.MustCompile(`^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`)

// bcryptDefaultCost follows the current OWASP Password Storage Cheat Sheet
// recommendation of cost >= 10, using 12 as pashly's default.
const bcryptDefaultCost = 12

type bcryptAlgorithm struct{}

func (bcryptAlgorithm) ID() string       { return IDBcrypt }
func (bcryptAlgorithm) LegacyOnly() bool { return false }

func (bcryptAlgorithm) DefaultParams() Params {
	return Params{Cost: bcryptDefaultCost}
}

// Hash delegates entirely to golang.org/x/crypto/bcrypt, which owns salt
// generation and produces its own native $2b$ string; pashly does not
// re-encode bcrypt output.
func (b bcryptAlgorithm) Hash(password []byte, params Params) (Result, error) {
	cost := params.Cost
	if cost == 0 {
		cost = bcryptDefaultCost
	}
	encoded, err := bcrypt.GenerateFromPassword(password, cost)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Algorithm: b.ID(),
		Params:    Params{Cost: cost},
		Key:       encoded,
	}, nil
}

func (b bcryptAlgorithm) Encode(r Result) (string, error) {
	return string(r.Key), nil
}

func (b bcryptAlgorithm) Decode(encoded string) (Result, error) {
	cost, err := bcrypt.Cost([]byte(encoded))
	if err != nil {
		return Result{}, err
	}
	return Result{
		Algorithm: b.ID(),
		Params:    Params{Cost: cost},
		Key:       []byte(encoded),
	}, nil
}

func (bcryptAlgorithm) Detect(encoded string) bool {
	return bcryptRE.MatchString(encoded)
}

func (b bcryptAlgorithm) Verify(password []byte, encoded string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(encoded), password)
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// BcryptSplitSaltHash splits a native bcrypt string into its 22-character
// salt substring and 31-character hash substring, as used verbatim (not
// re-decoded) by the Okta target adapter.
func BcryptSplitSaltHash(encoded string) (salt, hashPart string, cost int, ok bool) {
	if !bcryptRE.MatchString(encoded) {
		return "", "", 0, false
	}
	// $2b$12$<22 char salt><31 char hash>
	body := encoded[len(encoded)-53:]
	salt = body[:22]
	hashPart = body[22:]
	c, err := bcrypt.Cost([]byte(encoded))
	if err != nil {
		return "", "", 0, false
	}
	return salt, hashPart, c, true
}

// BcryptJoinSaltHash reassembles a native bcrypt string from a 22-character
// salt substring, 31-character hash substring, and cost, as used by the
// Okta target adapter's Decode.
func BcryptJoinSaltHash(salt, hashPart string, cost int) string {
	return fmt.Sprintf("$2b$%02d$%s%s", cost, salt, hashPart)
}

// constantTimeEqual is a small helper kept alongside the algorithms that
// need it for a raw byte comparison (pbkdf2/scrypt/argon2 use it; bcrypt's
// own CompareHashAndPassword is already constant time).
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

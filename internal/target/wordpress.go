package target

import (
	"fmt"
	"strings"

	"github.com/cerberauth/pashly/internal/hash"
)

// wordpressAdapter implements WordPress's current (6.8+) password format:
// a bcrypt hash using the $2y$ prefix (PHP's PASSWORD_BCRYPT convention),
// wrapped with a literal "$wp$" prefix to signal to older WordPress code
// paths that this is not a legacy phpass hash. Reference: WordPress core
// wp_hash_password()/class-wp-password-hasher.php.
//
// Legacy phpass ($P$/$H$) hashes are supported for verify/info only, via
// the "phpass" algorithm in internal/hash — never as a hash target.
type wordpressAdapter struct{}

func (wordpressAdapter) Name() string        { return NameWordpress }
func (wordpressAdapter) AlgorithmID() string { return hash.IDBcrypt }

const wordpressDefaultCost = 12

func (wordpressAdapter) DefaultParams() hash.Params {
	return hash.Params{Cost: wordpressDefaultCost}
}

func (w wordpressAdapter) Hash(password []byte, params hash.Params) (hash.Result, error) {
	algo, err := hash.Get(w.AlgorithmID())
	if err != nil {
		return hash.Result{}, err
	}
	if params.Cost == 0 {
		params.Cost = wordpressDefaultCost
	}
	return algo.Hash(password, params)
}

func (w wordpressAdapter) Encode(r hash.Result) (string, error) {
	if r.Algorithm != w.AlgorithmID() {
		return "", fmt.Errorf("wordpress target requires a bcrypt hash.Result, got %q", r.Algorithm)
	}
	bcryptStr := string(r.Key)
	if len(bcryptStr) < 4 {
		return "", fmt.Errorf("invalid bcrypt hash")
	}
	// Rewrite the $2a$/$2b$ minor version to $2y$, PHP's PASSWORD_BCRYPT
	// convention, then wrap with WordPress's own "$wp" prefix (the "$2y$"
	// that follows already supplies the separating '$').
	wpBcrypt := "$2y$" + bcryptStr[4:]
	return "$wp" + wpBcrypt, nil
}

func (w wordpressAdapter) Decode(encoded string) (hash.Result, error) {
	rest, ok := strings.CutPrefix(encoded, "$wp")
	if !ok {
		return hash.Result{}, fmt.Errorf("not a valid WordPress $wp$ bcrypt hash")
	}
	algo, err := hash.Get("bcrypt")
	if err != nil {
		return hash.Result{}, err
	}
	return algo.Decode(rest)
}

package cmd

import (
	"fmt"
	"strings"

	"github.com/cerberauth/pashly/internal/hash"
	"github.com/cerberauth/pashly/internal/target"
)

// resolvedHash carries everything verify/info need regardless of whether
// the encoded string was pashly's own canonical format or a --target
// platform's native representation.
type resolvedHash struct {
	label  string // algorithm ID, or "target:<name>" for target formats
	result hash.Result
	algo   hash.Algorithm
}

func (r resolvedHash) verify(password []byte) (bool, error) {
	canonical := string(r.result.Key)
	if r.algo.ID() != "bcrypt" {
		var err error
		canonical, err = r.algo.Encode(r.result)
		if err != nil {
			return false, err
		}
	}
	return r.algo.Verify(password, canonical)
}

// resolveHash detects (or, if override is non-empty, forces) the
// algorithm/target an encoded hash was produced with. override may be
// either a hash.Algorithm ID (bcrypt, argon2id, ...) or a --target name
// (auth0, okta, ...).
func resolveHash(encoded, override string) (resolvedHash, error) {
	if override != "" {
		if algo, err := hash.Get(override); err == nil {
			result, err := algo.Decode(encoded)
			if err != nil {
				return resolvedHash{}, fmt.Errorf("decoding as %s: %w", override, err)
			}
			return resolvedHash{label: override, result: result, algo: algo}, nil
		}
		if adapter, err := target.Get(override); err == nil {
			return resolveViaTarget(adapter, encoded)
		}
		return resolvedHash{}, fmt.Errorf("unknown algorithm or target %q", override)
	}

	if algo, err := hash.Detect(encoded); err == nil {
		result, err := algo.Decode(encoded)
		if err != nil {
			return resolvedHash{}, err
		}
		return resolvedHash{label: algo.ID(), result: result, algo: algo}, nil
	}

	if adapter := sniffTarget(encoded); adapter != nil {
		return resolveViaTarget(adapter, encoded)
	}

	return resolvedHash{}, fmt.Errorf("unable to detect algorithm or target for the given hash; use --algorithm to specify one explicitly")
}

func resolveViaTarget(adapter target.Adapter, encoded string) (resolvedHash, error) {
	result, err := adapter.Decode(encoded)
	if err != nil {
		return resolvedHash{}, fmt.Errorf("decoding as %s: %w", adapter.Name(), err)
	}
	algo, err := hash.Get(adapter.AlgorithmID())
	if err != nil {
		return resolvedHash{}, err
	}
	return resolvedHash{label: "target:" + adapter.Name(), result: result, algo: algo}, nil
}

// sniffTarget makes a best-effort guess at which --target format encoded
// is, based on its shape, trying each candidate's real Decode as the
// final check. Used only when hash.Detect (pashly's own canonical/legacy
// formats) fails to match, since target formats are platform-specific and
// not otherwise auto-detectable with full confidence.
func sniffTarget(encoded string) target.Adapter {
	trimmed := strings.TrimSpace(encoded)

	var candidates []string
	switch {
	case strings.HasPrefix(trimmed, "$wp$"):
		candidates = []string{"wordpress"}
	case strings.HasPrefix(trimmed, "pbkdf2_sha256$"):
		candidates = []string{"django"}
	case strings.HasPrefix(trimmed, "{"):
		candidates = []string{"auth0", "okta", "keycloak"}
	default:
		candidates = []string{"aspnet-identity"}
	}

	for _, name := range candidates {
		adapter, err := target.Get(name)
		if err != nil {
			continue
		}
		if _, err := adapter.Decode(trimmed); err == nil {
			return adapter
		}
	}
	return nil
}

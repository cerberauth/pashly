package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// passwordInputFlags are the three mutually exclusive ways to supply a
// password, shared by hash and verify.
type passwordInputFlags struct {
	password     string
	stdin        bool
	passwordFile string
}

// readPassword resolves exactly one of --password/--stdin/--password-file
// into a plaintext password. It never logs the value. A bare --password is
// flagged on stderr as the least-safe option.
func readPassword(f passwordInputFlags) ([]byte, error) {
	set := 0
	if f.password != "" {
		set++
	}
	if f.stdin {
		set++
	}
	if f.passwordFile != "" {
		set++
	}
	if set == 0 {
		return nil, fmt.Errorf("one of --password, --stdin, or --password-file is required")
	}
	if set > 1 {
		return nil, fmt.Errorf("--password, --stdin, and --password-file are mutually exclusive")
	}

	switch {
	case f.password != "":
		fmt.Fprintln(os.Stderr, "warning: passing --password on the command line may leak it via shell history or process listings; prefer --stdin or --password-file")
		return []byte(f.password), nil

	case f.passwordFile != "":
		data, err := os.ReadFile(f.passwordFile)
		if err != nil {
			return nil, fmt.Errorf("reading password file: %w", err)
		}
		return trimTrailingNewline(data), nil

	default: // f.stdin
		return readStdinPassword()
	}
}

func trimTrailingNewline(b []byte) []byte {
	s := string(b)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return []byte(s)
}

func readStdinPassword() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Password: ")
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("reading password from terminal: %w", err)
		}
		return pw, nil
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("reading password from stdin: %w", err)
	}
	return trimTrailingNewline([]byte(line)), nil
}

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// formatJSON is the shared --format value selecting JSON output, used by
// generate, hash, and info.
const formatJSON = "json"

// printJSON marshals v as indented JSON without HTML-escaping (passwords
// and hashes routinely contain '&', '<', '>', which json.Marshal would
// otherwise mangle into & etc.) and prints it to stdout.
func printJSON(v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	fmt.Print(buf.String())
	return nil
}

package hash

import "encoding/base64"

// phcEncoding is the unpadded standard base64 alphabet used by the PHC
// string format for salts and derived keys.
var phcEncoding = base64.RawStdEncoding

func b64Encode(b []byte) string { return phcEncoding.EncodeToString(b) }

func b64Decode(s string) ([]byte, error) { return phcEncoding.DecodeString(s) }

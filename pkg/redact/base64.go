package redact

import (
	"bytes"
	"encoding/base64"
	"strings"
	"unicode"
)

// minBase64Run mirrors the threshold decoders.Base64 uses: runs of more than
// 20 base64 characters are decoded.
const minBase64Run = 20

const base64EndChars = "+/-_="

var base64Charset [128]bool

func init() {
	for _, c := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=") {
		base64Charset[c] = true
	}
}

// base64Runs returns the substrings decoders.Base64 would try to decode, as
// offsets into data.
func base64Runs(data []byte) []rng {
	var runs []rng
	start, count := 0, 0
	flush := func() {
		if count > minBase64Run {
			if r, ok := trimBase64Run(data, start, start+count); ok {
				runs = append(runs, r)
			}
		}
		count = 0
	}
	for i, c := range data {
		if c < 128 && base64Charset[c] {
			if count == 0 {
				start = i
			}
			count++
			continue
		}
		flush()
	}
	flush()
	return runs
}

// trimBase64Run applies decoders.Base64's trimming: leading end characters are
// dropped, and for "key=value" runs only the part after the first inner '='
// is decoded.
func trimBase64Run(data []byte, s, e int) (rng, bool) {
	for s < e && strings.IndexByte(base64EndChars, data[s]) >= 0 {
		s++
	}
	trimmed := bytes.TrimRight(data[s:e], base64EndChars)
	if idx := bytes.IndexByte(trimmed, '='); idx != -1 {
		s += idx + 1
	}
	if e-s <= 0 {
		return rng{}, false
	}
	return rng{s, e}, true
}

var base64Encodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

// decodeBase64 decodes s with the first encoding that accepts it and yields
// ASCII, which is what decoders.Base64 requires of decoded content.
func decodeBase64(s []byte) ([]byte, *base64.Encoding) {
	for _, enc := range base64Encodings {
		dec := make([]byte, enc.DecodedLen(len(s)))
		n, err := enc.Decode(dec, s)
		if err != nil || n == 0 {
			continue
		}
		dec = dec[:n]
		if isASCII(dec) {
			return dec, enc
		}
	}
	return nil, nil
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

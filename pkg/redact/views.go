package redact

import (
	"bytes"
	"html"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// encoding describes how a replacement must be written back into the original
// bytes for a span found through a particular view.
type encoding int

const (
	encPlain encoding = iota
	encUTF16LE
	encUTF16BE
	encBase64 // the span is a base64 run whose decoded form was redacted
)

func (e encoding) String() string {
	switch e {
	case encUTF16LE:
		return "utf16le"
	case encUTF16BE:
		return "utf16be"
	case encBase64:
		return "base64"
	default:
		return "plain"
	}
}

// view is a transformed rendering of the input in which a secret may appear in
// the form a detector saw it, for example after trufflehog's decoders ran or
// after a detector unescaped its input. Every byte of text maps back to the
// range of original bytes it was produced from, so a match in the view can be
// redacted at its source.
//
// The identity view has nil start/end slices and maps offsets directly.
type view struct {
	name  string
	text  []byte
	start []int32 // start[i] is the original offset of the bytes text[i] came from
	end   []int32 // end[i] is the exclusive original end offset of those bytes
	enc   encoding
}

func identityView(data []byte) *view {
	return &view{name: "plain", text: data, enc: encPlain}
}

// orig maps the view range [a, b) onto the original input.
func (v *view) orig(a, b int) (int, int) {
	if v.start == nil {
		return a, b
	}
	return int(v.start[a]), int(v.end[b-1])
}

// adjacent reports whether text[i] and text[i+1] come from neighbouring bytes
// of the original, i.e. the view dropped nothing between them.
func (v *view) adjacent(i int) bool {
	return v.start == nil || v.end[i] >= v.start[i+1]
}

// viewBuilder accumulates a view's text alongside its offset mapping.
type viewBuilder struct {
	v *view
}

func newViewBuilder(name string, enc encoding, sizeHint int) *viewBuilder {
	return &viewBuilder{v: &view{
		name:  name,
		enc:   enc,
		text:  make([]byte, 0, sizeHint),
		start: make([]int32, 0, sizeHint),
		end:   make([]int32, 0, sizeHint),
	}}
}

// emit appends text that was produced from the original range [s, e).
func (b *viewBuilder) emit(text []byte, s, e int) {
	for _, c := range text {
		b.emitByte(c, s, e)
	}
}

func (b *viewBuilder) emitByte(c byte, s, e int) {
	b.v.text = append(b.v.text, c)
	b.v.start = append(b.v.start, int32(s))
	b.v.end = append(b.v.end, int32(e))
}

// done returns the view, or nil when it is empty or identical to the input and
// therefore cannot reveal anything the identity view does not.
func (b *viewBuilder) done(data []byte) *view {
	if len(b.v.text) == 0 || bytes.Equal(b.v.text, data) {
		return nil
	}
	return b.v
}

// buildViews returns every view of data that may contain secrets the identity
// view cannot see. Views are only built when the input contains the markers
// they decode, which keeps the common case (plain source code) cheap.
func buildViews(data []byte) []*view {
	// Character encodings first, then the escapes found in the text, the way
	// the engine chains its decoders.
	bases := []*view{identityView(data)}
	if !utf8.Valid(data) {
		if v := sanitizedUTF8View(data); v != nil {
			bases = append(bases, v)
		}
	}
	if bytes.IndexByte(data, 0) >= 0 {
		for _, le := range []bool{true, false} {
			if v := utf16View(data, le); v != nil {
				bases = append(bases, v)
			}
		}
	}
	views := append([]*view(nil), bases...)
	for _, base := range bases {
		views = append(views, escapeViews(base)...)
	}
	return views
}

// maxUnescapeDepth bounds repeated unescaping, matching the engine's default
// --max-decode-depth.
const maxUnescapeDepth = 5

// escapeViews returns views of base's text with escape sequences decoded.
func escapeViews(base *view) []*view {
	var views []*view
	add := func(v *view) {
		if v == nil {
			return
		}
		if base.start != nil {
			v = composeViews(v, base)
		}
		views = append(views, v)
	}
	text := base.text
	if bytes.IndexByte(text, '\\') >= 0 || bytes.Contains(text, []byte("U+")) {
		// JSON embedded in a JSON string escapes its escapes ("\\n"), so
		// unescape repeatedly, as deep as the engine decodes.
		v := unescapeView(text)
		for depth := 1; v != nil; depth++ {
			add(v)
			if depth == maxUnescapeDepth || bytes.IndexByte(v.text, '\\') < 0 {
				break
			}
			if inner := unescapeView(v.text); inner != nil {
				v = composeViews(inner, v)
			} else {
				v = nil
			}
		}
	}
	if bytes.IndexByte(text, '%') >= 0 {
		add(percentView(text))
	}
	if bytes.IndexByte(text, '&') >= 0 || htmlTagPattern.Match(text) {
		add(htmlView(text))
	}
	return views
}

// composeViews maps outer, a view of base's text, onto the original input.
// Replacements are encoded the way base requires.
func composeViews(outer, base *view) *view {
	b := newViewBuilder(base.name+"+"+outer.name, base.enc, len(outer.text))
	for i, c := range outer.text {
		s, e := outer.orig(i, i+1)
		bs, _ := base.orig(s, s+1)
		_, be := base.orig(e-1, e)
		b.emitByte(c, bs, be)
	}
	return b.v
}

// sanitizedUTF8View mirrors decoders.UTF8 for invalid UTF-8 input (typically
// binaries): control characters and malformed sequences become U+FFFD.
func sanitizedUTF8View(data []byte) *view {
	b := newViewBuilder("utf8", encPlain, len(data))
	replacement := []byte(string(utf8.RuneError))
	for i := 0; i < len(data); {
		c := data[i]
		if c < utf8.RuneSelf {
			if c > 31 && c < 127 {
				b.emitByte(c, i, i+1)
			} else {
				b.emit(replacement, i, i+1)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError {
			b.emit(replacement, i, i+1)
			i++
			continue
		}
		b.emit(data[i:i+size], i, i+size)
		i += size
	}
	return b.done(data)
}

// utf16View mirrors decoders.UTF16, keeping printable ASCII code units.
func utf16View(data []byte, littleEndian bool) *view {
	name, enc := "utf16be", encUTF16BE
	if littleEndian {
		name, enc = "utf16le", encUTF16LE
	}
	b := newViewBuilder(name, enc, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		hi, lo := data[i], data[i+1]
		if littleEndian {
			hi, lo = lo, hi
		}
		if hi == 0 && lo > 31 && lo < 127 {
			b.emitByte(lo, i, i+2)
		}
	}
	return b.done(data)
}

var (
	// Escape sequences decoded by decoders.EscapedUnicode and commonly found in
	// string literals, JSON and source code.
	braceEscapePat = regexp.MustCompile(`^\\u\{([a-fA-F0-9]{1,6})\}`)
	escapePat      = regexp.MustCompile(`^\\{1,2}[uU]([a-fA-F0-9]{4})`)
	longEscapePat  = regexp.MustCompile(`^\\U([a-fA-F0-9]{8})`)
	perlEscapePat  = regexp.MustCompile(`^\\x\{([a-fA-F0-9]{1,6})\}`)
	hexEscapePat   = regexp.MustCompile(`^\\x([a-fA-F0-9]{2})`)
	codePointPat   = regexp.MustCompile(`^U\+([a-fA-F0-9]{4})`)
)

var simpleEscapes = map[byte]byte{
	'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'f': '\f', 'v': '\v', '0': 0,
	'/': '/', '"': '"', '\'': '\'', '\\': '\\', '`': '`', '$': '$',
}

// unescapeView decodes backslash escapes (JSON, JavaScript, Go, Python, ...)
// and U+XXXX code points.
func unescapeView(data []byte) *view {
	b := newViewBuilder("unescape", encPlain, len(data))
	for i := 0; i < len(data); {
		c := data[i]
		if c != '\\' && c != 'U' {
			b.emitByte(c, i, i+1)
			i++
			continue
		}
		// The longest escape sequence handled here is 10 bytes long.
		rest := data[i:min(i+12, len(data))]
		decoded := false
		for _, pat := range []*regexp.Regexp{braceEscapePat, longEscapePat, escapePat, perlEscapePat, hexEscapePat, codePointPat} {
			m := pat.FindSubmatchIndex(rest)
			if m == nil {
				continue
			}
			cp, err := strconv.ParseUint(string(rest[m[2]:m[3]]), 16, 32)
			if err != nil || !utf8.ValidRune(rune(cp)) {
				continue
			}
			b.emit([]byte(string(rune(cp))), i, i+m[1])
			i += m[1]
			decoded = true
			break
		}
		if decoded {
			continue
		}
		if c == '\\' && i+1 < len(data) {
			if r, ok := simpleEscapes[data[i+1]]; ok {
				b.emitByte(r, i, i+2)
				i += 2
				continue
			}
		}
		b.emitByte(c, i, i+1)
		i++
	}
	return b.done(data)
}

// percentView decodes URL percent-encoding (%XX and %uXXXX).
func percentView(data []byte) *view {
	b := newViewBuilder("percent", encPlain, len(data))
	for i := 0; i < len(data); {
		if data[i] == '%' {
			if i+6 <= len(data) && (data[i+1] == 'u' || data[i+1] == 'U') {
				if cp, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 32); err == nil {
					b.emit([]byte(string(rune(cp))), i, i+6)
					i += 6
					continue
				}
			}
			if i+3 <= len(data) {
				if c, err := strconv.ParseUint(string(data[i+1:i+3]), 16, 8); err == nil {
					b.emitByte(byte(c), i, i+3)
					i += 3
					continue
				}
			}
		}
		b.emitByte(data[i], i, i+1)
		i++
	}
	return b.done(data)
}

// htmlTagPattern matches the start of an HTML tag, like decoders.HTML does.
var htmlTagPattern = regexp.MustCompile(`<[a-zA-Z][a-zA-Z0-9]*(?::[a-zA-Z][a-zA-Z0-9]*)?[\s>/]`)

var htmlEntityPat = regexp.MustCompile(`^&(?:#[xX][0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-zA-Z][a-zA-Z0-9]{1,31});`)

// htmlView decodes character references and drops markup, so that values split
// across tags (as syntax highlighters do) or entity-encoded are contiguous.
// The quoted attribute values of dropped tags are kept, so secrets in them
// stay findable.
func htmlView(data []byte) *view {
	b := newViewBuilder("html", encPlain, len(data))
	stripTags := htmlTagPattern.Match(data)
	for i := 0; i < len(data); {
		c := data[i]
		if c == '&' {
			if m := htmlEntityPat.Find(data[i:]); m != nil {
				if s := html.UnescapeString(string(m)); s != string(m) {
					b.emit([]byte(s), i, i+len(m))
					i += len(m)
					continue
				}
			}
		}
		if stripTags && c == '<' && i+1 < len(data) && (isASCIILetter(data[i+1]) || data[i+1] == '/' || data[i+1] == '!') {
			if end := bytes.IndexByte(data[i:], '>'); end > 0 {
				// Keep quoted attribute values so secrets inside them stay findable.
				tag := data[i : i+end+1]
				for j := 0; j < len(tag); j++ {
					q := tag[j]
					if q != '"' && q != '\'' {
						continue
					}
					k := bytes.IndexByte(tag[j+1:], q)
					if k < 0 {
						break
					}
					b.emitByte(' ', i+j, i+j+1)
					for x := j + 1; x <= j+k; x++ {
						b.emitByte(tag[x], i+x, i+x+1)
					}
					b.emitByte(' ', i+j+k+1, i+j+k+2)
					j += k + 1
				}
				i += end + 1
				continue
			}
		}
		b.emitByte(c, i, i+1)
		i++
	}
	return b.done(data)
}

func isASCIILetter(c byte) bool { return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') }

// isCompactable reports whether c is dropped by compactView: layout and
// string-literal syntax that commonly splits long secrets across lines.
func isCompactable(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '"', '\'', '+', '`':
		return true
	}
	return false
}

// compact returns s without the bytes compactView drops.
func compact(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !isCompactable(s[i]) {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// compactView drops whitespace and string-literal syntax from another view. It
// is a fallback used to find long or multi-line secrets that detectors
// normalized, such as private keys reflowed across lines or concatenated
// string literals.
func compactView(src *view) *view {
	b := newViewBuilder(src.name+"+compact", src.enc, len(src.text))
	for i, c := range src.text {
		if isCompactable(c) {
			continue
		}
		s, e := src.orig(i, i+1)
		b.emitByte(c, s, e)
	}
	if len(b.v.text) == 0 {
		return nil
	}
	return b.v
}

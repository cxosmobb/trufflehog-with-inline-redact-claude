// Package redact overwrites the secrets trufflehog detects in their original
// input, so that the input can be handed to an untrusted consumer.
//
// Only the secret material of a finding is replaced: identifiers that are
// reported alongside a secret (key IDs, usernames, hosts, ...) and the text
// around a secret are left untouched. Secrets that trufflehog only found after
// decoding the input (base64, UTF-16, escape sequences, HTML) are redacted in
// their encoded form.
package redact

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf16"
)

// DefaultReplacement is written over every redacted secret.
const DefaultReplacement = "REDACTED"

// DefaultMaxDecodeDepth bounds nested base64 decoding, matching the engine's
// default --max-decode-depth.
const DefaultMaxDecodeDepth = 5

// maxAnchorDistance is how far (in bytes) a non-distinctive secret may be from
// the rest of its credential and still be redacted.
const maxAnchorDistance = 1024

// maxViewInput bounds the inputs that decoded views are built for: a view
// takes about nine bytes per input byte. Secrets in larger inputs are only
// looked for as plain text and in base64; any other finding there is
// reported as unredactable rather than exhausting memory.
const maxViewInput = 4 << 20

// Options configures redaction.
type Options struct {
	// Replacement overwrites each secret. Defaults to DefaultReplacement.
	Replacement string
	// PreserveLength repeats or truncates the replacement to the length of
	// each secret, which keeps offsets in binary files intact.
	PreserveLength bool
	// MaxDecodeDepth bounds nested base64 decoding. Defaults to
	// DefaultMaxDecodeDepth.
	MaxDecodeDepth int
}

func (o Options) withDefaults() Options {
	if o.Replacement == "" {
		o.Replacement = DefaultReplacement
	}
	if o.MaxDecodeDepth <= 0 {
		o.MaxDecodeDepth = DefaultMaxDecodeDepth
	}
	return o
}

// Redaction describes one overwritten region of the input. It never holds
// secret material.
type Redaction struct {
	// Start and End delimit the original bytes that were replaced.
	Start, End int
	// Line is the 1-based line of Start.
	Line int
	// Encoding is how the secret was stored in the input: plain, base64,
	// utf16le or utf16be.
	Encoding string
	// Findings are the indexes of the findings the redaction belongs to.
	Findings []int
}

// Report summarizes a redaction.
type Report struct {
	Redactions []Redaction
	// Unredacted holds the indexes of findings with at least one secret that
	// could not be located in the input, for example because it is stored
	// compressed, or because the detector did not report its secret.
	Unredacted []int
	// Residual holds the indexes of findings whose secrets all already read
	// as the replacement, but that a detector still reports because it
	// matches the structure around them. They hold no secret material.
	Residual []int
}

// Redact returns data with the secrets of findings replaced.
func Redact(data []byte, findings []Finding, opts Options) ([]byte, Report) {
	r := newRedactor(data, opts.withDefaults(), 0)
	var report Report
	for i, f := range findings {
		switch r.redactFinding(i, f) {
		case stateUnredacted:
			report.Unredacted = append(report.Unredacted, i)
		case stateResidual:
			report.Residual = append(report.Residual, i)
		}
	}
	out, redactions := r.render()
	report.Redactions = redactions
	return out, report
}

// span is a region of the input to overwrite.
type span struct {
	start, end int
	enc        encoding
	findings   []int
	// container is set for base64 runs whose decoded content was redacted.
	container *container
}

// container is a base64 run in the input and the redactor for its decoding.
type container struct {
	start, end int
	enc        *base64.Encoding
	// textEnc is how the base64 text itself is stored, e.g. as UTF-16.
	textEnc encoding
	sub     *redactor
}

type redactor struct {
	data  []byte
	opts  Options
	depth int

	views      []*view
	compacts   []*view
	containers []*container
	built      struct{ compacts, containers bool }
	lineStarts []int

	spans []span
}

func newRedactor(data []byte, opts Options, depth int) *redactor {
	return &redactor{data: data, opts: opts, depth: depth}
}

func (r *redactor) getViews() []*view {
	if r.views == nil {
		if len(r.data) > maxViewInput {
			r.views = []*view{identityView(r.data)}
		} else {
			r.views = buildViews(r.data)
		}
	}
	return r.views
}

func (r *redactor) getCompacts() []*view {
	if !r.built.compacts && len(r.data) <= maxViewInput {
		for _, v := range r.getViews() {
			if c := compactView(v); c != nil {
				r.compacts = append(r.compacts, c)
			}
		}
	}
	r.built.compacts = true
	return r.compacts
}

// getContainers returns the base64 runs of the input, including runs that
// only appear once escapes or UTF-16 are decoded, like the engine finds them.
func (r *redactor) getContainers() []*container {
	if !r.built.containers {
		r.built.containers = true
		if r.depth < r.opts.MaxDecodeDepth {
			seen := map[[2]int]bool{}
			for _, v := range r.getViews() {
				for _, run := range base64Runs(v.text) {
					dec, enc := decodeBase64(v.text[run.start:run.end])
					if dec == nil {
						continue
					}
					s, e := v.orig(run.start, run.end)
					if seen[[2]int{s, e}] {
						continue
					}
					seen[[2]int{s, e}] = true
					r.containers = append(r.containers, &container{
						start: s, end: e, enc: enc, textEnc: v.enc,
						sub: newRedactor(dec, r.opts, r.depth+1),
					})
				}
			}
		}
	}
	return r.containers
}

// findingState is the outcome of redacting one finding.
type findingState int

const (
	// stateRedacted: every secret was found and is overwritten.
	stateRedacted findingState = iota
	// stateResidual: every secret already reads as the replacement, yet the
	// detector still reports the finding because it matches the structure
	// around the secret (GCP flags any service account JSON). No secret
	// material is left, and widening the redaction would not help.
	stateResidual
	// stateUnredacted: a secret could not be found in the input.
	stateUnredacted
)

// redactFinding records the spans of f.
func (r *redactor) redactFinding(i int, f Finding) findingState {
	targets := secretTargets(f)
	if len(targets) == 0 {
		return stateUnredacted
	}
	effective := false
	for _, t := range targets {
		located, eff := r.redactTarget(i, f, t)
		if !located && !t.optional {
			return stateUnredacted
		}
		effective = effective || eff
	}
	if effective {
		return stateRedacted
	}

	// The secrets already read as the replacement, but the detector still
	// reports the credential, e.g. Postgres flags user:REDACTED@host. Widen
	// the redaction to the credential the secret sits in.
	for _, c := range containerTargets(f, targets, r.opts.Replacement) {
		if loc, eff := r.redactTarget(i, f, c); loc && eff {
			effective = true
		}
	}
	if !effective {
		for _, t := range targets {
			if r.widenField(i, f, t) {
				effective = true
			}
		}
	}
	if effective {
		return stateRedacted
	}
	return stateResidual
}

// connFieldKeyPat matches the key of a connection string field right before
// its value, e.g. ";Password=" in "Server=x;Password=hunter2;".
var connFieldKeyPat = regexp.MustCompile(`(?i)(?:^|[;&?,\s])((?:password|passwd|pwd|pass|secret|token|apikey|api_key|accountkey|sharedaccesskey|sig)\s*=\s*)(["']?)$`)

// widenField extends occurrences of t that are values of a connection string
// field to the whole field, so "Password=REDACTED" becomes "REDACTED". It is
// only used when the containing value was not reported verbatim. JSON, YAML
// and code are not widened this way because dropping a key there would break
// their syntax.
func (r *redactor) widenField(i int, f Finding, t target) bool {
	var spans []span
	needle := []byte(t.value)
	for off := 0; off < len(r.data); {
		idx := bytes.Index(r.data[off:], needle)
		if idx < 0 {
			break
		}
		a, b := off+idx, off+idx+len(needle)
		off = b
		lo := max(0, a-64)
		m := connFieldKeyPat.FindSubmatchIndex(r.data[lo:a])
		if m == nil {
			continue
		}
		if q := m[5] - m[4]; q == 1 && b < len(r.data) && r.data[b] == r.data[lo+m[4]] {
			b++
		}
		spans = append(spans, span{start: lo + m[2], end: b, enc: encPlain, findings: []int{i}})
	}
	if t.anchored {
		spans = r.nearAnchors(spans, f, t.value)
	}
	r.spans = append(r.spans, spans...)
	return len(spans) > 0
}

// redactTarget records spans for every occurrence of t. It reports whether t
// was found in the input and whether redacting it changes the input.
func (r *redactor) redactTarget(i int, f Finding, t target) (located, effective bool) {
	spans := r.find(i, t.value, r.getViews())
	if t.anchored {
		spans = r.nearAnchors(spans, f, t.value)
	}

	// A short secret is only looked for in base64 that also holds the rest of
	// its credential, unless the finding has nothing else to anchor it to.
	anchorInContainers := t.anchored && len(anchorValues(f, t.value)) > 0
	for _, c := range r.getContainers() {
		if anchorInContainers && len(c.sub.anchorOffsets(f, t.value)) == 0 {
			continue
		}
		sub := f
		sub.Line = 0
		if loc, eff := c.sub.redactTarget(i, sub, t); loc {
			located = true
			effective = effective || eff
		}
	}

	if len(spans) == 0 && !located && (len(t.value) >= 32 || strings.ContainsAny(t.value, " \t\r\n")) {
		// Detectors normalize some long secrets (private keys, concatenated
		// literals). Look for them with layout characters ignored.
		spans = r.find(i, compact(t.value), r.getCompacts())
		if t.anchored {
			spans = r.nearAnchors(spans, f, t.value)
		}
	}

	if len(spans) == 0 && !located {
		if t.fallback {
			return false, false
		}
		fallbacks := fallbackTargets(t.value)
		if len(fallbacks) == 0 {
			return false, false
		}
		located = true
		for _, fb := range fallbacks {
			loc, eff := r.redactTarget(i, f, fb)
			located = located && loc
			effective = effective || eff
		}
		return located, effective
	}

	for _, s := range spans {
		if !r.alreadyRedacted(s) {
			effective = true
		}
	}
	r.spans = append(r.spans, spans...)
	return true, effective
}

// find returns spans for every occurrence of value in views, each covering the
// narrowest redaction level of the occurrence that is not redacted yet.
func (r *redactor) find(i int, value string, views []*view) []span {
	if value == "" {
		return nil
	}
	needle := []byte(value)
	levels := redactionLevels(value)
	var spans []span
	for _, v := range views {
		for off := 0; off < len(v.text); {
			idx := bytes.Index(v.text[off:], needle)
			if idx < 0 {
				break
			}
			p := off + idx
			off = p + len(needle)

			var occ []span
			for _, level := range levels {
				if level == nil {
					a, b := tokenBounds(v.text, p, p+len(needle), value, v.adjacent)
					level = []rng{{a - p, b - p}}
				}
				occ = occ[:0]
				done := true
				for _, rg := range level {
					s, e := v.orig(p+rg.start, p+rg.end)
					sp := span{start: s, end: e, enc: v.enc, findings: []int{i}}
					done = done && r.alreadyRedacted(sp)
					occ = append(occ, sp)
				}
				if !done {
					break
				}
			}
			spans = append(spans, occ...)
		}
	}
	return spans
}

// tokenBounds adjusts the occurrence text[a:b] of value to the token it
// belongs to. A closing quote the detector matched along with the value is
// left in place when the same quote opens it. A value that stops inside a
// longer token, because a detector's pattern caps the secret's length, is
// extended to the end of that token so no fragment of the secret is left
// behind; long runs are left alone, as the value then sits in an unrelated
// blob. The token ends where adjacent(i) reports that text[i] and text[i+1]
// were not next to each other in the input, as when a view dropped a line
// break.
func tokenBounds(text []byte, a, b int, value string, adjacent func(int) bool) (int, int) {
	if b-a >= 2 {
		if q := text[b-1]; (q == '`' || q == '"' || q == '\'') && a > 0 && text[a-1] == q {
			b--
		}
		if q := text[a]; (q == '`' || q == '"' || q == '\'') && b < len(text) && text[b] == q {
			a++
		}
	}
	inToken := func(c byte) bool {
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') {
			return true
		}
		return strings.IndexByte("-_+/=.", c) >= 0 && strings.IndexByte(value, c) >= 0
	}
	limit := max(16, len(value)/2)
	if b > a && inToken(text[b-1]) {
		e := b
		for e < len(text) && e-b <= limit && inToken(text[e]) && adjacent(e-1) {
			e++
		}
		if e-b <= limit {
			b = e
		}
	}
	if b > a && inToken(text[a]) {
		s := a
		for s > 0 && a-s <= limit && inToken(text[s-1]) && adjacent(s-1) {
			s--
		}
		if a-s <= limit {
			a = s
		}
	}
	return a, b
}

// alreadyRedacted reports whether s already holds the replacement text.
func (r *redactor) alreadyRedacted(s span) bool {
	if s.container != nil {
		return false
	}
	return bytes.Equal(r.data[s.start:s.end], r.replacement(s))
}

// anchorOffsets returns where the anchor values of f start and end in the
// input.
func (r *redactor) anchorOffsets(f Finding, secret string) []int {
	var offs []int
	for _, a := range anchorValues(f, secret) {
		needle := []byte(a)
		for off := 0; off < len(r.data); {
			idx := bytes.Index(r.data[off:], needle)
			if idx < 0 {
				break
			}
			offs = append(offs, off+idx, off+idx+len(needle))
			off += idx + len(needle)
		}
	}
	return offs
}

// nearAnchors keeps the spans that are close to the rest of the credential or
// on the line the engine reported. When there is nothing to anchor to, every
// span is kept: redacting too much is preferable to leaking a secret.
func (r *redactor) nearAnchors(spans []span, f Finding, secret string) []span {
	if len(spans) == 0 {
		return spans
	}
	anchors := r.anchorOffsets(f, secret)
	lineLo, lineHi := -1, -1
	if f.Line > 0 && r.depth == 0 {
		lineLo = r.lineStart(int(f.Line) - 1)
		lineHi = r.lineStart(int(f.Line) + 2)
	}
	if len(anchors) == 0 && lineLo < 0 {
		return spans
	}
	var kept []span
	for _, s := range spans {
		keep := lineLo >= 0 && s.start >= lineLo && s.start < lineHi
		for _, a := range anchors {
			if keep {
				break
			}
			// An anchor that contains the span is the credential itself.
			if abs(a-s.start) <= maxAnchorDistance || abs(a-s.end) <= maxAnchorDistance {
				keep = true
			}
		}
		if keep {
			kept = append(kept, s)
		}
	}
	if len(kept) == 0 {
		return spans
	}
	return kept
}

// lineStart returns the offset of the given 1-based line, clamped to the input.
func (r *redactor) lineStart(line int) int {
	if r.lineStarts == nil {
		r.lineStarts = []int{0}
		for i, c := range r.data {
			if c == '\n' {
				r.lineStarts = append(r.lineStarts, i+1)
			}
		}
	}
	switch {
	case line < 1:
		return 0
	case line > len(r.lineStarts):
		return len(r.data)
	default:
		return r.lineStarts[line-1]
	}
}

func (r *redactor) lineOf(offset int) int {
	r.lineStart(1)
	return sort.SearchInts(r.lineStarts, offset+1)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// replacement returns the bytes written over s.
func (r *redactor) replacement(s span) []byte {
	n := s.end - s.start
	switch s.enc {
	case encUTF16LE, encUTF16BE:
		out := toUTF16(r.fit(n/2), s.enc)
		if r.opts.PreserveLength && len(out) < n {
			out = append(out, r.data[s.start+len(out):s.end]...)
		}
		return out
	case encBase64:
		decoded, _ := s.container.sub.render()
		out := []byte(s.container.enc.EncodeToString(decoded))
		if te := s.container.textEnc; te != encPlain {
			out = toUTF16(string(out), te)
		}
		if r.opts.PreserveLength && len(out) != n {
			return []byte(r.fit(n))
		}
		return out
	default:
		return []byte(r.fit(n))
	}
}

// toUTF16 encodes s as UTF-16 in the byte order of enc.
func toUTF16(s string, enc encoding) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units))
	for _, u := range units {
		if enc == encUTF16LE {
			out = append(out, byte(u), byte(u>>8))
		} else {
			out = append(out, byte(u>>8), byte(u))
		}
	}
	return out
}

// fit returns the replacement text, sized to n bytes if lengths are preserved.
// Padding uses '*' rather than repeating the replacement, because a repeated
// word is itself an alphanumeric run that token detectors match.
func (r *redactor) fit(n int) string {
	rep := r.opts.Replacement
	if !r.opts.PreserveLength {
		return rep
	}
	if n <= len(rep) {
		return rep[:max(n, 0)]
	}
	return rep + strings.Repeat("*", n-len(rep))
}

// render applies the recorded spans and returns the redacted input.
func (r *redactor) render() ([]byte, []Redaction) {
	spans := slices.Clone(r.spans)
	for _, c := range r.containers {
		if ids := c.sub.findingIndexes(); len(ids) > 0 {
			spans = append(spans, span{start: c.start, end: c.end, enc: encBase64, container: c, findings: ids})
		}
	}
	if len(spans) == 0 {
		return r.data, nil
	}
	slices.SortFunc(spans, func(a, b span) int {
		return cmp.Or(cmp.Compare(a.start, b.start), cmp.Compare(b.end, a.end))
	})

	merged := []span{spans[0]}
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start > last.end || (s.start == last.end && (s.enc != encPlain || last.enc != encPlain)) {
			merged = append(merged, s)
			continue
		}
		if s.end > last.end {
			last.end = s.end
		}
		if s.enc != last.enc {
			// Overlapping spans found through different encodings: overwrite
			// the union as plain text.
			last.enc, last.container = encPlain, nil
		}
		last.findings = append(last.findings, s.findings...)
	}

	var out bytes.Buffer
	out.Grow(len(r.data))
	redactions := make([]Redaction, 0, len(merged))
	prev := 0
	for _, s := range merged {
		out.Write(r.data[prev:s.start])
		out.Write(r.replacement(s))
		prev = s.end
		redactions = append(redactions, Redaction{
			Start: s.start, End: s.end,
			Line:     r.lineOf(s.start),
			Encoding: s.enc.String(),
			Findings: uniqueInts(s.findings),
		})
	}
	out.Write(r.data[prev:])
	return out.Bytes(), redactions
}

// findingIndexes returns the findings with spans in this input or in base64
// decoded from it. A container is rewritten only when this is not empty.
func (r *redactor) findingIndexes() []int {
	var out []int
	for _, s := range r.spans {
		out = append(out, s.findings...)
	}
	for _, c := range r.containers {
		out = append(out, c.sub.findingIndexes()...)
	}
	return uniqueInts(out)
}

func uniqueInts(in []int) []int {
	slices.Sort(in)
	return slices.Compact(in)
}

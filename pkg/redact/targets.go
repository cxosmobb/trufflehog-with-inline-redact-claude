package redact

import (
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

// Finding is the part of a detector result needed to redact it.
type Finding struct {
	DetectorType detector_typepb.DetectorType
	// DetectorName is set for custom detectors, which share a DetectorType.
	DetectorName string
	Raw          []byte
	RawV2        []byte
	// PrimarySecret is the verbatim match some detectors record when Raw is a
	// normalized form of what appeared in the input.
	PrimarySecret string
	SecretParts   map[string]string
	// Line is the 1-based line the engine reported for the result, or 0.
	Line int64
}

// NewFinding extracts the redaction-relevant fields of a detector result.
func NewFinding(r detectors.Result) Finding {
	return Finding{
		DetectorType:  r.DetectorType,
		DetectorName:  r.DetectorName,
		Raw:           r.Raw,
		RawV2:         r.RawV2,
		PrimarySecret: r.GetPrimarySecretValue(),
		SecretParts:   r.SecretParts,
	}
}

// FindingFromResult is NewFinding plus the line number the engine attached.
func FindingFromResult(r detectors.ResultWithMetadata) Finding {
	f := NewFinding(r.Result)
	f.Line = lineOf(r.SourceMetadata)
	return f
}

// Name returns a human-readable detector name.
func (f Finding) Name() string {
	if f.DetectorName != "" {
		return f.DetectorName
	}
	return f.DetectorType.String()
}

func lineOf(md *source_metadatapb.MetaData) int64 {
	if fs := md.GetFilesystem(); fs != nil {
		return fs.GetLine()
	}
	return 0
}

// identifierParts are SecretParts keys whose values identify an account,
// resource or endpoint rather than authenticate to it. They are left in place
// so that only the sensitive part of a credential is overwritten.
//
// Keys that are not listed here are treated as secret, so a new or renamed
// key in an upstream detector errs on the side of redacting.
var identifierParts = map[string]struct{}{
	"access_key_id":   {}, // AWS: the secret_access_key part is redacted
	"access_type":     {},
	"account_id":      {},
	"account_name":    {},
	"account_url":     {},
	"app":             {},
	"application":     {},
	"client_id":       {},
	"cloud_name":      {},
	"consumer_key":    {}, // OAuth client identifier; consumer_secret is redacted
	"database":        {},
	"domain":          {},
	"email":           {},
	"endpoint":        {},
	"env_id":          {},
	"host":            {},
	"id":              {},
	"ikey":            {}, // Duo integration key; skey is the secret
	"key_name":        {},
	"login":           {},
	"organization":    {},
	"organization_id": {},
	"project_id":      {},
	"region":          {},
	"registry":        {},
	"role_id":         {},
	"search_engine":   {},
	"service":         {},
	"store_url":       {},
	"subdomain":       {},
	"subscribe_key":   {}, // PubNub subscribe keys ship in client apps
	"token_name":      {},
	"type":            {}, // GCP: "service_account"
	"url":             {},
	"user":            {},
	"user_id":         {},
	"username":        {},
}

// IsIdentifierPart reports whether a SecretParts key names a non-secret
// identifier that redaction leaves in place.
func IsIdentifierPart(key string) bool {
	_, ok := identifierParts[strings.ToLower(key)]
	return ok
}

// target is one secret value of a finding that must be removed from the input.
type target struct {
	value string
	// anchored targets are not distinctive enough to redact everywhere they
	// occur, so only occurrences near the rest of the credential are redacted.
	anchored bool
	// fallback targets were derived from a value that could not be found
	// verbatim, such as the password of a URI a detector rebuilt.
	fallback bool
	// optional targets were derived from another target. They are redacted
	// wherever they occur, but need not occur at all.
	optional bool
}

// secretTargets returns the values of f that must be redacted. It returns
// nil when the detector did not report any secret material, in which case the
// finding cannot be redacted.
func secretTargets(f Finding) []target {
	var values []string
	identifiers := map[string]bool{}
	for _, k := range slices.Sorted(maps.Keys(f.SecretParts)) {
		if IsIdentifierPart(k) {
			identifiers[strings.TrimSpace(f.SecretParts[k])] = true
		} else {
			values = append(values, f.SecretParts[k])
		}
	}
	if f.PrimarySecret != "" {
		values = append(values, f.PrimarySecret)
	}
	if len(values) == 0 {
		// Without a secret part, Raw (and RawV2) is the best description of the
		// secret the detector has, unless it is one of the identifiers: then the
		// detector did not report its secret at all.
		for _, v := range [][]byte{f.Raw, f.RawV2} {
			if s := strings.TrimSpace(string(v)); s != "" && !identifiers[s] {
				values = append(values, s)
			}
		}
	}

	var targets []target
	seen := map[string]bool{}
	var add func(v string, optional bool)
	add = func(v string, optional bool) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		// A JSON document (for example a GCP service account key) is redacted
		// field by field so its structure survives.
		if leaves, ok := jsonSecretLeaves(v); ok {
			for _, l := range leaves {
				add(l, optional)
			}
			return
		}
		targets = append(targets, target{value: v, anchored: !distinctive(v), optional: optional})
		// The secret inside a container (the password of a URI, the body of a
		// PEM block, a SAS signature) is just as sensitive where it appears on
		// its own, as long as it is distinctive enough to tell apart. So is the
		// password of a base64 "user:password" credential.
		for _, r := range sensitiveRanges(v) {
			if p := v[r.start:r.end]; p != v && distinctive(p) {
				add(p, true)
			}
		}
		if pass, ok := basicAuthPassword(v); ok {
			add(pass, true)
		}
	}
	for _, v := range values {
		add(v, false)
	}
	// A detector that records its verbatim match as the primary secret
	// reports a normalized copy of the same secret too (PrivateKey reflows
	// keys and unescapes "\n"). Finding the verbatim match is enough.
	if p := strings.TrimSpace(f.PrimarySecret); p != "" {
		for i := range targets {
			if targets[i].value != p && sameSecret(targets[i].value, p) {
				targets[i].optional = true
			}
		}
	}
	return targets
}

// sameSecret reports whether a and b only differ in layout: whitespace,
// quotes, string concatenation and escaped newlines.
func sameSecret(a, b string) bool {
	norm := func(s string) string {
		for _, esc := range []string{`\\r`, `\\n`, `\\t`, `\r`, `\n`, `\t`} {
			s = strings.ReplaceAll(s, esc, "")
		}
		return compact(s)
	}
	return norm(a) == norm(b)
}

// containerTargets returns the values of f that embed its secrets, such as
// a connection URI reported as Raw next to the password. They are redacted
// only when the secrets themselves already read as the replacement but the
// detector still reports the credential.
func containerTargets(f Finding, targets []target, replacement string) []target {
	var out []target
	seen := map[string]bool{}
	for _, t := range targets {
		seen[t.value] = true
	}
	for _, v := range []string{string(f.Raw), string(f.RawV2), f.PrimarySecret} {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] || strings.HasPrefix(v, "{") {
			continue
		}
		seen[v] = true
		contains := strings.Contains(v, replacement)
		for _, t := range targets {
			contains = contains || strings.Contains(v, t.value)
		}
		if contains {
			out = append(out, target{value: v, anchored: !distinctive(v)})
		}
	}
	return out
}

// anchorValues returns the values of f that may appear near secret and so
// show where the credential is. Values that are (part of) the secret itself
// say nothing about that.
func anchorValues(f Finding, secret string) []string {
	vals := []string{string(f.Raw), string(f.RawV2), f.PrimarySecret}
	for _, v := range f.SecretParts {
		vals = append(vals, v)
	}
	var out []string
	for _, v := range vals {
		if v = strings.TrimSpace(v); len(v) < 4 {
			continue
		}
		out = append(out, v)
		if u := parseUserinfo(v); u != nil {
			out = append(out, v[u.hostStart:u.hostEnd], v[u.userStart:u.userEnd])
		}
	}
	return slices.DeleteFunc(out, func(a string) bool { return strings.Contains(secret, a) })
}

// distinctive reports whether v is unlikely to occur in the input except as
// the secret itself, so every occurrence can safely be redacted: it is long,
// or mixes letters with digits, or is long enough mixed-case text. Words and
// placeholders such as "PASSWORD" or "changeme" are not, even with
// punctuation attached.
func distinctive(v string) bool {
	if len(v) >= 20 {
		return true
	}
	if len(v) < 8 {
		return false
	}
	var lower, upper, digit bool
	for _, c := range v {
		switch {
		case 'a' <= c && c <= 'z':
			lower = true
		case 'A' <= c && c <= 'Z':
			upper = true
		case '0' <= c && c <= '9':
			digit = true
		}
	}
	return digit && (lower || upper) || lower && upper && len(v) >= 12
}

// rng is a half-open byte range within a value.
type rng struct{ start, end int }

var (
	pemBeginPat = regexp.MustCompile(`-----\s*BEGIN[ A-Za-z0-9_-]*?-----`)
	pemEndPat   = regexp.MustCompile(`-{4,5}\s*END[ A-Za-z0-9_-]*?-----`)
	// kvSecretPat matches key=value secrets inside connection strings and
	// query strings, e.g. "Password=hunter2;" or "&token=abc".
	kvSecretPat = regexp.MustCompile("(?i)(?:^|[;&?,\\s\"'`(])((?:password|passwd|pwd|pass|secret|token|apikey|api_key|accountkey|sharedaccesskey|sharedaccesssignature|sig)\\s*=\\s*)(\"[^\"]*\"|'[^']*'|[^;&\\s,\"'`)\\]}<>]+)")
)

// redactionLevels returns increasingly wide parts of v to redact, ending with
// nil, which stands for all of v.
//
// Containers that embed a secret in non-secret structure (PEM blocks, URIs
// with userinfo, connection strings) first only have the secret value
// redacted. Some detectors still report a container whose secret is the
// replacement (Postgres flags user:REDACTED@host), so the next level covers
// the whole credential field (user:password, password=...). Detectors that
// report a container regardless of its content (JDBC flags any JDBC URL) need
// the whole value redacted. Redaction uses the first level that is not
// already redacted, so each rescan widens it only as far as needed.
func redactionLevels(v string) [][]rng {
	if r, ok := pemBody(v); ok {
		return [][]rng{{r}, nil}
	}
	var values, fields []rng
	if u := parseUserinfo(v); u != nil {
		if u.passEnd > u.passStart {
			values = append(values, rng{u.passStart, u.passEnd})
		}
		fields = append(fields, rng{u.userStart, u.passEnd})
	}
	if strings.Contains(v, "=") && strings.ContainsAny(v, ";&?") {
		for _, m := range kvSecretPat.FindAllStringSubmatchIndex(v, -1) {
			s, e := m[4], m[5]
			if e-s >= 2 && (v[s] == '"' || v[s] == '\'') {
				s, e = s+1, e-1
			}
			if e > s {
				values = append(values, rng{s, e})
				fields = append(fields, rng{m[2], m[5]})
			}
		}
	}
	var levels [][]rng
	if len(values) > 0 {
		levels = append(levels, values)
	}
	if len(fields) > 0 {
		levels = append(levels, fields)
	}
	return append(levels, nil)
}

// sensitiveRanges returns the narrowest secret parts of v, or nil if all of v
// is secret.
func sensitiveRanges(v string) []rng {
	return redactionLevels(v)[0]
}

// pemBody returns the range between a PEM header and footer, excluding the
// whitespace and escaped newlines that surround the body.
func pemBody(v string) (rng, bool) {
	begin := pemBeginPat.FindStringIndex(v)
	if begin == nil {
		return rng{}, false
	}
	endLoc := pemEndPat.FindStringIndex(v[begin[1]:])
	if endLoc == nil {
		return rng{}, false
	}
	s, e := begin[1], begin[1]+endLoc[0]
	for n := 1; n > 0 && s < e; s += n {
		n = layoutLen(v[s:e], strings.HasPrefix)
	}
	for n := 1; n > 0 && s < e; e -= n {
		n = layoutLen(v[s:e], strings.HasSuffix)
	}
	if e <= s {
		return rng{}, false
	}
	return rng{s, e}, true
}

// layoutTokens are the whitespace, escaped newlines and string syntax that
// may surround a PEM body.
var layoutTokens = []string{`\\r\\n`, `\\n`, `\r\n`, `\n`, `\r`, `\\`, "\r\n", "\n", "\r", " ", "\t", `"`, `'`, "+"}

// layoutLen returns the length of the layout token that s starts (or, with
// strings.HasSuffix, ends) with, or 0.
func layoutLen(s string, has func(s, token string) bool) int {
	for _, t := range layoutTokens {
		if has(s, t) {
			return len(t)
		}
	}
	return 0
}

// userinfo holds offsets of the parts of a scheme://user:pass@host URI.
type userinfo struct {
	userStart, userEnd int
	passStart, passEnd int
	hostStart, hostEnd int
}

var schemePat = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// parseUserinfo locates the userinfo of a URI the way net/url splits it (the
// last '@' of the authority), but on the raw string so offsets stay exact and
// passwords with characters url.Parse rejects are still handled.
func parseUserinfo(v string) *userinfo {
	loc := schemePat.FindStringIndex(v)
	if loc == nil {
		// jdbc:postgresql://... and similar prefixed schemes.
		if i := strings.Index(v, "://"); i > 0 && !strings.ContainsAny(v[:i], " \t\n/@") {
			loc = []int{0, i + 3}
		} else {
			return nil
		}
	}
	authStart := loc[1]
	rest := v[authStart:]
	// The authority ends at whitespace, or at the first '/', '?' or '#' after
	// the last '@'. Passwords may contain unescaped '/' before that.
	end, at := len(rest), -1
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			end = i
			break
		}
		if c == '@' {
			at = i
			continue
		}
		if at >= 0 && (c == '/' || c == '?' || c == '#') {
			end = i
			break
		}
	}
	if at <= 0 {
		return nil
	}
	user := rest[:at]
	colon := strings.IndexByte(user, ':')
	name := user
	if colon >= 0 {
		name = user[:colon]
	}
	// "host/path?email=a@b" has no userinfo.
	if strings.ContainsAny(user, "?#") || strings.Contains(name, "/") {
		return nil
	}
	u := &userinfo{userStart: authStart, userEnd: authStart + at, passStart: authStart + at, passEnd: authStart + at}
	if colon >= 0 {
		u.userEnd = authStart + colon
		u.passStart = authStart + colon + 1
	}
	hostEnd := end
	if i := strings.IndexAny(rest[at+1:end], ";,"); i >= 0 {
		hostEnd = at + 1 + i
	}
	u.hostStart, u.hostEnd = authStart+at+1, authStart+hostEnd
	if u.hostEnd <= u.hostStart {
		return nil
	}
	return u
}

// fallbackTargets derives secrets from a value that was not found verbatim,
// for example the password of a connection URI that a detector rebuilt from
// its parts.
func fallbackTargets(v string) []target {
	var out []target
	for _, r := range sensitiveRanges(v) {
		if s := v[r.start:r.end]; s != v {
			out = append(out, target{value: s, anchored: !distinctive(s), fallback: true})
		}
	}
	// A Docker auth the detector recomputed from the username and password.
	if pass, ok := basicAuthPassword(v); ok {
		out = append(out, target{value: pass, anchored: !distinctive(pass), fallback: true})
	}
	return out
}

// jsonSecretLeaves returns the sensitive string fields of a JSON object.
func jsonSecretLeaves(v string) ([]string, bool) {
	if !strings.HasPrefix(v, "{") {
		return nil, false
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(v), &doc); err != nil {
		return nil, false
	}
	var out []string
	var walk func(m map[string]any)
	walk = func(m map[string]any) {
		for k, val := range m {
			switch t := val.(type) {
			case string:
				if t != "" && isSecretJSONKey(k) {
					out = append(out, t)
				}
			case map[string]any:
				walk(t)
			}
		}
	}
	walk(doc)
	slices.Sort(out)
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// isSecretJSONKey reports whether a JSON field holds secret material. Fields
// that name an endpoint, identifier or type ("token_uri", "private_key_id",
// "auth_provider_x509_cert_url") are not secret even if they mention one.
func isSecretJSONKey(k string) bool {
	k = strings.ToLower(k)
	if IsIdentifierPart(k) {
		return false
	}
	for _, suffix := range []string{"id", "uri", "url", "type", "name", "email"} {
		if strings.HasSuffix(k, suffix) {
			return false
		}
	}
	switch k {
	case "key", "auth", "token", "secret", "password", "passwd", "pwd", "credential", "credentials":
		return true
	}
	for _, s := range []string{"secret", "password", "passwd", "private_key", "privatekey", "_token", "token_", "apikey", "api_key", "access_key", "_auth"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// basicAuthPassword returns the password of a base64-encoded "user:password"
// value, such as a Basic authorization header or a Docker "auth" field. The
// password then also has to go wherever it appears on its own.
func basicAuthPassword(v string) (string, bool) {
	if len(v) < 8 || strings.ContainsAny(v, " \t\r\n") {
		return "", false
	}
	dec, _ := decodeBase64([]byte(v))
	if dec == nil {
		return "", false
	}
	for _, c := range dec {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	user, pass, ok := strings.Cut(string(dec), ":")
	if !ok || user == "" || len(pass) < 3 {
		return "", false
	}
	return pass, true
}

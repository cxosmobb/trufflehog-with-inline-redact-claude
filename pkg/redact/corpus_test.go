package redact

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// The corpus tests redact the example inputs of every detector's own tests.
// Those inputs are harvested from pkg/detectors/**/*_test.go, so detectors
// added upstream are covered without changes here.

const modulePath = "github.com/trufflesecurity/trufflehog/v3"

// maxCorpusPasses mirrors the CLI's default --max-passes.
const maxCorpusPasses = 5

// minDetectorCoverage is the share of detectors that must report at least one
// secret in the corpus. It guards against the harvester silently breaking.
const minDetectorCoverage = 0.90

func repoRoot(t testing.TB) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// detectorID identifies a detector implementation by its package, which also
// tells versions of the same detector type apart.
func detectorID(d detectors.Detector) string {
	t := reflect.TypeOf(d)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return strings.TrimPrefix(t.PkgPath(), modulePath+"/pkg/detectors/")
}

func detectorDir(root string, d detectors.Detector) string {
	t := reflect.TypeOf(d)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	rel := strings.TrimPrefix(t.PkgPath(), modulePath+"/")
	return filepath.Join(root, filepath.FromSlash(rel))
}

// corpusInput is an example input from a detector's tests.
type corpusInput struct {
	owner  string // detectorID of the detector whose tests hold the input
	source string
	data   []byte
}

// harvestCorpus returns the test inputs of every detector in dets.
func harvestCorpus(t testing.TB, dets []detectors.Detector) []corpusInput {
	root := repoRoot(t)
	byDir := map[string][]detectors.Detector{}
	for _, d := range dets {
		dir := detectorDir(root, d)
		byDir[dir] = append(byDir[dir], d)
	}
	dirs := make([]string, 0, len(byDir))
	for dir := range byDir {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	var inputs []corpusInput
	for _, dir := range dirs {
		ds := byDir[dir]
		for _, in := range harvestDir(t, root, dir, ds[0]) {
			for _, d := range ds {
				in.owner = detectorID(d)
				inputs = append(inputs, in)
			}
		}
	}
	return inputs
}

func hasBuildConstraint(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:build") || strings.HasPrefix(c.Text, "// +build") {
				return true
			}
		}
	}
	return false
}

// harvestDir extracts the `input` fields of the test tables in dir, and the
// raw text of its test files, which are themselves realistic source code with
// secrets in it.
func harvestDir(t testing.TB, root, dir string, d detectors.Detector) []corpusInput {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	fset := token.NewFileSet()
	var all []*ast.File
	var tests []*ast.File
	var testPaths []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			continue
		}
		isTest := strings.HasSuffix(name, "_test.go")
		// Integration tests need live credentials and hold no inputs.
		if isTest && (strings.HasSuffix(name, "_integration_test.go") || hasBuildConstraint(f)) {
			continue
		}
		all = append(all, f)
		if isTest {
			tests = append(tests, f)
			testPaths = append(testPaths, path)
		}
	}

	global := map[string]ast.Expr{}
	for _, f := range all {
		for _, decl := range f.Decls {
			if gd, ok := decl.(*ast.GenDecl); ok {
				collectSpecs(gd, global)
			}
		}
	}

	seen := map[string]bool{}
	var out []corpusInput
	add := func(source, s string) {
		if strings.TrimSpace(s) == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, corpusInput{source: source, data: []byte(s)})
	}
	for i, f := range tests {
		rel, _ := filepath.Rel(root, testPaths[i])
		rel = filepath.ToSlash(rel)
		if raw, err := os.ReadFile(testPaths[i]); err == nil {
			add(rel, string(raw))
		}
		for _, decl := range f.Decls {
			local := map[string]ast.Expr{}
			var body ast.Node = decl
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
				collectLocals(fd.Body, local)
				body = fd.Body
			}
			ev := &evaluator{local: local, global: global, det: d}
			ast.Inspect(body, func(n ast.Node) bool {
				kv, ok := n.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "input" {
					if s, ok := ev.str(kv.Value); ok {
						add(fmt.Sprintf("%s:%d", rel, fset.Position(kv.Pos()).Line), s)
					}
				}
				return true
			})
		}
	}
	return out
}

func collectSpecs(gd *ast.GenDecl, scope map[string]ast.Expr) {
	if gd.Tok != token.CONST && gd.Tok != token.VAR {
		return
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Values) != len(vs.Names) {
			continue
		}
		for i, name := range vs.Names {
			if _, dup := scope[name.Name]; !dup {
				scope[name.Name] = vs.Values[i]
			}
		}
	}
}

func collectLocals(body *ast.BlockStmt, scope map[string]ast.Expr) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) == len(s.Rhs) {
				for i, lhs := range s.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						if _, dup := scope[id.Name]; !dup {
							scope[id.Name] = s.Rhs[i]
						}
					}
				}
			}
		case *ast.DeclStmt:
			if gd, ok := s.Decl.(*ast.GenDecl); ok {
				collectSpecs(gd, scope)
			}
		}
		return true
	})
}

// evaluator statically evaluates the string expressions detector tests use to
// build their inputs: literals, constants, concatenation, fmt.Sprintf and a
// handful of strings/encoding helpers.
type evaluator struct {
	local, global map[string]ast.Expr
	det           detectors.Detector
	depth         int
}

func (ev *evaluator) str(e ast.Expr) (string, bool) {
	v, ok := ev.eval(e)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (ev *evaluator) eval(e ast.Expr) (any, bool) {
	if ev.depth > 32 {
		return nil, false
	}
	ev.depth++
	defer func() { ev.depth-- }()

	switch x := e.(type) {
	case *ast.BasicLit:
		switch x.Kind {
		case token.STRING, token.CHAR:
			s, err := strconv.Unquote(x.Value)
			return s, err == nil
		case token.INT:
			n, err := strconv.ParseInt(x.Value, 0, 64)
			return n, err == nil
		}
	case *ast.ParenExpr:
		return ev.eval(x.X)
	case *ast.Ident:
		if v, ok := ev.local[x.Name]; ok {
			return ev.eval(v)
		}
		if v, ok := ev.global[x.Name]; ok {
			return ev.eval(v)
		}
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return nil, false
		}
		a, ok1 := ev.eval(x.X)
		b, ok2 := ev.eval(x.Y)
		if !ok1 || !ok2 {
			return nil, false
		}
		switch av := a.(type) {
		case string:
			if bv, ok := b.(string); ok {
				return av + bv, true
			}
		case int64:
			if bv, ok := b.(int64); ok {
				return av + bv, true
			}
		}
	case *ast.CompositeLit:
		var out []string
		for _, elt := range x.Elts {
			s, ok := ev.str(elt)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case *ast.IndexExpr:
		a, ok1 := ev.eval(x.X)
		i, ok2 := ev.eval(x.Index)
		list, ok3 := a.([]string)
		n, ok4 := i.(int64)
		if ok1 && ok2 && ok3 && ok4 && n >= 0 && int(n) < len(list) {
			return list[n], true
		}
	case *ast.CallExpr:
		return ev.call(x)
	}
	return nil, false
}

func (ev *evaluator) args(call *ast.CallExpr) ([]any, bool) {
	out := make([]any, 0, len(call.Args))
	for _, a := range call.Args {
		v, ok := ev.eval(a)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

func (ev *evaluator) call(call *ast.CallExpr) (any, bool) {
	// Conversions: string(x), []byte(x).
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if fn.Name == "string" && len(call.Args) == 1 {
			return ev.str(call.Args[0])
		}
		return nil, false
	case *ast.ArrayType:
		if len(call.Args) == 1 {
			return ev.str(call.Args[0])
		}
		return nil, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	if sel.Sel.Name == "Keywords" && len(call.Args) == 0 {
		return ev.det.Keywords(), true
	}
	if inner, ok := sel.X.(*ast.SelectorExpr); ok {
		// base64.StdEncoding.EncodeToString(x) and friends.
		if pkg, ok := inner.X.(*ast.Ident); ok && pkg.Name == "base64" && sel.Sel.Name == "EncodeToString" && len(call.Args) == 1 {
			s, ok := ev.str(call.Args[0])
			if !ok {
				return nil, false
			}
			encs := map[string]*base64.Encoding{
				"StdEncoding": base64.StdEncoding, "URLEncoding": base64.URLEncoding,
				"RawStdEncoding": base64.RawStdEncoding, "RawURLEncoding": base64.RawURLEncoding,
			}
			if enc, ok := encs[inner.Sel.Name]; ok {
				return enc.EncodeToString([]byte(s)), true
			}
		}
		return nil, false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil, false
	}
	args, ok := ev.args(call)
	if !ok {
		return nil, false
	}
	strArg := func(i int) (string, bool) {
		if i >= len(args) {
			return "", false
		}
		s, ok := args[i].(string)
		return s, ok
	}
	intArg := func(i int) (int, bool) {
		if i >= len(args) {
			return 0, false
		}
		n, ok := args[i].(int64)
		return int(n), ok
	}
	switch pkg.Name + "." + sel.Sel.Name {
	case "fmt.Sprintf":
		format, ok := strArg(0)
		if !ok {
			return nil, false
		}
		return fmt.Sprintf(format, args[1:]...), true
	case "strings.Repeat":
		s, ok1 := strArg(0)
		n, ok2 := intArg(1)
		if ok1 && ok2 && n >= 0 && n < 1<<16 {
			return strings.Repeat(s, n), true
		}
	case "strings.Join":
		if len(args) == 2 {
			list, ok1 := args[0].([]string)
			sep, ok2 := strArg(1)
			if ok1 && ok2 {
				return strings.Join(list, sep), true
			}
		}
	case "strings.ToUpper", "strings.ToLower", "strings.TrimSpace":
		s, ok := strArg(0)
		if !ok {
			return nil, false
		}
		return map[string]func(string) string{
			"ToUpper": strings.ToUpper, "ToLower": strings.ToLower, "TrimSpace": strings.TrimSpace,
		}[sel.Sel.Name](s), true
	case "strings.ReplaceAll":
		s, ok1 := strArg(0)
		o, ok2 := strArg(1)
		n, ok3 := strArg(2)
		if ok1 && ok2 && ok3 {
			return strings.ReplaceAll(s, o, n), true
		}
	case "strconv.Itoa":
		if n, ok := intArg(0); ok {
			return strconv.Itoa(n), true
		}
	case "hex.EncodeToString":
		if s, ok := strArg(0); ok {
			return hex.EncodeToString([]byte(s)), true
		}
	}
	return nil, false
}

// detected is a result together with the detector that produced it.
type detected struct {
	id  string
	res detectors.Result
}

// scanner runs every detector on an input, the way the engine does for a
// plain chunk, without verification.
type scanner struct {
	core *ahocorasick.Core
	ids  map[detectors.Detector]string
}

func newScanner(dets []detectors.Detector) *scanner {
	s := &scanner{core: ahocorasick.NewAhoCorasickCore(dets), ids: map[detectors.Detector]string{}}
	for _, d := range dets {
		s.ids[d] = detectorID(d)
	}
	return s
}

func (s *scanner) scan(data []byte) []detected {
	var out []detected
	for _, m := range s.core.FindDetectorMatches(data) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		results, _ := m.Detector.FromData(ctx, false, data)
		cancel()
		for _, r := range results {
			out = append(out, detected{id: s.ids[m.Detector], res: r})
		}
	}
	return out
}

// outcome is what redacting one input produced.
type outcome struct {
	initial    []detected
	final      []byte // the input after the last pass
	passes     int
	escalators []string // detectors that still reported secrets after the first pass
	residual   []string // detectors still matching the redacted structure
	failures   map[string][]string
	redactions int
	redacted   int // original bytes overwritten in the first pass
	secret     int // bytes of the secrets located in the first pass
	idsRemoved int // identifier parts present in the input but gone afterwards
}

func (o *outcome) fail(id, format string, args ...any) {
	if o.failures == nil {
		o.failures = map[string][]string{}
	}
	o.failures[id] = append(o.failures[id], fmt.Sprintf(format, args...))
}

// redactInput redacts data until no detector reports anything, like the CLI.
func redactInput(s *scanner, data []byte) outcome {
	var o outcome
	cur := data
	var first Report
	var firstOut []byte
	for pass := 1; ; pass++ {
		found := s.scan(cur)
		if pass == 1 {
			o.initial = found
		}
		if len(found) == 0 {
			break
		}
		findings := make([]Finding, len(found))
		for i, d := range found {
			findings[i] = NewFinding(d.res)
		}
		out, report := Redact(cur, findings, Options{})
		residual := map[int]bool{}
		for _, i := range report.Residual {
			residual[i] = true
		}
		for _, i := range report.Unredacted {
			o.fail(found[i].id, "pass %d: secret could not be redacted: %s", pass, preview(found[i].res.Raw))
		}
		if pass == 1 {
			first, firstOut = report, out
		}
		if bytes.Equal(out, cur) || pass > maxCorpusPasses {
			// Whatever is still reported must hold no secret material.
			for i, d := range found {
				if residual[i] {
					o.residual = append(o.residual, d.id)
				} else if pass > maxCorpusPasses {
					o.fail(d.id, "still reported after %d passes: %s", maxCorpusPasses, preview(d.res.Raw))
				}
			}
			break
		}
		if pass > 1 {
			for i, d := range found {
				if !residual[i] {
					o.escalators = append(o.escalators, d.id)
				}
			}
		}
		o.passes = pass
		cur = out
	}
	o.final = cur
	if len(o.initial) == 0 {
		return o
	}

	findings := make([]Finding, len(o.initial))
	for i, d := range o.initial {
		findings[i] = NewFinding(d.res)
	}
	checkFirstPass(&o, data, firstOut, first, findings)
	checkSecretsGone(&o, data, cur)
	return o
}

// checkFirstPass verifies that the first pass, which redacts the narrowest
// form of each secret, only overwrote bytes of values a detector reported.
func checkFirstPass(o *outcome, data, out []byte, report Report, findings []Finding) {
	covered := reportedMask(data, findings)
	o.redactions = len(report.Redactions)
	for _, r := range report.Redactions {
		if r.Encoding == "plain" {
			o.redacted += r.End - r.Start
		}
		if r.Encoding != "plain" || IsBinary(data[r.Start:r.End]) {
			continue
		}
		for i := r.Start; i < r.End; i++ {
			if !covered[i] {
				o.fail(o.initialID(r.Findings), "over-redaction at line %d: %q is outside every reported value", r.Line, preview(data[r.Start:r.End]))
				break
			}
		}
	}
	for _, isSecret := range secretMask(data, findings) {
		if isSecret {
			o.secret++
		}
	}
	for _, f := range findings {
		for k, v := range f.SecretParts {
			if IsIdentifierPart(k) && len(v) >= 4 && bytes.Contains(data, []byte(v)) && !bytes.Contains(out, []byte(v)) {
				o.idsRemoved++
			}
		}
	}
}

func (o *outcome) initialID(idx []int) string {
	if len(idx) > 0 && idx[0] < len(o.initial) {
		return o.initial[idx[0]].id
	}
	return "unknown"
}

// checkSecretsGone verifies that no distinctive secret survives redaction.
func checkSecretsGone(o *outcome, data, out []byte) {
	for _, d := range o.initial {
		for _, t := range secretTargets(NewFinding(d.res)) {
			pieces := []string{t.value}
			if rs := sensitiveRanges(t.value); rs != nil {
				pieces = pieces[:0]
				for _, r := range rs {
					pieces = append(pieces, t.value[r.start:r.end])
				}
			}
			for _, p := range pieces {
				if distinctive(p) && p != DefaultReplacement && bytes.Contains(data, []byte(p)) && bytes.Contains(out, []byte(p)) {
					o.fail(d.id, "secret still present after redaction: %s", preview([]byte(p)))
				}
			}
		}
	}
}

// secretMask marks the bytes of data that hold the narrowest form of a
// finding's secrets, which is what an exact redaction would overwrite.
func secretMask(data []byte, findings []Finding) []bool {
	mask := make([]bool, len(data))
	views := buildViews(data)
	for _, f := range findings {
		for _, t := range secretTargets(f) {
			needle := []byte(t.value)
			ranges := sensitiveRanges(t.value)
			if ranges == nil {
				ranges = []rng{{0, len(needle)}}
			}
			for _, vw := range views {
				for off := 0; off < len(vw.text); {
					i := bytes.Index(vw.text[off:], needle)
					if i < 0 {
						break
					}
					for _, r := range ranges {
						s, e := vw.orig(off+i+r.start, off+i+r.end)
						for j := s; j < e; j++ {
							mask[j] = true
						}
					}
					off += i + len(needle)
				}
			}
		}
	}
	return mask
}

// reportedMask marks the bytes of data inside an occurrence of any value a
// finding reported, widened to token boundaries the way redaction does.
// Occurrences are also looked up in decoded views of data (escapes, HTML
// entities, ...), since detectors report values in decoded form.
func reportedMask(data []byte, findings []Finding) []bool {
	mask := make([]bool, len(data))
	views := buildViews(data)
	for _, f := range findings {
		vals := []string{string(f.Raw), string(f.RawV2), f.PrimarySecret}
		for _, v := range f.SecretParts {
			vals = append(vals, v)
		}
		for _, t := range secretTargets(f) {
			vals = append(vals, t.value)
		}
		for _, v := range vals {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			needle := []byte(v)
			for _, vw := range views {
				for off := 0; off < len(vw.text); {
					i := bytes.Index(vw.text[off:], needle)
					if i < 0 {
						break
					}
					a, b := off+i, off+i+len(needle)
					ea, eb := tokenBounds(vw.text, a, b, v, vw.adjacent)
					s, e := vw.orig(min(a, ea), max(b, eb))
					for j := s; j < e; j++ {
						mask[j] = true
					}
					off = b
				}
			}
		}
	}
	return mask
}

func preview(b []byte) string {
	s := strings.ReplaceAll(string(b), "\n", `\n`)
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return s
}

// detectorStats aggregates outcomes per detector.
type detectorStats struct {
	samples, findings, redactions int
	redacted, secret              int
	maxPasses, escalated          int
	residual                      int
	idsRemoved                    int
	failures                      []string
}

// secretParts are the SecretParts keys detectors use for secret material.
// Like any key missing from identifierParts (targets.go) they are redacted;
// listing them lets TestRedactDetectorCorpus flag keys nobody has classified.
var secretParts = map[string]struct{}{
	"account_key": {}, "api_key": {}, "api_secret": {}, "app_key": {}, "auth": {},
	"client": {}, "client_secret": {}, "connection_string": {}, "consumer_secret": {},
	"key": {}, "passphrase": {}, "password": {}, "pat": {}, "pat_secret": {},
	"private_key": {}, "refresh_token": {}, "secret": {}, "secret_access_key": {},
	"secret_id": {}, "session_token": {}, "sid": {}, "skey": {}, "token": {},
	"user_key": {}, "write_key": {},
}

// corpusTestsEnabled gates the corpus tests, which take minutes. The fork's CI
// enables them; locally run them with TRUFFLEHOG_REDACT_CORPUS=1.
func corpusTestsEnabled(t *testing.T) {
	if testing.Short() || os.Getenv("TRUFFLEHOG_REDACT_CORPUS") == "" {
		t.Skip("set TRUFFLEHOG_REDACT_CORPUS=1 to redact every detector's test inputs")
	}
}

func TestRedactDetectorCorpus(t *testing.T) {
	corpusTestsEnabled(t)
	enableCLIFeatures()
	dets := defaults.DefaultDetectors()
	inputs := harvestCorpus(t, dets)
	s := newScanner(dets)
	t.Logf("harvested %d inputs for %d detectors", len(inputs), len(dets))

	stats := map[string]*detectorStats{}
	statsFor := func(id string) *detectorStats {
		if stats[id] == nil {
			stats[id] = &detectorStats{}
		}
		return stats[id]
	}
	for _, d := range dets {
		statsFor(detectorID(d))
	}

	var mu sync.Mutex
	partKeys := map[string]string{} // SecretParts key -> a detector using it
	work := make(chan corpusInput)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for in := range work {
				o := redactInput(s, in.data)
				mu.Lock()
				fired := map[string]bool{}
				for _, d := range o.initial {
					for k := range d.res.SecretParts {
						partKeys[k] = d.id
					}
					st := statsFor(d.id)
					st.findings++
					if !fired[d.id] {
						fired[d.id] = true
						st.samples++
						st.maxPasses = max(st.maxPasses, o.passes)
						st.redactions += o.redactions
						st.redacted += o.redacted
						st.secret += o.secret
						st.idsRemoved += o.idsRemoved
					}
				}
				for _, id := range unique(o.escalators) {
					statsFor(id).escalated++
				}
				for _, id := range unique(o.residual) {
					statsFor(id).residual++
				}
				for id, fs := range o.failures {
					for _, f := range fs {
						statsFor(id).failures = append(statsFor(id).failures, in.source+": "+f)
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, in := range inputs {
		work <- in
	}
	close(work)
	wg.Wait()

	ids := make([]string, 0, len(stats))
	for id := range stats {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var covered, failed int
	var uncovered, residual []string
	for _, id := range ids {
		st := stats[id]
		if st.samples > 0 {
			covered++
		} else {
			uncovered = append(uncovered, id)
		}
		if st.residual > 0 {
			residual = append(residual, fmt.Sprintf("%s (%d)", id, st.residual))
		}
		if len(st.failures) > 0 {
			failed++
			for i, f := range st.failures {
				if i == 5 {
					t.Errorf("%s: ... %d more failures", id, len(st.failures)-5)
					break
				}
				t.Errorf("%s: %s", id, f)
			}
		}
	}
	// Every SecretParts key must have been classified as secret or identifier.
	// Unknown keys are redacted, which is safe but may over-redact.
	for _, k := range slices.Sorted(maps.Keys(partKeys)) {
		_, secret := secretParts[strings.ToLower(k)]
		if !secret && !IsIdentifierPart(k) {
			t.Errorf("SecretParts key %q (used by %s) is neither in secretParts nor identifierParts in targets.go", k, partKeys[k])
		}
	}

	coverage := float64(covered) / float64(len(dets))
	t.Logf("%d/%d detectors (%.1f%%) reported secrets in the corpus; %d had redaction failures", covered, len(dets), 100*coverage, failed)
	if len(uncovered) > 0 {
		t.Logf("detectors without a positive sample: %s", strings.Join(uncovered, ", "))
	}
	if len(residual) > 0 {
		t.Logf("detectors still matching redacted structure (no secret left), by inputs: %s", strings.Join(residual, ", "))
	}
	if coverage < minDetectorCoverage {
		t.Errorf("detector coverage %.1f%% is below %.0f%%; the input harvester may need updating", 100*coverage, 100*minDetectorCoverage)
	}
	if path := os.Getenv("REDACT_CORPUS_REPORT"); path != "" {
		if err := writeCorpusReport(path, ids, stats, len(inputs), covered, len(dets)); err != nil {
			t.Fatal(err)
		}
	}
}

func unique(in []string) []string {
	slices.Sort(in)
	return slices.Compact(in)
}

func writeCorpusReport(path string, ids []string, stats map[string]*detectorStats, inputs, covered, total int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Redaction corpus report\n\n%d inputs, %d/%d detectors with at least one positive sample.\n\n", inputs, covered, total)
	b.WriteString("Columns: inputs with findings, findings, redactions in the first pass, bytes redacted per byte of located secret, " +
		"passes needed, inputs where redaction had to widen, inputs where the detector still matches the redacted structure " +
		"(no secret material left), identifier parts removed, failures.\n\n")
	b.WriteString("| detector | inputs | findings | redactions | redacted/secret | max passes | widened | residual | identifiers removed | failures |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, id := range ids {
		st := stats[id]
		ratio := "-"
		if st.secret > 0 {
			ratio = fmt.Sprintf("%.2f", float64(st.redacted)/float64(st.secret))
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %s | %d | %d | %d | %d | %d |\n", id, st.samples, st.findings, st.redactions, ratio,
			st.maxPasses, st.escalated, st.residual, st.idsRemoved, len(st.failures))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

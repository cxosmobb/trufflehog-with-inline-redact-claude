package redact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// engineScan scans paths with the trufflehog engine, configured the way the
// redact command configures it.
func engineScan(t testing.TB) ScanFunc {
	return func(paths []string) (*Collector, error) {
		ctx := context.Background()
		n := runtime.NumCPU()
		collector := NewCollector()
		eng, err := engine.NewEngine(ctx, &engine.Config{
			Concurrency:    n,
			Detectors:      defaults.DefaultDetectors(),
			Verify:         false,
			NoIgnoreTag:    true,
			Results:        map[string]struct{}{"verified": {}, "unverified": {}, "unknown": {}, "filtered_unverified": {}},
			Dispatcher:     collector,
			MaxDecodeDepth: DefaultMaxDecodeDepth,
			SourceManager: sources.NewManager(
				sources.WithConcurrentSources(n),
				sources.WithConcurrentUnits(n),
				sources.WithSourceUnits(),
				sources.WithBufferedOutput(64),
			),
		})
		if err != nil {
			return nil, err
		}
		eng.Start(ctx)
		if _, err := eng.ScanFileSystem(ctx, sources.FilesystemConfig{Paths: paths}); err != nil {
			return nil, err
		}
		return collector, eng.Finish(ctx)
	}
}

// encodings are the forms the engine test stores corpus inputs in, one per
// trufflehog decoder (plus JSON strings, which detectors unescape).
var encodings = map[string]func([]byte) ([]byte, bool){
	"plain": func(b []byte) ([]byte, bool) { return b, true },
	"base64": func(b []byte) ([]byte, bool) {
		return []byte("value: " + base64.StdEncoding.EncodeToString(b) + "\n"), isASCII(b)
	},
	"utf16le": func(b []byte) ([]byte, bool) {
		if !utf8.Valid(b) {
			return nil, false
		}
		out := []byte{0xff, 0xfe}
		for _, u := range utf16.Encode([]rune(string(b))) {
			out = append(out, byte(u), byte(u>>8))
		}
		return out, true
	},
	"uescape": func(b []byte) ([]byte, bool) {
		var sb strings.Builder
		sb.WriteString(`{"value": "`)
		for _, r := range string(b) {
			if r > 0xffff {
				return nil, false
			}
			fmt.Fprintf(&sb, `\u%04x`, r)
		}
		sb.WriteString("\"}\n")
		return []byte(sb.String()), true
	},
	"html": func(b []byte) ([]byte, bool) {
		return []byte("<html><body><pre>" + html.EscapeString(string(b)) + "</pre></body></html>\n"), true
	},
	"json": func(b []byte) ([]byte, bool) {
		v, err := json.Marshal(map[string]string{"value": string(b)})
		return append(v, '\n'), err == nil
	},
}

func TestRedactEngineCorpus(t *testing.T) {
	corpusTestsEnabled(t)
	enableCLIFeatures()
	dets := defaults.DefaultDetectors()
	s := newScanner(dets)

	// Up to two inputs per detector that it reports secrets in.
	perOwner := map[string]int{}
	var samples [][]byte
	for _, in := range harvestCorpus(t, dets) {
		if perOwner[in.owner] >= 2 {
			continue
		}
		found := false
		for _, d := range s.scan(in.data) {
			found = found || d.id == in.owner
		}
		if found {
			perOwner[in.owner]++
			samples = append(samples, in.data)
		}
	}

	// REDACT_ENGINE_DEBUG=<encoding>:<sample> redacts a single file and prints
	// each pass, e.g. REDACT_ENGINE_DEBUG=utf16le:0353.
	if spec := os.Getenv("REDACT_ENGINE_DEBUG"); spec != "" {
		debugEngineSample(t, spec, samples)
		return
	}

	root := t.TempDir()
	files := 0
	for name, encode := range encodings {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for i, sample := range samples {
			data, ok := encode(sample)
			if !ok {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%04d.txt", i)), data, 0o644); err != nil {
				t.Fatal(err)
			}
			files++
		}
	}
	t.Logf("wrote %d files for %d samples", files, len(samples))

	scan := engineScan(t)
	before, err := scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	perEncoding := map[string]int{}
	for _, path := range before.Files() {
		rel, _ := filepath.Rel(root, path)
		perEncoding[strings.Split(filepath.ToSlash(rel), "/")[0]]++
	}
	t.Logf("files with findings before redaction, by encoding: %v", perEncoding)
	for name := range encodings {
		if perEncoding[name] == 0 {
			t.Errorf("no findings in %s files: the engine did not decode them", name)
		}
	}

	res, err := Run([]string{root}, scan, RunOptions{InPlace: true, MaxPasses: maxCorpusPasses})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d passes, %d files changed, %d redactions, %d files with residual findings",
		res.Passes, len(res.Changed), res.Redactions, len(res.Residual))
	for path, findings := range res.Unredactable {
		rel, _ := filepath.Rel(root, path)
		for _, f := range findings {
			t.Errorf("%s: %s finding at line %d could not be redacted: %s", rel, f.Name(), f.Line, preview(f.Raw))
		}
	}
	for _, f := range res.Orphaned {
		t.Errorf("finding without a file: %s", f.Name())
	}
}

func debugEngineSample(t *testing.T, spec string, samples [][]byte) {
	name, idx, _ := strings.Cut(spec, ":")
	var i int
	if _, err := fmt.Sscanf(idx, "%d", &i); err != nil || i >= len(samples) || encodings[name] == nil {
		t.Fatalf("bad REDACT_ENGINE_DEBUG %q", spec)
	}
	data, _ := encodings[name](samples[i])
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("sample:\n%s", samples[i])
	scan := engineScan(t)
	for pass := 1; pass <= maxCorpusPasses+1; pass++ {
		c, err := scan([]string{path})
		if err != nil {
			t.Fatal(err)
		}
		findings := c.Findings(path)
		for j, f := range findings {
			t.Logf("pass %d finding %d %s line %d: raw=%q rawV2=%q primary=%q parts=%q", pass, j, f.Name(), f.Line, f.Raw, f.RawV2, f.PrimarySecret, f.SecretParts)
		}
		res, err := RedactFile(path, findings, Options{}, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("pass %d: unredacted=%v residual=%v redactions=%+v", pass, res.Report.Unredacted, res.Report.Residual, res.Report.Redactions)
		if !res.Written {
			break
		}
	}
	out, _ := os.ReadFile(path)
	for _, v := range buildViews(out) {
		if v.name == name || name == "plain" && v.name == "plain" {
			t.Logf("final %s view:\n%s", v.name, v.text)
		}
	}
}

const archiveSecret = "https://hooks.slack.com/services/T0A1B2C3D/B0A1B2C3D/abcdefghijklmnopqrstuvwx"

func writeZip(t *testing.T, path, member string, content []byte) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRedactEngineArchives(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine")
	}
	content := []byte("SLACK_WEBHOOK=" + archiveSecret + "\n")

	t.Run("compressed archives are unredactable", func(t *testing.T) {
		dir := t.TempDir()
		zipPath := filepath.Join(dir, "bundle.zip")
		writeZip(t, zipPath, "config.env", content)

		res, err := Run([]string{dir}, engineScan(t), RunOptions{InPlace: true, MaxPasses: 3})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := res.Unredactable[zipPath]; !ok || res.Clean() {
			t.Fatalf("zip not reported as unredactable: %+v", res)
		}

		res, err = Run([]string{dir}, engineScan(t), RunOptions{InPlace: true, MaxPasses: 3, RemoveUnredactable: true})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Clean() {
			t.Fatalf("unredactable files left: %+v", res.Unredactable)
		}
		if _, err := os.Stat(zipPath); !os.IsNotExist(err) {
			t.Fatalf("zip was not removed: %v", err)
		}
	})

	t.Run("uncompressed archives keep their layout", func(t *testing.T) {
		dir := t.TempDir()
		tarPath := filepath.Join(dir, "bundle.tar")
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(&tar.Header{Name: "config.env", Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		original := buf.Bytes()
		if err := os.WriteFile(tarPath, original, 0o644); err != nil {
			t.Fatal(err)
		}

		res, err := Run([]string{dir}, engineScan(t), RunOptions{InPlace: true, MaxPasses: 3})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Clean() || res.Redactions == 0 {
			t.Fatalf("tar not redacted cleanly: %+v", res)
		}
		redacted, err := os.ReadFile(tarPath)
		if err != nil {
			t.Fatal(err)
		}
		if len(redacted) != len(original) {
			t.Fatalf("tar size changed from %d to %d", len(original), len(redacted))
		}
		tr := tar.NewReader(bytes.NewReader(redacted))
		if _, err := tr.Next(); err != nil {
			t.Fatalf("redacted tar is unreadable: %v", err)
		}
		member, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		want := "SLACK_WEBHOOK=REDACTED" + strings.Repeat("*", len(archiveSecret)-len(DefaultReplacement)) + "\n"
		if string(member) != want {
			t.Fatalf("redacted member = %q, want %q", member, want)
		}
	})
}

package redact

import (
	"os"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// TestRedactCorpusDebug prints every redaction pass for the corpus inputs of
// one detector. Run it with REDACT_DEBUG_DETECTOR=<detector id> and optionally
// REDACT_DEBUG_SOURCE=<substring of the input's source> to investigate a
// TestRedactDetectorCorpus failure.
func TestRedactCorpusDebug(t *testing.T) {
	id := os.Getenv("REDACT_DEBUG_DETECTOR")
	if id == "" {
		t.Skip("set REDACT_DEBUG_DETECTOR")
	}
	source := os.Getenv("REDACT_DEBUG_SOURCE")
	enableCLIFeatures()
	dets := defaults.DefaultDetectors()
	s := newScanner(dets)
	for _, in := range harvestCorpus(t, dets) {
		if in.owner != id || !strings.Contains(in.source, source) {
			continue
		}
		if os.Getenv("REDACT_DEBUG_DIFF") != "" {
			// Only show the lines redaction changed.
			final := redactInput(s, in.data).final
			before, after := strings.Split(string(in.data), "\n"), strings.Split(string(final), "\n")
			for i := range before {
				if i < len(after) && before[i] != after[i] {
					t.Logf("%s:%d\n  - %s\n  + %s", in.source, i+1, strings.TrimSpace(before[i]), strings.TrimSpace(after[i]))
				}
			}
			continue
		}
		cur := in.data
		t.Logf("==== %s\n%s", in.source, cur)
		for pass := 1; pass <= maxCorpusPasses+1; pass++ {
			found := s.scan(cur)
			if len(found) == 0 {
				break
			}
			findings := make([]Finding, len(found))
			for i, d := range found {
				findings[i] = NewFinding(d.res)
				t.Logf("pass %d finding %d %s: raw=%q rawV2=%q primary=%q parts=%q", pass, i, d.id,
					d.res.Raw, d.res.RawV2, d.res.GetPrimarySecretValue(), d.res.SecretParts)
			}
			out, report := Redact(cur, findings, Options{})
			t.Logf("pass %d unredacted=%v redactions=%+v\n%s", pass, report.Unredacted, report.Redactions, out)
			if string(out) == string(cur) {
				break
			}
			cur = out
		}
	}
}

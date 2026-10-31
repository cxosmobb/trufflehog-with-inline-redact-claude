package redact

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// enableCLIFeatures turns on the features main.go enables for every scan.
func enableCLIFeatures() {
	for _, flag := range detectorFeatureFlags {
		flag.Store(true)
	}
	feature.HTMLDecoderEnabled.Store(true)
}

// TestDetectorFeatureFlagsComplete fails when upstream has added a detector
// feature flag since detector_flags_test.go was generated. The upstream sync
// regenerates it; after merging upstream by hand, run go run ./hack/detectorflags.
func TestDetectorFeatureFlagsComplete(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(repoRoot(t), "pkg", "feature", "feature.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range spec.Names {
			if strings.HasSuffix(name.Name, "DetectorEnabled") {
				if _, ok := detectorFeatureFlags[name.Name]; !ok {
					missing = append(missing, name.Name)
				}
			}
		}
		return true
	})
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("detector_flags_test.go lacks upstream feature flags %s; run go run ./hack/detectorflags",
			strings.Join(missing, ", "))
	}
}

package redact

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// detectorFeatureFlags are the feature flags that gate detectors. The CLI
// (main.go) enables all of them, so the tests do too in order to exercise the
// same detectors. TestDetectorFeatureFlagsComplete fails when upstream adds a
// flag that is missing here.
var detectorFeatureFlags = map[string]*atomic.Bool{
	"BraintrustDetectorEnabled":                &feature.BraintrustDetectorEnabled,
	"CloudflareApiTokenV2DetectorEnabled":      &feature.CloudflareApiTokenV2DetectorEnabled,
	"CloudflareGlobalApiKeyV2DetectorEnabled":  &feature.CloudflareGlobalApiKeyV2DetectorEnabled,
	"CloudinaryDetectorEnabled":                &feature.CloudinaryDetectorEnabled,
	"DatadogApiKeyDetectorEnabled":             &feature.DatadogApiKeyDetectorEnabled,
	"DuffelTokenDetectorEnabled":               &feature.DuffelTokenDetectorEnabled,
	"DuoDetectorEnabled":                       &feature.DuoDetectorEnabled,
	"EnigmaDetectorEnabled":                    &feature.EnigmaDetectorEnabled,
	"FigmaV3DetectorEnabled":                   &feature.FigmaV3DetectorEnabled,
	"GitLabOAuthDetectorEnabled":               &feature.GitLabOAuthDetectorEnabled,
	"HashiCorpVaultBatchTokenDetectorEnabled":  &feature.HashiCorpVaultBatchTokenDetectorEnabled,
	"HashiCorpVaultTokenDetectorEnabled":       &feature.HashiCorpVaultTokenDetectorEnabled,
	"HumioAPITokenDetectorEnabled":             &feature.HumioAPITokenDetectorEnabled,
	"IPInfoDetectorEnabled":                    &feature.IPInfoDetectorEnabled,
	"InfisicalDetectorEnabled":                 &feature.InfisicalDetectorEnabled,
	"KongKonnectDetectorEnabled":               &feature.KongKonnectDetectorEnabled,
	"LobDetectorEnabled":                       &feature.LobDetectorEnabled,
	"MSTeamsWebhookV2DetectorEnabled":          &feature.MSTeamsWebhookV2DetectorEnabled,
	"NewRelicBrowserKeyDetectorEnabled":        &feature.NewRelicBrowserKeyDetectorEnabled,
	"NewRelicInsightsInsertKeyDetectorEnabled": &feature.NewRelicInsightsInsertKeyDetectorEnabled,
	"NewRelicInsightsQueryKeyDetectorEnabled":  &feature.NewRelicInsightsQueryKeyDetectorEnabled,
	"NewRelicLicenseKeyDetectorEnabled":        &feature.NewRelicLicenseKeyDetectorEnabled,
	"NewRelicMobileAppTokenDetectorEnabled":    &feature.NewRelicMobileAppTokenDetectorEnabled,
	"NewRelicUserKeyDetectorEnabled":           &feature.NewRelicUserKeyDetectorEnabled,
	"OctopusDeployDetectorEnabled":             &feature.OctopusDeployDetectorEnabled,
	"OpenRouterDetectorEnabled":                &feature.OpenRouterDetectorEnabled,
	"PgAnalyzeReadKeyDetectorEnabled":          &feature.PgAnalyzeReadKeyDetectorEnabled,
	"PineconeDetectorEnabled":                  &feature.PineconeDetectorEnabled,
	"RedHatPyxisDetectorEnabled":               &feature.RedHatPyxisDetectorEnabled,
	"ResendDetectorEnabled":                    &feature.ResendDetectorEnabled,
	"RevDetectorEnabled":                       &feature.RevDetectorEnabled,
	"ShippoDetectorEnabled":                    &feature.ShippoDetectorEnabled,
	"SolarwindsDetectorEnabled":                &feature.SolarwindsDetectorEnabled,
	"SonarCloudV2DetectorEnabled":              &feature.SonarCloudV2DetectorEnabled,
	"SonarQubeDetectorEnabled":                 &feature.SonarQubeDetectorEnabled,
	"TlyDetectorEnabled":                       &feature.TlyDetectorEnabled,
	"UserDetectorEnabled":                      &feature.UserDetectorEnabled,
	"WeightsAndBiasesV2DetectorEnabled":        &feature.WeightsAndBiasesV2DetectorEnabled,
	"WitDetectorEnabled":                       &feature.WitDetectorEnabled,
}

// enableCLIFeatures turns on the features main.go enables for every scan.
func enableCLIFeatures() {
	for _, flag := range detectorFeatureFlags {
		flag.Store(true)
	}
	feature.HTMLDecoderEnabled.Store(true)
}

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
		t.Fatalf("add these upstream feature flags to detectorFeatureFlags in %s: %s",
			"features_test.go", strings.Join(missing, ", "))
	}
}

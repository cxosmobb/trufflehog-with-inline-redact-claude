package redact

import (
	"maps"
	"slices"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// Collector is an engine.ResultsDispatcher that groups findings by the file
// they were found in, so they can be redacted once scanning has finished.
type Collector struct {
	mu       sync.Mutex
	byFile   map[string][]Finding
	orphaned []Finding
}

// NewCollector returns an empty Collector.
func NewCollector() *Collector {
	return &Collector{byFile: make(map[string][]Finding)}
}

// Dispatch records a result. It implements engine.ResultsDispatcher.
func (c *Collector) Dispatch(_ context.Context, r detectors.ResultWithMetadata) error {
	f := FindingFromResult(r)
	path := r.SourceMetadata.GetFilesystem().GetFile()

	c.mu.Lock()
	defer c.mu.Unlock()
	if path == "" {
		c.orphaned = append(c.orphaned, f)
	} else {
		c.byFile[path] = append(c.byFile[path], f)
	}
	return nil
}

// Files returns the paths with findings, sorted.
func (c *Collector) Files() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Sorted(maps.Keys(c.byFile))
}

// Findings returns the findings recorded for path.
func (c *Collector) Findings(path string) []Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byFile[path]
}

// Orphaned returns findings without a file path. They cannot be redacted.
func (c *Collector) Orphaned() []Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.orphaned
}

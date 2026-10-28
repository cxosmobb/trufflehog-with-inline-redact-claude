package main

// This file adds the `redact` command, which is not part of upstream
// trufflehog. It is kept apart from main.go so that merging upstream changes
// only ever touches the single runScan call in run(); see docs/redaction.md.

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/alecthomas/kingpin/v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/redact"
)

var (
	redactCmd      = cli.Command("redact", "Overwrite secrets found in files with REDACTED. Reports what would be redacted unless --in-place is given.")
	redactPaths    = redactCmd.Arg("path", "Path to file or directory to redact.").Required().Strings()
	redactInPlace  = redactCmd.Flag("in-place", "Write the redacted content back to the files.").Bool()
	redactWith     = redactCmd.Flag("replacement", "Text written over each secret. In binary files it is padded with '*' or truncated to the secret's length.").Default(redact.DefaultReplacement).String()
	redactVerify   = redactCmd.Flag("verify", "Verify secrets with their providers before redacting. By default nothing is sent over the network and every detected secret is redacted.").Bool()
	redactPasses   = redactCmd.Flag("max-passes", "Maximum number of redact-and-rescan passes. Rescanning catches secrets a detector only reports once another secret near them is gone.").Default("5").Int()
	redactRemove   = redactCmd.Flag("remove-unredactable", "Delete files with secrets that cannot be redacted in place, such as secrets inside compressed archives. Requires --in-place.").Bool()
	redactIncludes = redactCmd.Flag("include-paths", "Path to file with newline separated regexes for files to include.").Short('i').String()
	redactExcludes = redactCmd.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude.").Short('x').String()

	// Fork builds must never self-update: the updater would replace this
	// binary with an upstream release, which has no redact command. Without
	// updates, overseer (the updater's supervisor) is skipped too: on Windows
	// its child process asks WMI every two seconds whether its parent is
	// alive and exits with status 1, silently, when a query fails or takes
	// over three seconds, which happens on busy machines.
	_ = cli.PreAction(func(*kingpin.ParseContext) error {
		*noUpdate = true
		*localDev = true
		return nil
	})
)

// runScan runs the scan for cmd. It is the only hook into main.go.
func runScan(ctx context.Context, cmd string, cfg engine.Config) (metrics, error) {
	if cmd != redactCmd.FullCommand() {
		return runSingleScan(ctx, cmd, cfg)
	}
	return runRedact(ctx, cfg)
}

// runRedact scans the redact paths the way `filesystem` does and redacts every
// result in the file it came from.
func runRedact(ctx context.Context, cfg engine.Config) (metrics, error) {
	// Redaction must not leak secrets to providers, nor skip any: verification
	// is opt-in, ignore tags are not honored (the input is untrusted), and
	// wordlist false positives are redacted unless --results says otherwise.
	cfg.Verify = *redactVerify
	cfg.NoIgnoreTag = true
	if *results == "" && !*onlyVerified {
		cfg.Results = map[string]struct{}{"verified": {}, "unverified": {}, "unknown": {}, "filtered_unverified": {}}
	}
	// Without verification every secret is unverified, so leaving unverified
	// results out would silently redact nothing.
	_, unverified := cfg.Results["unverified"]
	_, filtered := cfg.Results["filtered_unverified"]
	if !cfg.Verify && !unverified && !filtered {
		return metrics{}, errors.New("redact without --verify needs unverified results: add unverified to --results, or pass --verify")
	}

	*filesystemDirectories = nil
	*filesystemScanIncludePaths = *redactIncludes
	*filesystemScanExcludePaths = *redactExcludes

	var first, last metrics
	scans := 0
	scan := func(paths []string) (*redact.Collector, error) {
		collector := redact.NewCollector()
		cfg.Dispatcher = collector
		*filesystemPaths = paths
		m, err := runSingleScan(ctx, filesystemScan.FullCommand(), cfg)
		if scans++; scans == 1 {
			first = m
		}
		last = m
		return collector, err
	}

	out := redactPrinter{json: *jsonOut}
	res, err := redact.Run(*redactPaths, scan, redact.RunOptions{
		Options:            redact.Options{Replacement: *redactWith, MaxDecodeDepth: *maxDecodeDepth},
		InPlace:            *redactInPlace,
		MaxPasses:          *redactPasses,
		RemoveUnredactable: *redactRemove,
		OnFile:             out.result,
		OnFileError:        out.fileError,
		OnRemoved:          out.removed,
	})
	if err != nil {
		return last, err
	}
	for _, f := range res.Orphaned {
		out.unredacted("", f, "result has no file path")
	}

	ctx.Logger().Info("finished redacting",
		"in_place", *redactInPlace,
		"passes", res.Passes,
		"files_redacted", len(res.Changed),
		"redactions", res.Redactions,
		"files_unredactable", len(res.Unredactable),
		"files_residual", len(res.Residual),
	)

	if !*redactInPlace {
		return first, nil
	}
	if !res.Clean() {
		return last, fmt.Errorf("secrets in %d file(s) could not be redacted", len(res.Unredactable)+len(res.Orphaned))
	}
	return last, nil
}

// redactPrinter reports redactions on stdout. It never prints secret values,
// so its output is safe to keep in CI logs.
type redactPrinter struct{ json bool }

type redactEvent struct {
	Action    string   `json:"action"`
	File      string   `json:"file"`
	Line      int      `json:"line,omitempty"`
	Detectors []string `json:"detectors,omitempty"`
	Encoding  string   `json:"encoding,omitempty"`
	Bytes     int      `json:"bytes,omitempty"`
	Error     string   `json:"error,omitempty"`
}

func (p redactPrinter) print(e redactEvent) {
	if p.json {
		b, _ := json.Marshal(e)
		fmt.Println(string(b))
		return
	}
	loc := printable(e.File)
	if e.Line > 0 {
		loc = fmt.Sprintf("%s:%d", loc, e.Line)
	}
	line := fmt.Sprintf("%-13s %s  %s", e.Action, loc, strings.Join(e.Detectors, ","))
	if e.Encoding != "" && e.Encoding != "plain" {
		line += " [" + e.Encoding + "]"
	}
	if e.Error != "" {
		line += "  (" + printable(e.Error) + ")"
	}
	fmt.Println(line)
}

// printable quotes s if it holds control characters. File names come from the
// untrusted input, and a newline or terminal escape in one could otherwise
// forge or hide lines of the report.
func printable(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return s
	}
	return strconv.Quote(s)
}

func (p redactPrinter) result(res redact.FileResult) {
	action := "would_redact"
	if res.Written {
		action = "redacted"
	}
	for _, r := range res.Report.Redactions {
		p.print(redactEvent{
			Action:    action,
			File:      res.Path,
			Line:      r.Line,
			Detectors: findingNames(res.Findings, r.Findings),
			Encoding:  r.Encoding,
			Bytes:     r.End - r.Start,
		})
	}
	for _, f := range res.Unredacted() {
		p.unredacted(res.Path, f, "secret not found in the file's bytes")
	}
	for _, f := range res.Residual() {
		p.print(redactEvent{Action: "residual", File: res.Path, Line: int(f.Line), Detectors: []string{f.Name()},
			Error: "detector still matches the redacted structure; no secret material is left"})
	}
}

func (p redactPrinter) unredacted(path string, f redact.Finding, reason string) {
	p.print(redactEvent{Action: "unredactable", File: path, Line: int(f.Line), Detectors: []string{f.Name()}, Error: reason})
}

func (p redactPrinter) fileError(path string, findings []redact.Finding, err error) {
	p.print(redactEvent{Action: "unredactable", File: path, Detectors: findingNames(findings, nil), Error: err.Error()})
}

func (p redactPrinter) removed(path string, findings []redact.Finding) {
	p.print(redactEvent{Action: "removed", File: path, Detectors: findingNames(findings, nil)})
}

// findingNames returns the sorted detector names of findings, restricted to
// idx unless it is nil.
func findingNames(findings []redact.Finding, idx []int) []string {
	set := map[string]struct{}{}
	if idx == nil {
		for _, f := range findings {
			set[f.Name()] = struct{}{}
		}
	}
	for _, i := range idx {
		set[findings[i].Name()] = struct{}{}
	}
	return slices.Sorted(maps.Keys(set))
}

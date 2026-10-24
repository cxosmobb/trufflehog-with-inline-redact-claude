package redact

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// ScanFunc scans paths and returns the findings it collected.
type ScanFunc func(paths []string) (*Collector, error)

// RunOptions configures Run.
type RunOptions struct {
	Options
	// InPlace writes redacted content back to the files. Otherwise Run only
	// reports what it would redact.
	InPlace bool
	// MaxPasses bounds the number of redact-and-rescan passes.
	MaxPasses int
	// RemoveUnredactable deletes files with secrets that cannot be redacted,
	// such as secrets inside compressed archives. Requires InPlace.
	RemoveUnredactable bool

	// OnFile is called with the outcome of each file in each pass.
	OnFile func(res FileResult)
	// OnFileError is called for files that could not be redacted at all.
	OnFileError func(path string, findings []Finding, err error)
	// OnRemoved is called for each file deleted by RemoveUnredactable.
	OnRemoved func(path string, findings []Finding)
}

// RunResult summarizes Run.
type RunResult struct {
	Passes     int
	Redactions int
	// Changed lists the files that were (or would be) changed.
	Changed []string
	// Unredactable maps files to the findings in them that could not be
	// redacted. Removed files are not included.
	Unredactable map[string][]Finding
	// Residual maps files to findings a detector still reports although no
	// secret material is left in them.
	Residual map[string][]Finding
	// Orphaned holds findings without a file path.
	Orphaned []Finding
}

// Clean reports whether every finding was redacted.
func (r RunResult) Clean() bool {
	return len(r.Unredactable) == 0 && len(r.Orphaned) == 0
}

// Run scans paths, redacts every finding in the file it was found in, and,
// with InPlace, rescans the redacted files until nothing but residual findings
// is left or MaxPasses is reached. Rescanning catches secrets a detector only
// reports once another secret near them is gone, and lets redaction widen
// where a detector still recognizes a credential whose secret is already
// replaced (see redactionLevels). After the last pass a final scan checks
// that nothing is left.
//
// Files are only read, written and removed inside paths: a finding reported
// for a file elsewhere (e.g. reached through a symlink) is unredactable.
func Run(paths []string, scan ScanFunc, opts RunOptions) (RunResult, error) {
	if opts.RemoveUnredactable && !opts.InPlace {
		return RunResult{}, errors.New("removing unredactable files requires redacting in place")
	}
	rs, err := openRoots(paths)
	if err != nil {
		return RunResult{}, err
	}
	defer rs.close()

	maxPasses := max(opts.MaxPasses, 1)
	res := RunResult{Unredactable: map[string][]Finding{}, Residual: map[string][]Finding{}}
	changed := map[string]bool{}
	for pass := 1; ; pass++ {
		collector, err := scan(paths)
		if err != nil {
			return res, err
		}
		if pass == 1 {
			res.Orphaned = collector.Orphaned()
		}
		res.Passes = pass
		// The pass after the last allowed one only verifies.
		write := opts.InPlace && pass <= maxPasses

		var written []string
		for _, path := range collector.Files() {
			findings := collector.Findings(path)
			fr, err := rs.redactFile(path, findings, opts.Options, write)
			if err != nil {
				res.Unredactable[path] = findings
				if opts.OnFileError != nil {
					opts.OnFileError(path, findings, err)
				}
				continue
			}
			if opts.OnFile != nil {
				opts.OnFile(fr)
			}
			unredacted := fr.Unredacted()
			if len(unredacted) == 0 && !write && opts.InPlace && fr.Changed {
				unredacted = findings // still not clean after the last pass
			}
			setOrDelete(res.Unredactable, path, unredacted)
			setOrDelete(res.Residual, path, fr.Residual())
			if fr.Changed {
				changed[path] = true
				res.Redactions += len(fr.Report.Redactions)
			}
			if fr.Written {
				written = append(written, path)
			}
		}
		if !opts.InPlace || len(written) == 0 {
			break
		}
		paths = written
	}

	if opts.RemoveUnredactable {
		for _, path := range slices.Sorted(maps.Keys(res.Unredactable)) {
			if err := rs.remove(path); err != nil {
				return res, fmt.Errorf("removing unredactable file: %w", err)
			}
			if opts.OnRemoved != nil {
				opts.OnRemoved(path, res.Unredactable[path])
			}
			delete(res.Unredactable, path)
		}
	}
	res.Changed = slices.Sorted(maps.Keys(changed))
	return res, nil
}

func setOrDelete(m map[string][]Finding, path string, findings []Finding) {
	if len(findings) > 0 {
		m[path] = findings
	} else {
		delete(m, path)
	}
}

func (rs roots) redactFile(path string, findings []Finding, opts Options, write bool) (FileResult, error) {
	root, name, err := rs.resolve(path)
	if err != nil {
		return FileResult{Path: path, Findings: findings}, err
	}
	return redactIn(root, name, path, findings, opts, write)
}

func (rs roots) remove(path string) error {
	root, name, err := rs.resolve(path)
	if err != nil {
		return err
	}
	return root.Remove(name)
}

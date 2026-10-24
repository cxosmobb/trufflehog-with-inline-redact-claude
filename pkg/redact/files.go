package redact

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

// FileResult describes the redaction of one file.
type FileResult struct {
	Path     string
	Findings []Finding
	Report   Report
	// Binary is set when the file was treated as binary, in which case each
	// replacement has the length of the secret it overwrites.
	Binary bool
	// Changed is set when the redacted content differs from the original.
	Changed bool
	// Written is set when the redacted content was written back to Path.
	Written bool
}

// Unredacted returns the findings that could not be redacted.
func (r FileResult) Unredacted() []Finding { return r.pick(r.Report.Unredacted) }

// Residual returns the findings that a detector reports although no secret
// material is left in them (see Report.Residual).
func (r FileResult) Residual() []Finding { return r.pick(r.Report.Residual) }

func (r FileResult) pick(idx []int) []Finding {
	out := make([]Finding, 0, len(idx))
	for _, i := range idx {
		out = append(out, r.Findings[i])
	}
	return out
}

var (
	// ErrNotRegularFile is returned for paths that are not regular files, such
	// as symlinks, which are never read or written through.
	ErrNotRegularFile = errors.New("not a regular file")
	// ErrOutsideRoots is returned for paths outside the paths being redacted.
	ErrOutsideRoots = errors.New("outside the paths being redacted")
)

// RedactFile redacts findings in the file at path. When write is false the
// file is left untouched and the result describes what would change.
func RedactFile(path string, findings []Finding, opts Options, write bool) (FileResult, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return FileResult{Path: path, Findings: findings}, err
	}
	defer root.Close()
	return redactIn(root, filepath.Base(path), path, findings, opts, write)
}

// redactIn redacts the file name inside root. Going through os.Root means a
// symlink, or a path component swapped for one, cannot lead outside root.
func redactIn(root *os.Root, name, path string, findings []Finding, opts Options, write bool) (FileResult, error) {
	res := FileResult{Path: path, Findings: findings}
	info, err := root.Lstat(name)
	if err != nil {
		return res, err
	}
	if !info.Mode().IsRegular() {
		return res, fmt.Errorf("%s: %w", path, ErrNotRegularFile)
	}
	data, links, err := readSame(root, name, info)
	if err != nil {
		return res, fmt.Errorf("%s: %w", path, err)
	}

	res.Binary = IsBinary(data)
	opts.PreserveLength = opts.PreserveLength || res.Binary
	out, report := Redact(data, findings, opts)
	res.Report = report
	res.Changed = !bytes.Equal(out, data)
	if !write || !res.Changed {
		return res, nil
	}
	if err := writeFile(root, name, info, out, links); err != nil {
		return res, fmt.Errorf("%s: %w", path, err)
	}
	res.Written = true
	return res, nil
}

// errChanged is returned when a file is no longer the one that was checked,
// e.g. because it was replaced by a symlink in the meantime.
var errChanged = errors.New("file changed while being redacted")

// openSame opens name, failing if it is no longer the file described by info.
func openSame(root *os.Root, name string, flag int, info os.FileInfo) (*os.File, error) {
	f, err := root.OpenFile(name, flag, 0)
	if err != nil {
		return nil, err
	}
	if opened, err := f.Stat(); err != nil || !os.SameFile(info, opened) {
		_ = f.Close()
		return nil, errChanged
	}
	return f, nil
}

// readSame reads the file described by info and counts its hard links.
func readSame(root *os.Root, name string, info os.FileInfo) ([]byte, uint64, error) {
	f, err := openSame(root, name, os.O_RDONLY, info)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	links, err := linkCount(f)
	if err != nil {
		return nil, 0, err
	}
	data, err := io.ReadAll(f)
	return data, links, err
}

// IsBinary reports whether data should be treated as binary: it contains NUL
// bytes or is not valid UTF-8. Changing the length of binary content (or of
// UTF-16 text and uncompressed archives) would corrupt it.
func IsBinary(data []byte) bool {
	return bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data)
}

// writeFile replaces name with data. It writes a copy and renames it over
// the original, so a crash never leaves a half-written file and data never
// goes to other hard links of the file. Neither needs any privilege, also on
// Windows, where a read-only file is made writable for the rename and a file
// briefly held open (by a virus scanner, say) is retried.
//
// Where the copy cannot be created or renamed for lack of permission, as in a
// directory the user may change files in but not add files to, a file with no
// other links is overwritten in place instead.
func writeFile(root *os.Root, name string, info os.FileInfo, data []byte, links uint64) error {
	perm := info.Mode().Perm()
	err := replace(root, name, data, perm)
	if err == nil || links != 1 || !permissionDenied(err) {
		return err
	}
	if oerr := withWritable(root, name, perm, func() error { return overwrite(root, name, info, data) }); oerr != nil {
		return errors.Join(err, oerr)
	}
	return nil
}

func replace(root *os.Root, name string, data []byte, perm os.FileMode) error {
	dir, base := filepath.Split(name)
	tmp := filepath.Join(dir, "."+base+".redact-"+rand.Text()[:12])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmp) }()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Chmod(tmp, perm)
	}
	if err != nil {
		return err
	}
	rename := func() error { return retryTransient(func() error { return root.Rename(tmp, name) }) }
	if runtime.GOOS == "windows" {
		// Windows refuses to replace a read-only file.
		return withWritable(root, name, perm, rename)
	}
	return rename()
}

// overwrite writes data over the content of the file described by info.
func overwrite(root *os.Root, name string, info os.FileInfo, data []byte) error {
	f, err := openSame(root, name, os.O_WRONLY, info)
	if err != nil {
		return err
	}
	err = f.Truncate(0)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// withWritable runs fn with name made writable by its owner, then gives name
// the permissions perm.
func withWritable(root *os.Root, name string, perm os.FileMode, fn func() error) error {
	if perm&0o200 != 0 {
		return fn()
	}
	if err := root.Chmod(name, perm|0o200); err != nil {
		return err
	}
	err := fn()
	if cerr := root.Chmod(name, perm); err == nil {
		err = cerr
	}
	return err
}

// retryTransient retries fn for about half a second while it fails with an
// error that may go away (see transientError).
func retryTransient(fn func() error) error {
	var err error
	for attempt := 1; attempt <= 5; attempt++ {
		if err = fn(); err == nil || !transientError(err) {
			return err
		}
		time.Sleep(time.Duration(attempt) * 50 * time.Millisecond)
	}
	return err
}

// rootDir is one of the paths Run was asked to redact.
type rootDir struct {
	dir  string // absolute directory of the path
	file string // set when the path is a single file
	root *os.Root
}

// roots confines Run to the paths it was asked to redact.
type roots []rootDir

func openRoots(paths []string) (roots, error) {
	var rs roots
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			rs.close()
			return nil, err
		}
		dir, file := abs, ""
		if info, err := os.Stat(abs); err == nil && !info.IsDir() {
			dir, file = filepath.Dir(abs), filepath.Base(abs)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			rs.close()
			return nil, err
		}
		rs = append(rs, rootDir{dir, file, root})
	}
	return rs, nil
}

func (rs roots) close() {
	for _, r := range rs {
		_ = r.root.Close()
	}
}

// resolve returns the root that contains path and path's name inside it.
func (rs roots) resolve(path string) (*os.Root, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	for _, r := range rs {
		rel, err := filepath.Rel(r.dir, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || (r.file != "" && rel != r.file) {
			continue
		}
		return r.root, rel, nil
	}
	return nil, "", fmt.Errorf("%s: %w", path, ErrOutsideRoots)
}

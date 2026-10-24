package redact

import (
	"os"
	"path/filepath"
	"testing"
)

const fileSecret = "xoxb-2222222222-3333333333-ExampleExample01"

// redactOne writes "SLACK=<secret>" to a file in dir, applies setup, redacts
// the file in place and returns its content afterwards.
func redactOne(t *testing.T, dir string, perm os.FileMode, setup func(path string)) string {
	t.Helper()
	path := filepath.Join(dir, "config.env")
	if err := os.WriteFile(path, []byte("SLACK="+fileSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	if setup != nil {
		setup(path)
	}
	res, err := RedactFile(path, []Finding{{Raw: []byte(fileSecret)}}, Options{}, true)
	if err != nil || !res.Written {
		t.Fatalf("RedactFile: %+v, %v", res, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRedactFileReadOnly(t *testing.T) {
	dir := t.TempDir()
	if got := redactOne(t, dir, 0o444, nil); got != "SLACK=REDACTED" {
		t.Fatalf("content = %q", got)
	}
	info, err := os.Stat(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o200 != 0 {
		t.Errorf("file is no longer read-only: %v", info.Mode())
	}
}

func TestRedactFileInDirectoryWithoutCreatePermission(t *testing.T) {
	dir := t.TempDir()
	if got := redactOne(t, dir, 0o644, func(string) { denyCreate(t, dir) }); got != "SLACK=REDACTED" {
		t.Fatalf("content = %q", got)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".*.redact-*"))
	if len(leftovers) > 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestRedactFileHeldOpenByAnotherProcess(t *testing.T) {
	got := redactOne(t, t.TempDir(), 0o644, func(path string) { holdOpen(t, path) })
	if got != "SLACK=REDACTED" {
		t.Fatalf("content = %q", got)
	}
}

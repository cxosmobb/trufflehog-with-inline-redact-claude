//go:build unix

package redact

import (
	"os"
	"testing"
)

func denyCreate(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root may create files anywhere")
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

// holdOpen is a no-op: an open file never blocks renaming over it on Unix.
func holdOpen(t *testing.T, path string) {}

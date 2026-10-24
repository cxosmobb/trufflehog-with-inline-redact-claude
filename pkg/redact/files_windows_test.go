package redact

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// denyCreate denies the current user adding files to dir, which needs no
// privilege: the owner of dir may change its ACL.
func denyCreate(t *testing.T, dir string) {
	t.Helper()
	user := os.Getenv("USERDOMAIN") + `\` + os.Getenv("USERNAME")
	if out, err := exec.Command("icacls", dir, "/deny", user+":(WD)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("icacls", dir, "/remove:d", user).Run() })
	if err := os.WriteFile(dir+`\probe`, nil, 0o644); err == nil {
		t.Fatal("creating files in dir is still allowed")
	}
}

// holdOpen keeps path open the way virus scanners and editors do: sharing
// reads and writes but not deletion, so it cannot be renamed over.
func holdOpen(t *testing.T, path string) {
	t.Helper()
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.CloseHandle(h) })
}

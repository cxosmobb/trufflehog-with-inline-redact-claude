//go:build unix

package redact

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func linkCount(f *os.File) (uint64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink), nil
	}
	return 1, nil
}

func transientError(error) bool { return false }

// permissionDenied reports errors after which overwriting the file in place
// may still work.
func permissionDenied(err error) bool { return errors.Is(err, fs.ErrPermission) }

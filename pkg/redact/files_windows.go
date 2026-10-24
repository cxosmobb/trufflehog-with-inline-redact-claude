package redact

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

const (
	errorSharingViolation syscall.Errno = 32
	errorLockViolation    syscall.Errno = 33
)

func linkCount(f *os.File) (uint64, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info); err != nil {
		return 0, err
	}
	return uint64(info.NumberOfLinks), nil
}

// transientError reports errors Windows returns while another process, such
// as a virus scanner or search indexer, briefly holds a file open.
func transientError(err error) bool {
	return errors.Is(err, errorSharingViolation) || errors.Is(err, errorLockViolation) || errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}

// permissionDenied reports errors after which overwriting the file in place
// may still work.
func permissionDenied(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, errorSharingViolation) || errors.Is(err, errorLockViolation)
}

package transfer

import (
	"errors"
	"os"
	"syscall"
)

// freeSpace reports bytes available to unprivileged users in dir.
func freeSpace(dir string) (uint64, bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true, nil
}

// preallocate reserves blocks without changing the file size (FALLOC_FL_KEEP_SIZE),
// so a short download never looks like a complete file. Filesystems without
// support are tolerated; running out of space is not.
func preallocate(f *os.File, size int64) error {
	if size <= 0 {
		return nil
	}
	err := syscall.Fallocate(int(f.Fd()), 1, 0, size)
	if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
		return nil
	}
	return err
}

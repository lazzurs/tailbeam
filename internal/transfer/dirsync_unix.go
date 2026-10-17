//go:build !windows

package transfer

import (
	"errors"
	"os"
	"syscall"
)

// syncDir makes the new directory entry durable. Filesystems that cannot sync
// directories are tolerated.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

package transfer

import (
	"fmt"
	"os"
	"syscall"
)

// fileIdentity names a file's inode and its last status change.
func fileIdentity(st os.FileInfo) (string, bool) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("dev=%d ino=%d ctime=%d.%09d", s.Dev, s.Ino, s.Ctim.Sec, s.Ctim.Nsec), true
}

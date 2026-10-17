//go:build !linux

package transfer

import "os"

// Best-effort checks are Linux-only; elsewhere the download simply fails with ENOSPC.
func freeSpace(string) (uint64, bool, error) { return 0, false, nil }

func preallocate(*os.File, int64) error { return nil }

//go:build !linux && !darwin

package transfer

import "os"

// fileIdentity is unavailable here (no status-change time), so the manifest
// cache is not used.
func fileIdentity(os.FileInfo) (string, bool) { return "", false }

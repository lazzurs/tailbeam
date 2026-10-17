//go:build !linux

package transfer

import "os"

// dataRegions cannot find holes here: every chunk of a partial file is
// re-checked on resume.
func dataRegions(*os.File, int64) ([][2]int64, bool) { return nil, false }

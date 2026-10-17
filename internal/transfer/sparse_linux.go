package transfer

import (
	"errors"
	"os"
	"syscall"
)

const (
	seekData = 3 // SEEK_DATA on Linux
	seekHole = 4 // SEEK_HOLE on Linux
)

// dataRegions lists the [start, end) byte ranges of f that may hold data, so a
// resume only re-reads what an earlier run wrote. ok is false when the
// filesystem cannot tell, and the caller must treat the whole file as data.
func dataRegions(f *os.File, size int64) (regions [][2]int64, ok bool) {
	for off := int64(0); off < size; {
		start, err := f.Seek(off, seekData)
		if errors.Is(err, syscall.ENXIO) {
			break // no data after off
		}
		if err != nil {
			return nil, false
		}
		end, err := f.Seek(start, seekHole)
		if err != nil {
			return nil, false
		}
		regions = append(regions, [2]int64{start, min(end, size)})
		off = end
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, false
	}
	return regions, true
}

package transfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The sender's manifest cache saves re-hashing a large file when the same
// file is offered again, typically after a sender restart so that a receiver
// can resume: hashing 100 GB takes about 20 minutes on a Celeron N3160.
//
// An entry is keyed by the file's device, inode, size, modification and
// status-change times, and the chunk size. Any write to the file changes its
// ctime, which ordinary tools cannot set back. A stale entry could only make
// the receiver reject chunks ("source changed"); it cannot make it accept
// wrong data, because the receiver checks every chunk against the manifest.
const (
	manifestCacheMaxAge = 30 * 24 * time.Hour
	manifestCacheMagic  = "tailbeam manifest cache v1\n"
)

// manifestCacheMin is the smallest file worth caching: smaller files hash in
// about a second. A variable so tests can lower it.
var manifestCacheMin int64 = 256 << 20

// DefaultManifestCacheDir returns the per-user cache directory, or "" if the
// platform has none.
func DefaultManifestCacheDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "tailbeam", "manifests")
}

// manifestCacheEntry returns the entry path and the key it must contain, or
// ok false when the file cannot be keyed (no inode or ctime on this platform).
func manifestCacheEntry(dir string, st os.FileInfo, chunk int64) (path string, key []byte, ok bool) {
	id, ok := fileIdentity(st)
	if dir == "" || !ok || st.Size() < manifestCacheMin {
		return "", nil, false
	}
	key = fmt.Appendf(nil, "%s size=%d mtime=%d chunk=%d\n", id, st.Size(), st.ModTime().UnixNano(), chunk)
	h := sha256.Sum256(key)
	return filepath.Join(dir, hex.EncodeToString(h[:16])), key, true
}

// loadManifest returns a cached manifest of the expected length, or nil.
func loadManifest(path string, key []byte, want int64) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	head := append([]byte(manifestCacheMagic), key...)
	if !bytes.HasPrefix(b, head) || int64(len(b)-len(head)) != want {
		return nil
	}
	now := time.Now()
	os.Chtimes(path, now, now) // keep recently used entries from being pruned
	return b[len(head):]
}

// storeManifest writes an entry atomically and prunes old ones. Errors are
// ignored: the cache is only an optimization.
func storeManifest(dir, path string, key, manifest []byte) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if info, err := e.Info(); err == nil && info.Mode().IsRegular() && time.Since(info.ModTime()) > manifestCacheMaxAge {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	_, err = f.Write(append(append([]byte(manifestCacheMagic), key...), manifest...))
	if cerr := f.Close(); err != nil || cerr != nil {
		return
	}
	os.Rename(f.Name(), path)
}

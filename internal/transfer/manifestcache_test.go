package transfer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestCache(t *testing.T) {
	old := manifestCacheMin
	manifestCacheMin = 0
	defer func() { manifestCacheMin = old }()
	data := randomData(6*testChunk+1, 31)
	src := writeSource(t, data)
	cache := filepath.Join(t.TempDir(), "cache")
	first, err := newSenderV2(context.Background(), src, allow, testChunk, cache)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	st, _ := os.Stat(src)
	path, key, ok := manifestCacheEntry(cache, st, testChunk)
	if !ok {
		t.Skip("no file identity on this platform")
	}
	if fst, err := os.Stat(path); err != nil || fst.Mode().Perm()&0077 != 0 {
		t.Fatalf("cache entry missing or not private: %v", err)
	}

	// Replace the cached manifest with a different one of the same length:
	// a second sender must use it, which proves the cache is read...
	b, _ := os.ReadFile(path)
	b[len(b)-1] ^= 1
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	second := senderCached(t, src, cache)
	if second.Offer.Root == first.Offer.Root {
		t.Fatal("cache not used")
	}
	// ...and a receiver given that stale manifest refuses the file rather
	// than publishing data that does not match it.
	dir := t.TempDir()
	if _, err := download(t, context.Background(), second, dir); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected chunk verification failure, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
		t.Fatal("published data that does not match the manifest")
	}

	// Any write to the file changes its key, so the entry is not reused.
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	third := senderCached(t, src, cache)
	if third.Offer.Root != first.Offer.Root {
		t.Fatal("stale cache entry used after the file was rewritten")
	}
	if got := loadManifest(path, key, 1); got != nil {
		t.Fatal("entry of the wrong length accepted")
	}
}

func senderCached(t *testing.T, path, cache string) *SenderV2 {
	t.Helper()
	s, err := newSenderV2(context.Background(), path, allow, testChunk, cache)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

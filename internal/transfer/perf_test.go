package transfer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/linuskendall/tailbeam/internal/e2e"
)

// CPU cost per 8 MiB chunk of the receiver's per-chunk work. Run on the
// slowest expected host: go test -run x -bench . ./internal/transfer
func BenchmarkSHA256Chunk(b *testing.B) {
	buf := make([]byte, v2DefaultChunk)
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		sha256.Sum256(buf)
	}
}

func benchKeys(b *testing.B) e2e.Keys {
	fk, err := e2e.NewFileKey()
	if err != nil {
		b.Fatal(err)
	}
	k, err := e2e.DeriveKeys(fk)
	if err != nil {
		b.Fatal(err)
	}
	return k
}

func BenchmarkE2ESealChunk(b *testing.B) {
	k, buf, id := benchKeys(b), make([]byte, v2DefaultChunk), make([]byte, 32)
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		if _, err := k.SealChunk(id, id, 1, false, buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAES256GCMChunk is a reference point for the AEAD choice: it is not
// used by the protocol.
func BenchmarkAES256GCMChunk(b *testing.B) {
	block, _ := aes.NewCipher(make([]byte, 32))
	a, _ := cipher.NewGCM(block)
	buf, nonce := make([]byte, v2DefaultChunk), make([]byte, a.NonceSize())
	out := make([]byte, 0, len(buf)+a.Overhead())
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		a.Seal(out[:0], nonce, buf, nil)
	}
}

func BenchmarkE2EOpenChunk(b *testing.B) {
	k, buf, id := benchKeys(b), make([]byte, v2DefaultChunk), make([]byte, 32)
	sealed, err := k.SealChunk(id, id, 1, false, buf)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		if _, err := k.OpenChunk(buf, id, id, 1, len(buf), false, sealed); err != nil {
			b.Fatal(err)
		}
	}
}

// TestLoopbackThroughput times whole downloads of TAILBEAM_BENCH_FILE over
// loopback HTTP with the default chunk size, into TAILBEAM_BENCH_DIR (default
// a temporary directory), with TAILBEAM_BENCH_STREAMS parallel streams
// (default DefaultStreams). It is skipped unless the file is given.
func TestLoopbackThroughput(t *testing.T) {
	path := os.Getenv("TAILBEAM_BENCH_FILE")
	if path == "" {
		t.Skip("TAILBEAM_BENCH_FILE not set")
	}
	streams, _ := strconv.Atoi(os.Getenv("TAILBEAM_BENCH_STREAMS"))
	dir := os.Getenv("TAILBEAM_BENCH_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mb := float64(st.Size()) / 1e6
	report := func(what string, d time.Duration) {
		t.Logf("%-28s %6.2fs %6.0f MB/s", what, d.Seconds(), mb/d.Seconds())
	}
	ctx := context.Background()

	start := time.Now()
	v2, err := newSenderV2(ctx, path, allow, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	report("sender manifest (hash)", time.Since(start))
	ts := httptest.NewServer(v2)
	start = time.Now()
	r, err := FetchAnyOffer(ctx, ts.Client(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	r.Streams = streams
	out, err := r.Download(ctx, ts.Client(), ts.URL, testSender, dir, 1<<50, 0)
	if err != nil {
		t.Fatal(err)
	}
	report("plaintext v2 download", time.Since(start))
	ts.Close()
	os.Remove(out)

	code, err := e2e.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSenderE2E(ctx, path, allow, code, testSender, testReceiver, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ts = httptest.NewServer(s)
	defer ts.Close()
	start = time.Now()
	o, err := FetchE2EOffer(ctx, ts.Client(), ts.URL, code, testSender, testReceiver)
	if err != nil {
		t.Fatal(err)
	}
	o.Streams = streams
	out, err = o.Download(ctx, ts.Client(), ts.URL, testSender, dir, 1<<50, 0)
	if err != nil {
		t.Fatal(err)
	}
	report("e2e download", time.Since(start))
	os.Remove(out)
}

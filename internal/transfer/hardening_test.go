package transfer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// intercepted serves h, letting intercept answer a request first; intercept
// returns true when it has written the response.
func intercepted(t *testing.T, h http.Handler, intercept func(w http.ResponseWriter, r *http.Request) bool) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if intercept != nil && intercept(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func plainDownload(ctx context.Context, ts *httptest.Server, dir string, max int64, idle time.Duration) (string, error) {
	r, err := FetchPlainOffer(ctx, ts.Client(), ts.URL)
	if err != nil {
		return "", err
	}
	return r.Download(ctx, ts.Client(), ts.URL, testSender, dir, max, idle)
}

// rangeHeaders writes the 206 headers for the request's range of s's file and
// returns that range.
func rangeHeaders(w http.ResponseWriter, r *http.Request, s *SenderV2) (start, end int64) {
	start, end, _, _ = v2ParseRange(r.Header.Get("Range"), s.Offer.Size)
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end-1, s.Offer.Size))
	w.Header().Set("Content-Length", fmt.Sprint(end-start))
	w.WriteHeader(http.StatusPartialContent)
	return start, end
}

func isFile(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/v2/file/") }
func isAck(r *http.Request) bool  { return strings.HasPrefix(r.URL.Path, "/v2/ack/") }

func TestV2FailedDownloadsNotPublishedOrAcked(t *testing.T) {
	data := randomData(2*testChunk+5, 7)
	for _, kind := range []string{"truncated", "corrupt", "limit"} {
		t.Run(kind, func(t *testing.T) {
			s := senderV2(t, writeSource(t, data), allow)
			var h http.Handler = s
			if kind == "corrupt" {
				h = &tap{h: s, flip: func(int) int64 { return 0 }}
			}
			var acked atomic.Bool
			ts := intercepted(t, h, func(w http.ResponseWriter, r *http.Request) bool {
				switch {
				case isAck(r):
					acked.Store(true)
					w.WriteHeader(http.StatusNoContent)
					return true
				case kind == "truncated" && isFile(r):
					start, end := rangeHeaders(w, r, s)
					w.Write(data[start : start+(end-start)/2])
					return true
				}
				return false
			})
			max := int64(1 << 30)
			if kind == "limit" {
				max = 1
			}
			dir := t.TempDir()
			if _, err := plainDownload(context.Background(), ts, dir, max, 0); err == nil {
				t.Fatal("accepted failed download")
			}
			if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil || acked.Load() {
				t.Fatal("published or acknowledged a failed download")
			}
		})
	}
}

func TestV2NoOverwriteOrSymlinkFollow(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(fmt.Sprint(symlink), func(t *testing.T) {
			s := senderV2(t, writeSource(t, []byte("new")), allow)
			ts := httptest.NewServer(s)
			defer ts.Close()
			dir := t.TempDir()
			dest := filepath.Join(dir, s.Offer.Name)
			target := dest
			if symlink {
				target = filepath.Join(t.TempDir(), "valuable")
				if err := os.Symlink(target, dest); err != nil {
					t.Skip(err)
				}
			}
			if err := os.WriteFile(target, []byte("keep me"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := plainDownload(context.Background(), ts, dir, 1024, 0); err == nil {
				t.Fatal("overwrote destination")
			}
			if got, _ := os.ReadFile(target); string(got) != "keep me" {
				t.Fatal("existing data was modified")
			}
		})
	}
}

func TestV2AckFailurePreservesVerifiedFile(t *testing.T) {
	data := []byte("verified")
	s := senderV2(t, writeSource(t, data), allow)
	ts := intercepted(t, s, func(w http.ResponseWriter, r *http.Request) bool {
		if isAck(r) {
			http.Error(w, "failure", 500)
			return true
		}
		return false
	})
	dest, err := plainDownload(context.Background(), ts, t.TempDir(), 1024, 0)
	if dest == "" || err == nil || !strings.Contains(err.Error(), "acknowledgement failed") {
		t.Fatalf("%q: %v", dest, err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, data) {
		t.Fatal("lost verified download")
	}
}

func TestV2DestinationCreatedDuringTransfer(t *testing.T) {
	s := senderV2(t, writeSource(t, []byte("new")), allow)
	dir := t.TempDir()
	dest := filepath.Join(dir, s.Offer.Name)
	var once sync.Once
	ts := intercepted(t, s, func(w http.ResponseWriter, r *http.Request) bool {
		if isFile(r) {
			once.Do(func() {
				if err := os.WriteFile(dest, []byte("winner"), 0600); err != nil {
					t.Error(err)
				}
			})
		}
		return false
	})
	if _, err := plainDownload(context.Background(), ts, dir, 1024, 0); err == nil {
		t.Fatal("overwrote concurrent file")
	}
	if got, _ := os.ReadFile(dest); string(got) != "winner" {
		t.Fatal("concurrent file modified")
	}
}

func TestV2SourceMutationDetected(t *testing.T) {
	path := writeSource(t, []byte("before"))
	s := senderV2(t, path, allow)
	if err := os.WriteFile(path, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	dir := t.TempDir()
	if _, err := plainDownload(context.Background(), ts, dir, 1024, 0); err == nil {
		t.Fatal("accepted mutated source")
	}
	if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
		t.Fatal("published a mutated source")
	}
}

func TestV2OfferLimits(t *testing.T) {
	for _, body := range []string{strings.Repeat("x", maxMetadata+1), `{"version":1}`, `{"version":2,"size":-1}`} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		_, err := FetchPlainOffer(context.Background(), ts.Client(), ts.URL)
		ts.Close()
		if err == nil {
			t.Fatalf("accepted invalid offer %.40q", body)
		}
	}
}

func TestV2ServeLifecycle(t *testing.T) {
	for _, acknowledge := range []bool{true, false} {
		t.Run(fmt.Sprint(acknowledge), func(t *testing.T) {
			s := senderV2(t, writeSource(t, []byte("hello")), allow)
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- ServeV2(ctx, l, s) }()
			if acknowledge {
				c := &http.Client{Timeout: 3 * time.Second}
				defer c.CloseIdleConnections()
				base := "http://" + l.Addr().String()
				r, err := FetchPlainOffer(ctx, c, base)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := r.Download(ctx, c, base, testSender, t.TempDir(), 1024, 0); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if acknowledge && err != nil {
					t.Fatal(err)
				}
				if !acknowledge && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation returned %v", err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("sender failed to stop")
			}
		})
	}
}

func TestV2CompletedOfferGoneEverywhere(t *testing.T) {
	s := senderV2(t, writeSource(t, []byte("data")), allow)
	ts := httptest.NewServer(s)
	defer ts.Close()
	do := func(method, path string) int {
		r, _ := http.NewRequest(method, ts.URL+path, nil)
		r.Header.Set(browserGuardHeader, browserGuardValue)
		resp, err := ts.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if do("POST", "/v2/ack/"+s.Offer.ID) != http.StatusNoContent {
		t.Fatal("ack failed")
	}
	for _, c := range [][2]string{{"GET", "/v2/offer"}, {"GET", "/v2/manifest/" + s.Offer.ID}, {"GET", "/v2/file/" + s.Offer.ID}, {"POST", "/v2/ack/" + s.Offer.ID}} {
		if code := do(c[0], c[1]); code != http.StatusGone {
			t.Errorf("%v: %d", c, code)
		}
	}
}

// A black-holed client must neither block retries nor hold its handler forever.
func TestV2StalledClientDoesNotBlockRetry(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 64<<20)
	s := senderV2(t, writeSource(t, data), allow)
	s.writeIdle = 300 * time.Millisecond
	ts := httptest.NewServer(s)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "GET /v2/file/" + s.Offer.ID + " HTTP/1.1\r\nHost: x\r\n" + browserGuardHeader + ": " + browserGuardValue + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // handler is now blocked writing

	// A concurrent download succeeds while the stalled one is stuck.
	if _, err := plainDownload(context.Background(), ts, t.TempDir(), 1<<30, 0); err != nil {
		t.Fatalf("download during stall: %v", err)
	}

	// The stalled stream is cut off by the write deadline: it ends short.
	time.Sleep(time.Second)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := io.Copy(io.Discard, conn)
	if n >= int64(len(data)) {
		t.Fatalf("stalled stream was not terminated (%d bytes)", n)
	}
}

func TestV2IdleTimeoutAbortsDownload(t *testing.T) {
	data := []byte("0123456789")
	s := senderV2(t, writeSource(t, data), allow)
	release := make(chan struct{})
	defer close(release)
	ts := intercepted(t, s, func(w http.ResponseWriter, r *http.Request) bool {
		if !isFile(r) {
			return false
		}
		rangeHeaders(w, r, s)
		w.Write(data[:5])
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return true
	})
	dir := t.TempDir()
	start := time.Now()
	if _, err := plainDownload(context.Background(), ts, dir, 1024, 200*time.Millisecond); err == nil {
		t.Fatal("stalled download succeeded")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("watchdog too slow")
	}
	if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
		t.Fatal("published a stalled download")
	}
}

func TestV2IdleTimeoutDoesNotCapSlowProgress(t *testing.T) {
	data := []byte("0123456789")
	s := senderV2(t, writeSource(t, data), allow)
	ts := intercepted(t, s, func(w http.ResponseWriter, r *http.Request) bool {
		if !isFile(r) {
			return false
		}
		start, end := rangeHeaders(w, r, s)
		for i := start; i < end; i++ {
			w.Write(data[i : i+1])
			w.(http.Flusher).Flush()
			time.Sleep(60 * time.Millisecond) // total 600ms > idle 250ms
		}
		return true
	})
	if _, err := plainDownload(context.Background(), ts, t.TempDir(), 1024, 250*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestV2StartedClosesOnDataRequestOnly(t *testing.T) {
	s := senderV2(t, writeSource(t, []byte("x")), allow)
	ts := httptest.NewServer(s)
	defer ts.Close()
	if _, err := FetchPlainOffer(context.Background(), ts.Client(), ts.URL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Started():
		t.Fatal("offer fetch counted as transfer start")
	default:
	}
	if _, err := plainDownload(context.Background(), ts, t.TempDir(), 10, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Started():
	default:
		t.Fatal("not started")
	}
}

func TestV2InsufficientSpaceFailsFast(t *testing.T) {
	dir := t.TempDir()
	const size = 1 << 40
	if free, ok, err := freeSpace(dir); err != nil || !ok || free >= size {
		t.Skip("free-space check unsupported here, or the disk is larger than the test file")
	}
	o := OfferV2{2, strings.Repeat("ab", 32), "big", size, v2MaxChunk, v2Hash, ""}
	manifest := make([]byte, o.chunks()*v2ChunkHashSize)
	o.Root = hex.EncodeToString(v2Root(o.Size, o.ChunkSize, manifest))
	var called atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/offer":
			json.NewEncoder(w).Encode(o)
		case strings.HasPrefix(r.URL.Path, "/v2/manifest/"):
			w.Header().Set("Content-Length", fmt.Sprint(len(manifest)))
			w.Write(manifest)
		default:
			called.Store(true)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer ts.Close()
	_, err := plainDownload(context.Background(), ts, dir, 1<<62, 0)
	if err == nil || !strings.Contains(err.Error(), "free space") {
		t.Fatalf("got %v", err)
	}
	if called.Load() {
		t.Fatal("requested file data despite insufficient space")
	}
	if _, err := os.Lstat(filepath.Join(dir, "big")); err == nil {
		t.Fatal("published a file")
	}
}

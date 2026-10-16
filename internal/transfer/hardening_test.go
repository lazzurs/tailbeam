package transfer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStrictNames(t *testing.T) {
	for _, name := range []string{
		".profile", ".envrc", ".npmrc", ".hidden.txt",
		"a\u202eb.txt", "a\u2066b", "a\u200bb", "a\u00adb", "a\ufeffb", // bidi, zero-width, soft hyphen, BOM
		"a\u0085b", "a\u009fb", "a\x7fb", "a\tb", "a\u00a0b", "a\u2028b",
		"bad\xffutf8", "\xc3",
	} {
		if err := validName(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, name := range []string{"résumé.pdf", "日本語.txt", "a b.tar.gz", "emoji🙂.png", "x.profile"} {
		if err := validName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestSenderRejectsDotfile(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".envrc")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSender(context.Background(), p, allow); err == nil || !strings.Contains(err.Error(), "dot") {
		t.Fatalf("got %v", err)
	}
}

func TestCompletedOfferGoneEverywhere(t *testing.T) {
	s := sender(t, []byte("data"), allow)
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
	if do("POST", "/v1/ack/"+s.Offer.ID) != http.StatusNoContent {
		t.Fatal("ack failed")
	}
	for _, c := range [][2]string{{"GET", "/v1/offer"}, {"GET", "/v1/file/" + s.Offer.ID}, {"POST", "/v1/ack/" + s.Offer.ID}} {
		if code := do(c[0], c[1]); code != http.StatusGone {
			t.Errorf("%v: %d", c, code)
		}
	}
}

// A black-holed client must neither block retries nor hold its handler forever.
func TestStalledClientDoesNotBlockRetry(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 64<<20)
	s := sender(t, data, allow)
	s.writeTimeout = 300 * time.Millisecond
	ts := httptest.NewServer(s)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "GET /v1/file/" + s.Offer.ID + " HTTP/1.1\r\nHost: x\r\n" + browserGuardHeader + ": " + browserGuardValue + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // handler is now blocked writing

	// Concurrent retry succeeds immediately instead of 409.
	o, err := FetchOffer(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("retry during stall: %v", err)
	}
	if _, err := Download(context.Background(), ts.Client(), ts.URL, o, t.TempDir(), 1<<30); err == nil {
		t.Log("download during stall completed") // acked, offer now consumed
	} else {
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

func TestIdleTimeoutAbortsDownload(t *testing.T) {
	s := sender(t, []byte("0123456789"), allow)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.Write([]byte("01234"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer ts.Close()
	defer close(release)
	dir := t.TempDir()
	start := time.Now()
	_, err := DownloadIdle(context.Background(), ts.Client(), ts.URL, s.Offer, dir, 1024, 200*time.Millisecond)
	if !errors.Is(err, errIdle) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("watchdog too slow")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("left files behind")
	}
}

func TestIdleTimeoutDoesNotCapSlowProgress(t *testing.T) {
	data := []byte("0123456789")
	s := sender(t, data, allow)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Length", "10")
		for i := range data {
			w.Write(data[i : i+1])
			w.(http.Flusher).Flush()
			time.Sleep(60 * time.Millisecond) // total 600ms > idle 250ms
		}
	}))
	defer ts.Close()
	if _, err := DownloadIdle(context.Background(), ts.Client(), ts.URL, s.Offer, t.TempDir(), 1024, 250*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestStartedClosesOnFileRequestOnly(t *testing.T) {
	s := sender(t, []byte("x"), allow)
	ts := httptest.NewServer(s)
	defer ts.Close()
	if _, err := FetchOffer(context.Background(), ts.Client(), ts.URL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Started():
		t.Fatal("offer fetch counted as transfer start")
	default:
	}
	if _, err := Download(context.Background(), ts.Client(), ts.URL, s.Offer, t.TempDir(), 10); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Started():
	default:
		t.Fatal("not started")
	}
}

func TestInsufficientSpaceFailsFast(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := freeSpace(dir); err != nil || !ok {
		t.Skip("free-space check unsupported on this platform")
	}
	o := Offer{Version: 1, ID: strings.Repeat("00", 32), Name: "big", Size: 1 << 62, SHA256: strings.Repeat("00", 32)}
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer ts.Close()
	_, err := Download(context.Background(), ts.Client(), ts.URL, o, dir, 1<<62)
	if err == nil || !strings.Contains(err.Error(), "free space") {
		t.Fatalf("got %v", err)
	}
	if called {
		t.Fatal("requested file despite insufficient space")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("left files behind")
	}
}

func TestPreallocateKeepsSizeAndMode(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := preallocate(f, 1<<20); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	if st.Size() != 0 || st.Mode().Perm() != 0600 {
		t.Fatalf("size %d mode %v", st.Size(), st.Mode())
	}
	if err := syncDir(filepath.Dir(f.Name())); err != nil {
		t.Fatal(err)
	}
}

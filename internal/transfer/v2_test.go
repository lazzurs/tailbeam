package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
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

const testChunk = v2MinChunk
const testSender = "nSender"

func init() { v2Backoff = time.Millisecond }

func randomData(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, 1))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func writeSource(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "example.bin")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func senderV2(t *testing.T, path string, auth Authorize) *SenderV2 {
	t.Helper()
	s, err := newSenderV2(context.Background(), path, auth, testChunk)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// tap wraps a sender, counting file bytes served and optionally corrupting or
// cutting responses.
type tap struct {
	h       http.Handler
	served  atomic.Int64
	mu      sync.Mutex
	reqs    int
	flip    func(req int) int64 // body offset to corrupt, or -1
	cutAt   int64               // stop the first file response after this many bytes
	onCut   func()
	cutDone bool
}

type tapWriter struct {
	http.ResponseWriter
	t      *tap
	n      int64
	flipAt int64
	cut    int64
}

func (w *tapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *tapWriter) Write(p []byte) (int, error) {
	p = bytes.Clone(p)
	if w.flipAt >= w.n && w.flipAt < w.n+int64(len(p)) {
		p[w.flipAt-w.n] ^= 0xff
	}
	if w.cut > 0 && w.n+int64(len(p)) > w.cut {
		k := w.cut - w.n
		w.ResponseWriter.Write(p[:k])
		w.n += k
		w.t.served.Add(k)
		if w.t.onCut != nil {
			w.t.onCut()
		}
		return int(k), errors.New("cut")
	}
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	w.t.served.Add(int64(n))
	return n, err
}

func (t *tap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v2/file/") {
		t.h.ServeHTTP(w, r)
		return
	}
	t.mu.Lock()
	req := t.reqs
	t.reqs++
	tw := &tapWriter{ResponseWriter: w, t: t, flipAt: -1}
	if t.flip != nil {
		tw.flipAt = t.flip(req)
	}
	if t.cutAt > 0 && !t.cutDone {
		tw.cut, t.cutDone = t.cutAt, true
	}
	t.mu.Unlock()
	t.h.ServeHTTP(tw, r)
}

func download(t *testing.T, ctx context.Context, h http.Handler, dir string) (string, error) {
	t.Helper()
	ts := httptest.NewServer(h)
	defer ts.Close()
	r, err := FetchAnyOffer(ctx, ts.Client(), ts.URL)
	if err != nil {
		return "", err
	}
	return r.Download(ctx, ts.Client(), ts.URL, testSender, dir, 1<<40)
}

func onlyEntry(t *testing.T, dir, name string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != name {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("unexpected directory contents: %v", names)
	}
}

func TestV2RoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, testChunk - 1, testChunk, testChunk + 1, 5*testChunk + 123} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			data := randomData(n, uint64(n))
			s := senderV2(t, writeSource(t, data), allow)
			if s.Offer.chunks() != int64((n+testChunk-1)/testChunk) {
				t.Fatal("wrong chunk count")
			}
			dir := t.TempDir()
			path, err := download(t, context.Background(), s, dir)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("mismatch: %v", err)
			}
			if st, _ := os.Stat(path); st.Mode().Perm()&0077 != 0 {
				t.Fatal("download is accessible to other local users")
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("missing acknowledgement")
			}
			onlyEntry(t, dir, "example.bin")
			if _, err := download(t, context.Background(), s, t.TempDir()); err == nil {
				t.Fatal("completed offer still available")
			}
		})
	}
}

func TestV2ParallelManifestMatchesSequential(t *testing.T) {
	data := randomData(7*testChunk+5, 7)
	s := senderV2(t, writeSource(t, data), allow)
	var want []byte
	for off := 0; off < len(data); off += testChunk {
		h := sha256.Sum256(data[off:min(off+testChunk, len(data))])
		want = append(want, h[:]...)
	}
	if !bytes.Equal(s.manifest, want) || s.Offer.Root != hex.EncodeToString(v2Root(int64(len(data)), testChunk, want)) {
		t.Fatal("manifest or root differs from sequential hashing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newSenderV2(ctx, writeSource(t, data), allow, testChunk); err == nil {
		t.Fatal("hashing ignored cancellation")
	}
}

func TestV2ChunkSizeSelection(t *testing.T) {
	for _, c := range []struct{ size, want int64 }{
		{0, v2DefaultChunk}, {1 << 30, v2DefaultChunk}, {8 << 40, v2DefaultChunk},
		{8<<40 + 1, 16 << 20}, {1 << 50, v2MaxChunk},
	} {
		if got := v2ChunkSizeFor(c.size); got != c.want {
			t.Errorf("size %d: chunk %d, want %d", c.size, got, c.want)
		}
	}
}

func TestV2DroppedConnectionResumesWithinRun(t *testing.T) {
	data := randomData(40*testChunk, 1)
	s := senderV2(t, writeSource(t, data), allow)
	tp := &tap{h: s, cutAt: int64(len(data)) / 2}
	dir := t.TempDir()
	path, err := download(t, context.Background(), tp, dir)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, data) {
		t.Fatal("mismatch")
	}
	if tp.served.Load() > int64(len(data))+2*testChunk {
		t.Fatalf("re-sent verified chunks: served %d of %d", tp.served.Load(), len(data))
	}
}

// interrupted runs a download that is cancelled half way, as if the receiver
// were killed, and leaves the partial state in dir.
func interrupted(t *testing.T, path, dir string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := senderV2(t, path, allow)
	st, _ := os.Stat(path)
	tp := &tap{h: s, cutAt: st.Size() / 2, onCut: cancel}
	if _, err := download(t, ctx, tp, dir); err == nil {
		t.Fatal("interrupted download succeeded")
	}
	part, state := V2PartialPaths(dir, testSender, "example.bin")
	for _, p := range []string{part, state} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("partial state missing: %v", err)
		}
		if st.Mode().Perm()&0077 != 0 {
			t.Fatal("partial state is accessible to other users")
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
		t.Fatal("published an incomplete file")
	}
}

func TestV2ResumeAcrossReceiverAndSenderRestart(t *testing.T) {
	data := randomData(40*testChunk+17, 2)
	src := writeSource(t, data)
	dir := t.TempDir()
	interrupted(t, src, dir)

	// A new sender process: new offer ID, same root.
	tp := &tap{h: senderV2(t, src, allow)}
	path, err := download(t, context.Background(), tp, dir)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, data) {
		t.Fatal("mismatch after resume")
	}
	if served := tp.served.Load(); served == 0 || served > int64(len(data))*3/4 {
		t.Fatalf("resume re-fetched too much: %d of %d bytes", served, len(data))
	}
	onlyEntry(t, dir, "example.bin")
}

func TestV2SourceChangedBetweenRuns(t *testing.T) {
	for _, newSize := range []int{40 * testChunk, 3*testChunk + 1} {
		t.Run(fmt.Sprint(newSize), func(t *testing.T) {
			src := writeSource(t, randomData(40*testChunk, 3))
			dir := t.TempDir()
			interrupted(t, src, dir)
			changed := randomData(newSize, 4)
			if err := os.WriteFile(src, changed, 0600); err != nil {
				t.Fatal(err)
			}
			path, err := download(t, context.Background(), senderV2(t, src, allow), dir)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, changed) {
				t.Fatal("stale partial data was published")
			}
			onlyEntry(t, dir, "example.bin")
		})
	}
}

func TestV2CorruptChunkIsRefetched(t *testing.T) {
	data := randomData(10*testChunk, 5)
	tp := &tap{h: senderV2(t, writeSource(t, data), allow), flip: func(req int) int64 {
		if req == 0 {
			return 2*testChunk + 5
		}
		return -1
	}}
	path, err := download(t, context.Background(), tp, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, data) {
		t.Fatal("published corrupted data")
	}
}

func TestV2PersistentCorruptionFails(t *testing.T) {
	data := randomData(4*testChunk, 6)
	s := senderV2(t, writeSource(t, data), allow)
	tp := &tap{h: s, flip: func(int) int64 { return 5 }}
	dir := t.TempDir()
	if _, err := download(t, context.Background(), tp, dir); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected chunk verification failure, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
		t.Fatal("published corrupted data")
	}
	select {
	case <-s.Done():
		t.Fatal("acknowledged a failed download")
	default:
	}
}

func TestV2CorruptPartialFileCaughtByFinalCheck(t *testing.T) {
	data := randomData(20*testChunk, 8)
	src := writeSource(t, data)
	dir := t.TempDir()
	interrupted(t, src, dir)
	part, _ := V2PartialPaths(dir, testSender, "example.bin")
	f, err := os.OpenFile(part, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte("garbage"), 10) // chunk 0 is marked verified
	f.Close()
	path, err := download(t, context.Background(), senderV2(t, src, allow), dir)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, data) {
		t.Fatal("published a corrupted partial file")
	}
}

func TestV2PartialPathSymlinkNotFollowed(t *testing.T) {
	data := randomData(3*testChunk, 9)
	dir := t.TempDir()
	valuable := filepath.Join(t.TempDir(), "valuable")
	if err := os.WriteFile(valuable, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	part, state := V2PartialPaths(dir, testSender, "example.bin")
	if err := os.Symlink(valuable, part); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(valuable, state); err != nil {
		t.Skip(err)
	}
	path, err := download(t, context.Background(), senderV2(t, writeSource(t, data), allow), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(valuable); string(got) != "keep me" {
		t.Fatal("followed a symlink at the partial path")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatal("mismatch")
	}
}

func TestV2HostileOffers(t *testing.T) {
	good := OfferV2{2, strings.Repeat("a", 64), "x.bin", 10, testChunk, v2Hash, strings.Repeat("b", 64)}
	if err := validateOfferV2(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*OfferV2){
		"version":      func(o *OfferV2) { o.Version = 3 },
		"hash":         func(o *OfferV2) { o.Hash = "md5" },
		"negative":     func(o *OfferV2) { o.Size = -1 },
		"zero chunk":   func(o *OfferV2) { o.ChunkSize = 0 },
		"odd chunk":    func(o *OfferV2) { o.ChunkSize = testChunk + 1 },
		"small chunk":  func(o *OfferV2) { o.ChunkSize = 4096 },
		"huge chunk":   func(o *OfferV2) { o.ChunkSize = 1 << 30 },
		"many chunks":  func(o *OfferV2) { o.Size = (v2MaxChunks + 1) * testChunk },
		"root":         func(o *OfferV2) { o.Root = "zz" },
		"id":           func(o *OfferV2) { o.ID = "" },
		"name":         func(o *OfferV2) { o.Name = "../x" },
		"max overflow": func(o *OfferV2) { o.Size = 1<<63 - 1; o.ChunkSize = v2MaxChunk },
	} {
		o := good
		mut(&o)
		if validateOfferV2(o) == nil {
			t.Errorf("%s: accepted hostile offer", name)
		}
	}
}

// fakeV2 serves a valid offer for data but lets tests tamper with responses.
func fakeV2(t *testing.T, data []byte, manifest func([]byte) []byte, fileRange func(w http.ResponseWriter, r *http.Request) bool) *httptest.Server {
	s := senderV2(t, writeSource(t, data), allow)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case manifest != nil && strings.HasPrefix(r.URL.Path, "/v2/manifest/"):
			m := manifest(bytes.Clone(s.manifest))
			w.Header().Set("Content-Length", fmt.Sprint(len(m)))
			w.Write(m)
		case fileRange != nil && strings.HasPrefix(r.URL.Path, "/v2/file/") && fileRange(w, r):
		default:
			s.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestV2HostileManifestsAndRanges(t *testing.T) {
	data := randomData(4*testChunk, 10)
	for name, ts := range map[string]*httptest.Server{
		"short manifest": fakeV2(t, data, func(m []byte) []byte { return m[:len(m)-1] }, nil),
		"long manifest":  fakeV2(t, data, func(m []byte) []byte { return append(m, make([]byte, 32)...) }, nil),
		"tampered manifest": fakeV2(t, data, func(m []byte) []byte {
			m[40] ^= 1
			return m
		}, nil),
		"wrong range": fakeV2(t, data, nil, func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-9/%d", len(data)))
			w.Header().Set("Content-Length", "10")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(data[:10])
			return true
		}),
		"ignores range": fakeV2(t, data, nil, func(w http.ResponseWriter, r *http.Request) bool {
			w.Write(data)
			return true
		}),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			r, err := FetchAnyOffer(context.Background(), ts.Client(), ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Download(context.Background(), ts.Client(), ts.URL, testSender, dir, 1<<40); err == nil {
				t.Fatal("accepted hostile response")
			}
			if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
				t.Fatal("published a file")
			}
		})
	}
}

func TestV2ParseRange(t *testing.T) {
	for _, c := range []struct {
		h          string
		size       int64
		start, end int64
		partial    bool
		ok         bool
	}{
		{"", 10, 0, 10, false, true},
		{"", 0, 0, 0, false, true},
		{"bytes=0-0", 10, 0, 1, true, true},
		{"bytes=9-9", 10, 9, 10, true, true},
		{"bytes=3-", 10, 3, 10, true, true},
		{"bytes=3-100", 10, 3, 10, true, true},
		{"bytes=10-", 10, 0, 0, false, false},
		{"bytes=0-0", 0, 0, 0, false, false},
		{"bytes=5-4", 10, 0, 0, false, false},
		{"bytes=-5", 10, 0, 0, false, false},
		{"bytes=0-1,3-4", 10, 0, 0, false, false},
		{"bytes= 0-1", 10, 0, 0, false, false},
		{"bytes=+1-2", 10, 0, 0, false, false},
		{"items=0-1", 10, 0, 0, false, false},
		{"bytes=99999999999999999999-", 10, 0, 0, false, false},
	} {
		s, e, p, ok := v2ParseRange(c.h, c.size)
		if s != c.start || e != c.end || p != c.partial || ok != c.ok {
			t.Errorf("%q size %d: got %d %d %v %v", c.h, c.size, s, e, p, ok)
		}
	}
}

func TestV2ServeRange(t *testing.T) {
	data := []byte("0123456789")
	s := senderV2(t, writeSource(t, data), allow)
	for _, c := range []struct {
		h, body, cr string
		code        int
	}{
		{"", "0123456789", "", 200},
		{"bytes=2-4", "234", "bytes 2-4/10", 206},
		{"bytes=7-", "789", "bytes 7-9/10", 206},
		{"bytes=10-", "", "bytes */10", 416},
		{"bytes=0-1,4-5", "", "bytes */10", 416},
	} {
		r := httptest.NewRequest("GET", "/v2/file/"+s.Offer.ID, nil)
		r.Header.Set(browserGuardHeader, browserGuardValue)
		if c.h != "" {
			r.Header.Set("Range", c.h)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != c.code || w.Header().Get("Content-Range") != c.cr || (c.code < 400 && w.Body.String() != c.body) {
			t.Errorf("%q: %d %q %q", c.h, w.Code, w.Header().Get("Content-Range"), w.Body.String())
		}
	}
}

func TestV2FallsBackToV1(t *testing.T) {
	data := []byte("v1 sender data")
	s := sender(t, data, allow)
	ts := httptest.NewServer(s)
	defer ts.Close()
	r, err := FetchAnyOffer(context.Background(), ts.Client(), ts.URL)
	if err != nil || r.Version != 1 || r.Name != "example.bin" || r.Size != int64(len(data)) {
		t.Fatalf("fallback failed: %+v %v", r, err)
	}
	path, err := r.Download(context.Background(), ts.Client(), ts.URL, testSender, t.TempDir(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatal("mismatch")
	}

	// A v2 sender that refuses for any other reason is not downgraded.
	ts2 := httptest.NewServer(senderV2(t, writeSource(t, data), func(context.Context, string) error { return errors.New("no") }))
	defer ts2.Close()
	if _, err := FetchAnyOffer(context.Background(), ts2.Client(), ts2.URL); err == nil {
		t.Fatal("unauthorized offer accepted")
	}
}

func TestV2GatesOnEveryEndpoint(t *testing.T) {
	var lookedUp atomic.Bool
	deny := func(context.Context, string) error { lookedUp.Store(true); return errors.New("wrong node") }
	s := senderV2(t, writeSource(t, []byte("secret data")), deny)
	paths := [][2]string{{"GET", "/v2/offer"}, {"GET", "/v2/manifest/" + s.Offer.ID}, {"GET", "/v2/file/" + s.Offer.ID}, {"POST", "/v2/ack/" + s.Offer.ID}}
	for _, kind := range []string{"unauthorized", "no guard", "origin", "fetch metadata"} {
		for _, mp := range paths {
			r := httptest.NewRequest(mp[0], mp[1], nil)
			r.RemoteAddr = "100.64.0.3:5555"
			if kind != "no guard" {
				r.Header.Set(browserGuardHeader, browserGuardValue)
			}
			switch kind {
			case "origin":
				r.Header.Set("Origin", "https://evil.example")
			case "fetch metadata":
				r.Header.Set("Sec-Fetch-Site", "same-origin")
			}
			lookedUp.Store(false)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			body := w.Body.String()
			if w.Code != 403 || strings.Contains(body, "secret") || strings.Contains(body, s.Offer.ID) || strings.Contains(body, s.Offer.Root) {
				t.Fatalf("%s %s: disclosed data (%d)", kind, mp[1], w.Code)
			}
			if kind != "unauthorized" && lookedUp.Load() {
				t.Fatal("browser guard should run before identity lookup")
			}
		}
	}
	select {
	case <-s.Done():
		t.Fatal("unauthorized acknowledgement")
	default:
	}
}

func TestV2StateRejectsMismatch(t *testing.T) {
	o := OfferV2{2, strings.Repeat("a", 64), "x.bin", 3 * testChunk, testChunk, v2Hash, strings.Repeat("b", 64)}
	s := v2State{1, testSender, o.Name, o.Size, o.ChunkSize, o.Root, make([]byte, 1)}
	if !s.matches(o, testSender) {
		t.Fatal("matching state rejected")
	}
	for name, mut := range map[string]func(*v2State){
		"sender": func(s *v2State) { s.Sender = "nOther" },
		"root":   func(s *v2State) { s.Root = strings.Repeat("c", 64) },
		"size":   func(s *v2State) { s.Size++ },
		"bitmap": func(s *v2State) { s.Done = make([]byte, 2) },
		"chunk":  func(s *v2State) { s.ChunkSize *= 2 },
	} {
		c := s
		mut(&c)
		if c.matches(o, testSender) {
			t.Errorf("%s: mismatched state accepted", name)
		}
	}
	b, _ := json.Marshal(s)
	if len(b) > v2MaxState {
		t.Fatal("state too large")
	}
}

package transfer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linuskendall/tailbeam/internal/e2e"
)

const testReceiver = "nReceiver"

func newCode(t *testing.T) e2e.Code {
	t.Helper()
	c, err := e2e.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func senderE2E(t *testing.T, path string, code e2e.Code, auth Authorize) *SenderE2E {
	t.Helper()
	s, err := newSenderE2E(context.Background(), path, auth, code, testSender, testReceiver, testChunk, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func downloadE2E(t *testing.T, ctx context.Context, h http.Handler, code e2e.Code, dir string) (string, error) {
	t.Helper()
	ts := httptest.NewServer(h)
	defer ts.Close()
	o, err := FetchE2EOffer(ctx, ts.Client(), ts.URL, code, testSender, testReceiver)
	if err != nil {
		return "", err
	}
	return o.Download(ctx, ts.Client(), ts.URL, testSender, dir, 1<<40, 0)
}

func guarded(method, url string, body []byte) *http.Request {
	r := httptest.NewRequest(method, url, bytes.NewReader(body))
	r.RemoteAddr = "100.64.0.3:5555"
	r.Header.Set(browserGuardHeader, browserGuardValue)
	return r
}

func TestE2ERoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, testChunk, 3*testChunk + 5} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			data := randomData(n, 20)
			code := newCode(t)
			s := senderE2E(t, writeSource(t, data), code, allow)
			dir := t.TempDir()
			path, err := downloadE2E(t, context.Background(), s, code, dir)
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
				t.Fatal("mismatch")
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("missing acknowledgement")
			}
			onlyEntry(t, dir, "example.bin")
		})
	}
}

func TestE2EServeLifecycle(t *testing.T) {
	data := randomData(2*testChunk, 21)
	code := newCode(t)
	s := senderE2E(t, writeSource(t, data), code, allow)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- ServeE2E(context.Background(), l, s) }()
	base := "http://" + l.Addr().String()
	o, err := FetchE2EOffer(context.Background(), http.DefaultClient, base, code, testSender, testReceiver)
	if err != nil {
		t.Fatal(err)
	}
	if o.Name != "example.bin" || o.Size != int64(len(data)) {
		t.Fatalf("offer %+v", o)
	}
	if _, err := o.Download(context.Background(), http.DefaultClient, base, testSender, t.TempDir(), 1<<40, 0); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// helloWith sends msg1 built from code and binding to the offer at offerID.
func helloWith(s http.Handler, code e2e.Code, b e2e.Binding, offerID []byte) *httptest.ResponseRecorder {
	_, msg1, _ := e2e.Hello(code, b)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, guarded("POST", "/e2e/"+hex.EncodeToString(offerID)+"/hello", msg1))
	return w
}

func TestE2EWrongCodeLeaksNothingAndBurns(t *testing.T) {
	code := newCode(t)
	s := senderE2E(t, writeSource(t, []byte("secret data")), code, allow)
	id := code.OfferID()
	b := e2e.Binding{SenderID: testSender, ReceiverID: testReceiver, OfferID: id}

	// A wrong but well-formed code names a different offer: plain 404, not counted.
	other := newCode(t)
	ts := httptest.NewServer(s)
	defer ts.Close()
	if _, err := FetchE2EOffer(context.Background(), ts.Client(), ts.URL, other, testSender, testReceiver); err == nil {
		t.Fatal("wrong code accepted")
	}

	// Someone who learned the offer ID but not the code: refused, counted.
	for i := range e2eMaxAttempts {
		w := helloWith(s, other, b, id)
		body := w.Body.String()
		if w.Code != http.StatusForbidden || strings.Contains(body, "example") || strings.Contains(body, "secret") || strings.Contains(body, s.core.Offer.Root) {
			t.Fatalf("attempt %d: %d %q", i, w.Code, body)
		}
	}
	select {
	case <-s.Burned():
	default:
		t.Fatal("offer not burned")
	}
	// Even the right code is refused now.
	if _, err := FetchE2EOffer(context.Background(), ts.Client(), ts.URL, code, testSender, testReceiver); !errors.Is(err, ErrOfferGone) {
		t.Fatalf("burned offer: %v", err)
	}
}

func TestE2EBurnStopsServe(t *testing.T) {
	code := newCode(t)
	s := senderE2E(t, writeSource(t, []byte("data")), code, allow)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan error, 1)
	go func() { done <- ServeE2E(context.Background(), l, s) }()
	other := newCode(t)
	b := e2e.Binding{SenderID: testSender, ReceiverID: testReceiver, OfferID: code.OfferID()}
	for range e2eMaxAttempts {
		helloWith(s, other, b, code.OfferID())
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrOfferBurned) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeE2E did not stop")
	}
}

func TestE2EBindingMismatchFails(t *testing.T) {
	code := newCode(t)
	s := senderE2E(t, writeSource(t, []byte("data")), code, allow)
	ts := httptest.NewServer(s)
	defer ts.Close()
	for name, ids := range map[string][2]string{"sender": {"nOther", testReceiver}, "receiver": {testSender, "nOther"}} {
		if _, err := FetchE2EOffer(context.Background(), ts.Client(), ts.URL, code, ids[0], ids[1]); err == nil {
			t.Errorf("%s ID mismatch accepted", name)
		}
	}
	// Wrong offer ID inside the prologue, sent to the real offer's path.
	other := newCode(t)
	if w := helloWith(s, code, e2e.Binding{SenderID: testSender, ReceiverID: testReceiver, OfferID: other.OfferID()}, code.OfferID()); w.Code != http.StatusForbidden {
		t.Fatalf("prologue offer mismatch: %d", w.Code)
	}
}

func TestE2EUnconfirmedHandshakeExpiresAndCounts(t *testing.T) {
	code := newCode(t)
	s := senderE2E(t, writeSource(t, []byte("data")), code, allow)
	now := time.Now()
	s.now = func() time.Time { return now }
	b := e2e.Binding{SenderID: testSender, ReceiverID: testReceiver, OfferID: code.OfferID()}
	for range e2eMaxAttempts {
		if w := helloWith(s, code, b, code.OfferID()); w.Code != http.StatusOK {
			t.Fatal(w.Code)
		}
		now = now.Add(2 * e2ePendingTTL)
	}
	// The next request sweeps the last one.
	helloWith(s, code, b, code.OfferID())
	select {
	case <-s.Burned():
	default:
		t.Fatalf("unconfirmed handshakes not counted (failures=%d)", s.failures)
	}
}

func TestE2ENodeIdentityWithoutCodeGetsNothing(t *testing.T) {
	code := newCode(t)
	s := senderE2E(t, writeSource(t, []byte("secret data")), code, allow)
	id := hex.EncodeToString(code.OfferID())
	// Complete a handshake but never confirm it.
	b := e2e.Binding{SenderID: testSender, ReceiverID: testReceiver, OfferID: code.OfferID()}
	init, msg1, _ := e2e.Hello(code, b)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, guarded("POST", "/e2e/"+id+"/hello", msg1))
	payload, err := init.Finish(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	unconfirmed := strings.Split(strings.Split(string(payload), `"sid":"`)[1], `"`)[0]
	for _, mp := range [][2]string{
		{"GET", "/v2/offer"}, {"GET", "/v1/offer"}, {"GET", "/v2/manifest/" + id}, {"GET", "/v2/file/" + id},
		{"GET", "/e2e/" + id + "/manifest"}, {"GET", "/e2e/" + id + "/manifest?sid=" + strings.Repeat("0", 32)},
		{"GET", "/e2e/" + id + "/manifest?sid=" + unconfirmed}, {"GET", "/e2e/" + id + "/chunks?first=0&last=0&sid=" + unconfirmed},
		{"POST", "/e2e/" + id + "/ack?sid=" + unconfirmed}, {"POST", "/e2e/" + id + "/confirm"},
	} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, guarded(mp[0], mp[1], nil))
		body := w.Body.String()
		if w.Code < 400 || strings.Contains(body, "secret") || strings.Contains(body, "example") || strings.Contains(body, s.core.Offer.Root) {
			t.Fatalf("%s %s: %d %q", mp[0], mp[1], w.Code, body)
		}
	}
	select {
	case <-s.Done():
		t.Fatal("acknowledged without a confirmed session")
	default:
	}
}

func TestE2EGatesOnEveryEndpoint(t *testing.T) {
	var lookedUp atomic.Bool
	deny := func(context.Context, string) error { lookedUp.Store(true); return errors.New("wrong node") }
	code := newCode(t)
	s := senderE2E(t, writeSource(t, []byte("secret data")), code, deny)
	id := hex.EncodeToString(code.OfferID())
	for _, kind := range []string{"unauthorized", "no guard", "origin", "fetch metadata"} {
		for _, action := range []string{"hello", "confirm", "manifest", "chunks", "ack"} {
			r := guarded("POST", "/e2e/"+id+"/"+action, nil)
			switch kind {
			case "no guard":
				r.Header.Del(browserGuardHeader)
			case "origin":
				r.Header.Set("Origin", "https://evil.example")
			case "fetch metadata":
				r.Header.Set("Sec-Fetch-Site", "same-origin")
			}
			lookedUp.Store(false)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 403 || w.Header().Get(modeHeader) != "" {
				t.Fatalf("%s %s: %d", kind, action, w.Code)
			}
			if kind != "unauthorized" && lookedUp.Load() {
				t.Fatal("browser guard should run before identity lookup")
			}
		}
	}
	if s.failures != 0 {
		t.Fatal("ungated requests counted as handshake attempts")
	}
}

func TestE2ETamperedChunks(t *testing.T) {
	t.Run("one-off flip is refetched", func(t *testing.T) {
		data := randomData(6*testChunk, 22)
		code := newCode(t)
		tp := &tap{h: senderE2E(t, writeSource(t, data), code, allow), flip: func(req int) int64 {
			if req == 0 {
				return 2*testChunk + 100
			}
			return -1
		}}
		path, err := downloadE2E(t, context.Background(), tp, code, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
			t.Fatal("mismatch")
		}
	})
	t.Run("persistent flip fails", func(t *testing.T) {
		code := newCode(t)
		s := senderE2E(t, writeSource(t, randomData(3*testChunk, 23)), code, allow)
		tp := &tap{h: s, flip: func(int) int64 { return 50 }}
		dir := t.TempDir()
		if _, err := downloadE2E(t, context.Background(), tp, code, dir); err == nil || !strings.Contains(err.Error(), "authentication") {
			t.Fatalf("expected authentication failure, got %v", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
			t.Fatal("published tampered data")
		}
	})
	t.Run("truncation resumes", func(t *testing.T) {
		data := randomData(20*testChunk, 24)
		code := newCode(t)
		tp := &tap{h: senderE2E(t, writeSource(t, data), code, allow), cutAt: int64(len(data)) / 2}
		path, err := downloadE2E(t, context.Background(), tp, code, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
			t.Fatal("mismatch")
		}
	})
}

// swapChunks reorders the first two sealed chunks of every chunk response.
type swapChunks struct{ h http.Handler }

func (s swapChunks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/chunks") {
		s.h.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, r)
	b := rec.Body.Bytes()
	n := testChunk + e2e.Overhead
	if len(b) >= 2*n {
		b = append(append(append([]byte{}, b[n:2*n]...), b[:n]...), b[2*n:]...)
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	w.WriteHeader(rec.Code)
	w.Write(b)
}

func TestE2EReorderedChunksRejected(t *testing.T) {
	code := newCode(t)
	dir := t.TempDir()
	// 8 chunks: with up to 4 streams every response carries at least two.
	h := swapChunks{senderE2E(t, writeSource(t, randomData(8*testChunk, 25)), code, allow)}
	if _, err := downloadE2E(t, context.Background(), h, code, dir); err == nil {
		t.Fatal("reordered chunks accepted")
	}
	if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
		t.Fatal("published reordered data")
	}
}

// flipManifest corrupts one byte of the sealed manifest.
type flipManifest struct{ h http.Handler }

func (f flipManifest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/manifest") {
		f.h.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	b := rec.Body.Bytes()
	b[len(b)/2] ^= 1
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	w.WriteHeader(rec.Code)
	w.Write(b)
}

func TestE2EManifestTamperRejected(t *testing.T) {
	code := newCode(t)
	h := flipManifest{senderE2E(t, writeSource(t, randomData(3*testChunk, 26)), code, allow)}
	if _, err := downloadE2E(t, context.Background(), h, code, t.TempDir()); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected manifest failure, got %v", err)
	}
}

func TestE2EResumeAcrossReceiverAndSenderRestart(t *testing.T) {
	data := randomData(40*testChunk+17, 27)
	src := writeSource(t, data)
	dir := t.TempDir()

	// The first sender goes away half way through.
	first := newCode(t)
	tp := &tap{h: senderE2E(t, src, first, allow), cutAt: int64(len(data)) / 2, failAfterCut: true}
	if _, err := downloadE2E(t, context.Background(), tp, first, dir); err == nil {
		t.Fatal("interrupted download succeeded")
	}
	if _, err := os.Lstat(filepath.Join(dir, "example.bin")); err == nil {
		t.Fatal("published an incomplete file")
	}

	// A new sender process prints a new code; the root is unchanged.
	code := newCode(t)
	tp2 := &tap{h: senderE2E(t, src, code, allow)}
	path, err := downloadE2E(t, context.Background(), tp2, code, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatal("mismatch after resume")
	}
	if served := tp2.served.Load(); served == 0 || served > int64(len(data))*3/4 {
		t.Fatalf("resume re-fetched too much: %d of %d bytes", served, len(data))
	}
	onlyEntry(t, dir, "example.bin")
}

func TestModeMismatch(t *testing.T) {
	data := []byte("data")
	code := newCode(t)

	// Encrypted receiver, plaintext senders (v2 and v1).
	for name, h := range map[string]http.Handler{"v2": senderV2(t, writeSource(t, data), allow), "v1": sender(t, data, allow)} {
		ts := httptest.NewServer(h)
		_, err := FetchE2EOffer(context.Background(), ts.Client(), ts.URL, code, testSender, testReceiver)
		ts.Close()
		if !errors.Is(err, ErrSenderPlaintext) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Plaintext receiver, encrypted sender: an error, never a plaintext offer.
	ts := httptest.NewServer(senderE2E(t, writeSource(t, data), code, allow))
	defer ts.Close()
	if _, err := FetchAnyOffer(context.Background(), ts.Client(), ts.URL); !errors.Is(err, ErrSenderEncrypted) {
		t.Fatalf("plaintext receiver: %v", err)
	}
	if _, err := FetchOffer(context.Background(), ts.Client(), ts.URL); !errors.Is(err, ErrSenderEncrypted) {
		t.Fatalf("v1 receiver: %v", err)
	}
}

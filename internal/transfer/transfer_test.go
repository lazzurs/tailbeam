package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sender(t *testing.T, data []byte, auth Authorize) *Sender {
	t.Helper()
	p := filepath.Join(t.TempDir(), "example.bin")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(context.Background(), p, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func allow(context.Context, string) error { return nil }

func TestRoundTrip(t *testing.T) {
	for _, data := range [][]byte{nil, bytes.Repeat([]byte("tailbeam\x00\xff"), 131072)} {
		t.Run(fmt.Sprint(len(data)), func(t *testing.T) {
			s := sender(t, data, allow)
			ts := httptest.NewServer(s)
			defer ts.Close()
			o, err := FetchOffer(context.Background(), ts.Client(), ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path, err := Download(context.Background(), ts.Client(), ts.URL, o, dir, 1<<30)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, got) {
				t.Fatalf("mismatch: %v", err)
			}
			st, _ := os.Stat(path)
			if st.Mode().Perm()&0077 != 0 {
				t.Fatal("download is accessible to other local users")
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("missing acknowledgement")
			}
			if _, err = FetchOffer(context.Background(), ts.Client(), ts.URL); err == nil {
				t.Fatal("completed offer still visible")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatal("temporary file was not removed")
			}
		})
	}
}

func TestUnauthorizedGetsNoMetadataOrContent(t *testing.T) {
	s := sender(t, []byte("secret data"), func(context.Context, string) error { return errors.New("wrong node") })
	for _, path := range []string{"/v1/offer", "/v1/file/" + s.Offer.ID, "/v1/ack/" + s.Offer.ID} {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "100.64.0.3:5555"
		r.Header.Set(browserGuardHeader, browserGuardValue)
		r.Header.Set("X-Forwarded-For", "100.64.0.2")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 403 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), s.Offer.ID) {
			t.Fatal("disclosed transfer to wrong peer")
		}
	}
	select {
	case <-s.Done():
		t.Fatal("unauthorized acknowledgement")
	default:
	}
}

func TestBrowserRequestsRejectedBeforeIdentityLookup(t *testing.T) {
	for _, kind := range []string{"no guard", "wrong guard", "cross-origin", "fetch metadata", "DNS rebinding"} {
		t.Run(kind, func(t *testing.T) {
			var lookedUp bool
			s := sender(t, []byte("secret"), func(context.Context, string) error { lookedUp = true; return nil })
			for _, methodPath := range [][2]string{{"GET", "/v1/offer"}, {"GET", "/v1/file/" + s.Offer.ID}, {"POST", "/v1/ack/" + s.Offer.ID}} {
				r := httptest.NewRequest(methodPath[0], methodPath[1], nil)
				switch kind {
				case "wrong guard":
					r.Header.Set(browserGuardHeader, "setec")
				case "cross-origin":
					r.Header.Set(browserGuardHeader, browserGuardValue)
					r.Header.Set("Origin", "https://evil.example")
				case "fetch metadata":
					r.Header.Set(browserGuardHeader, browserGuardValue)
					r.Header.Set("Sec-Fetch-Site", "same-origin")
				case "DNS rebinding":
					r.Host = "evil.example:8784"
				}
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Code != 403 || strings.Contains(w.Body.String(), s.Offer.ID) {
					t.Fatal("browser request was accepted")
				}
			}
			if lookedUp {
				t.Fatal("browser guard should run before expensive identity lookup")
			}
			select {
			case <-s.Done():
				t.Fatal("browser consumed offer")
			default:
			}
		})
	}
}

func TestFailedDownloadsAreNotPublished(t *testing.T) {
	for _, kind := range []string{"truncated", "corrupt", "oversized", "limit"} {
		t.Run(kind, func(t *testing.T) {
			s := sender(t, []byte("expected data"), allow)
			body := "expected data"
			switch kind {
			case "truncated":
				body = "short"
			case "corrupt":
				body = "corrupt! data"
			case "oversized":
				body += "extra"
			}
			var ack bool
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/v1/ack/") {
					ack = true
					w.WriteHeader(204)
					return
				}
				fmt.Fprint(w, body)
			}))
			defer ts.Close()
			max := int64(1024)
			if kind == "limit" {
				max = 1
			}
			dir := t.TempDir()
			if _, err := Download(context.Background(), ts.Client(), ts.URL, s.Offer, dir, max); err == nil {
				t.Fatal("accepted failed download")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 || ack {
				t.Fatal("published or acknowledged a failed download")
			}
		})
	}
}

func TestNoOverwriteOrSymlinkFollow(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(fmt.Sprint(symlink), func(t *testing.T) {
			s := sender(t, []byte("new"), allow)
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
			if _, err := Download(context.Background(), ts.Client(), ts.URL, s.Offer, dir, 1024); err == nil {
				t.Fatal("overwrote destination")
			}
			got, _ := os.ReadFile(target)
			if string(got) != "keep me" {
				t.Fatal("existing data was modified")
			}
		})
	}
}

func TestPathValidation(t *testing.T) {
	s := sender(t, []byte("data"), allow)
	for _, name := range []string{"../escape", "/absolute", "..", ".", "", `C:\file`, `dir\file`, "bad\nname", "NUL.txt", "COM1", " trailing", "trailing.", "a:b"} {
		o := s.Offer
		o.Name = name
		if err := validateOffer(o); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, name := range []string{"normal.txt", "résumé.pdf", "my file.tar.gz"} {
		if err := validName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestAckFailurePreservesVerifiedFile(t *testing.T) {
	data := []byte("verified")
	s := sender(t, data, allow)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			http.Error(w, "failure", 500)
			return
		}
		w.Write(data)
	}))
	defer ts.Close()
	dest, err := Download(context.Background(), ts.Client(), ts.URL, s.Offer, t.TempDir(), 1024)
	if dest == "" || err == nil || !strings.Contains(err.Error(), "acknowledgement failed") {
		t.Fatalf("%q: %v", dest, err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, data) {
		t.Fatal("lost verified download")
	}
}

func TestDestinationCreatedDuringTransfer(t *testing.T) {
	data := []byte("new")
	s := sender(t, data, allow)
	dir := t.TempDir()
	dest := filepath.Join(dir, s.Offer.Name)
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			if err := os.WriteFile(dest, []byte("winner"), 0600); err != nil {
				t.Error(err)
			}
		})
		w.Write(data)
	}))
	defer ts.Close()
	if _, err := Download(context.Background(), ts.Client(), ts.URL, s.Offer, dir, 1024); err == nil {
		t.Fatal("overwrote concurrent file")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "winner" {
		t.Fatal("concurrent file modified")
	}
}

func TestSourceMutationDetected(t *testing.T) {
	s := sender(t, []byte("before"), allow)
	if err := os.WriteFile(s.file.Name(), []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	if _, err := Download(context.Background(), ts.Client(), ts.URL, s.Offer, t.TempDir(), 1024); err == nil {
		t.Fatal("accepted mutated source")
	}
}

func TestOfferLimits(t *testing.T) {
	for _, body := range []string{strings.Repeat("x", maxMetadata+1), `{"version":2}`, `{"version":1,"size":-1}`} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		_, err := FetchOffer(context.Background(), ts.Client(), ts.URL)
		ts.Close()
		if err == nil {
			t.Fatal("accepted invalid offer")
		}
	}
}

func TestServeLifecycle(t *testing.T) {
	for _, acknowledge := range []bool{true, false} {
		t.Run(fmt.Sprint(acknowledge), func(t *testing.T) {
			s := sender(t, []byte("hello"), allow)
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Serve(ctx, l, s) }()
			if acknowledge {
				c := &http.Client{Timeout: 3 * time.Second}
				defer c.CloseIdleConnections()
				if _, err := Download(ctx, c, "http://"+l.Addr().String(), s.Offer, t.TempDir(), 1024); err != nil {
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

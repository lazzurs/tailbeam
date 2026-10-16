// Package transfer implements a single-file, single-recipient pull protocol.
package transfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/linuskendall/tailbeam/internal/tailnet"
)

const DefaultPort = 8784
const maxMetadata = 16 << 10

// A stalled sender write fails after this long without progress; every
// successful write renews it, so slow but live transfers are never cut off.
const defaultWriteTimeout = 60 * time.Second

// Like Setec, require a forbidden-to-browser-JavaScript Sec-* header. This is
// defense against browser-based access from an otherwise authorized host,
// including same-origin requests after DNS rebinding. It is not authentication.
const browserGuardHeader = "Sec-X-Tailscale-No-Browsers"
const browserGuardValue = "tailbeam"

type Offer struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// Authorize must authenticate the actual TCP peer, not HTTP headers.
type Authorize func(context.Context, string) error

type Sender struct {
	Offer     Offer
	file      *os.File
	authorize Authorize
	// mu guards only complete and the ack transition; file streaming is
	// lock-free (ReadAt is concurrency-safe) so a stuck connection cannot
	// block a retry.
	mu           sync.Mutex
	done         chan struct{}
	complete     bool
	started      chan struct{}
	startOnce    sync.Once
	writeTimeout time.Duration
}

func NewSender(ctx context.Context, path string, authorize Authorize) (*Sender, error) {
	if authorize == nil {
		return nil, errors.New("missing peer authorization")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("only regular files are supported")
	}
	name := filepath.Base(path)
	if err := validName(name); err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, f})
	if err != nil {
		return nil, err
	}
	if n != st.Size() {
		return nil, errors.New("file changed while hashing")
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	s := &Sender{Offer: Offer{1, hex.EncodeToString(token[:]), name, n, hex.EncodeToString(h.Sum(nil))}, file: f, authorize: authorize, done: make(chan struct{}), started: make(chan struct{}), writeTimeout: defaultWriteTimeout}
	ok = true
	return s, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

func (s *Sender) Close() error          { return s.file.Close() }
func (s *Sender) Done() <-chan struct{} { return s.done }

// Started is closed when the first authorized request for file content begins.
func (s *Sender) Started() <-chan struct{} { return s.started }

func (s *Sender) finished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.complete
}

// deadlineWriter renews the connection write deadline after each successful write.
type deadlineWriter struct {
	w  io.Writer
	rc *http.ResponseController
	d  time.Duration
}

func (w deadlineWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if err == nil {
		// Ignore unsupported-deadline errors; the initial call reported them.
		w.rc.SetWriteDeadline(time.Now().Add(w.d))
	}
	return n, err
}

func (s *Sender) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(browserGuardHeader) != browserGuardValue || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Authenticate before disclosing even metadata. Never trust proxy headers.
	if err := s.authorize(r.Context(), r.RemoteAddr); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if s.finished() {
		http.Error(w, "offer completed", http.StatusGone)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/offer":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Offer)
	case r.Method == "GET" && r.URL.Path == "/v1/file/"+s.Offer.ID:
		s.startOnce.Do(func() { close(s.started) })
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(s.Offer.Size))
		rc := http.NewResponseController(w)
		rc.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		dw := deadlineWriter{w, rc, s.writeTimeout}
		if _, err := io.Copy(dw, io.NewSectionReader(s.file, 0, s.Offer.Size)); err != nil {
			// Headers are already sent; the client sees a truncated body and
			// fails its length/hash checks. Returning drops the connection.
			return
		}
	case r.Method == "POST" && r.URL.Path == "/v1/ack/"+s.Offer.ID:
		s.mu.Lock()
		if s.complete {
			s.mu.Unlock()
			http.Error(w, "offer completed", http.StatusGone)
			return
		}
		s.complete = true
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		// Serve waits for the active handler before closing the connection.
		close(s.done)
	default:
		http.NotFound(w, r)
	}
}

func Serve(ctx context.Context, l net.Listener, s *Sender) error {
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	result := make(chan error, 1)
	go func() { result <- srv.Serve(l) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		srv.Close()
		return ctx.Err()
	case <-s.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// Client uses a fixed daemon-supplied Tailscale address. It bypasses proxies,
// rejects redirects, and verifies the daemon's identity for every new TCP link.
func Client(b tailnet.Backend, peer *tailnet.Node, port int) (*http.Client, string, error) {
	return newClient(b, peer, port, (&net.Dialer{Timeout: 3 * time.Second}).DialContext)
}

func newClient(b tailnet.Backend, peer *tailnet.Node, port int, dial func(context.Context, string, string) (net.Conn, error)) (*http.Client, string, error) {
	ip, err := tailnet.IP(peer)
	if err != nil {
		return nil, "", err
	}
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	tr := &http.Transport{
		Proxy:                  nil,
		ResponseHeaderTimeout:  10 * time.Second,
		IdleConnTimeout:        10 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != addr {
				return nil, errors.New("unexpected connection target")
			}
			conn, err := dial(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			if err := tailnet.Verify(ctx, b, conn.RemoteAddr().String(), peer.ID); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are forbidden") }}, "http://" + addr, nil
}

func request(ctx context.Context, c *http.Client, method, url string) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(browserGuardHeader, browserGuardValue)
	resp, err := c.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && !(method == "POST" && resp.StatusCode == http.StatusNoContent) {
		resp.Body.Close()
		return nil, fmt.Errorf("peer returned HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func FetchOffer(ctx context.Context, c *http.Client, base string) (Offer, error) {
	var o Offer
	r, err := request(ctx, c, "GET", base+"/v1/offer")
	if err != nil {
		return o, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, maxMetadata+1))
	if err != nil {
		return o, err
	}
	if len(b) > maxMetadata {
		return o, errors.New("offer too large")
	}
	if err = json.Unmarshal(b, &o); err != nil {
		return o, err
	}
	return o, validateOffer(o)
}

func validName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 255 || strings.ContainsAny(name, "/\\:") || strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") {
		return errors.New("unsafe file name")
	}
	// Dotfiles (.profile, .envrc, .npmrc) are commonly executed or trusted by tools.
	if strings.HasPrefix(name, ".") {
		return errors.New("file name must not start with a dot")
	}
	// Invalid UTF-8 would otherwise decode as printable U+FFFD below.
	if !utf8.ValidString(name) {
		return errors.New("file name is not valid UTF-8")
	}
	// NFC normalization is not enforced: golang.org/x/text is not a dependency.
	for _, r := range name {
		// IsPrint already excludes Cf and C1; the checks are explicit for clarity.
		if r < 32 || r == 127 || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r) {
			return errors.New("control, format, or non-printable character in file name")
		}
	}
	// Avoid Windows device names even when the sender runs on Unix.
	base := strings.ToUpper(strings.Split(name, ".")[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') {
		return errors.New("reserved file name")
	}
	return nil
}

func validateOffer(o Offer) error {
	if o.Version != 1 || o.Size < 0 {
		return errors.New("invalid offer version or size")
	}
	for _, v := range []string{o.ID, o.SHA256} {
		b, e := hex.DecodeString(v)
		if e != nil || len(b) != 32 {
			return errors.New("invalid offer token or checksum")
		}
	}
	return validName(o.Name)
}

// Download publishes only a complete, verified file. Linking a private temporary
// file into place gives atomic no-replace semantics, including against symlinks.
// The output directory must be trusted and must support hard links.
func Download(ctx context.Context, c *http.Client, base string, o Offer, dir string, maxBytes int64) (string, error) {
	return DownloadIdle(ctx, c, base, o, dir, maxBytes, 0)
}

var errIdle = errors.New("idle timeout")

// idleReader cancels the request when no bytes arrive for the idle duration.
type idleReader struct {
	r     io.Reader
	timer *time.Timer
	d     time.Duration
}

func (r idleReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	if n > 0 {
		r.timer.Reset(r.d)
	}
	return n, err
}

// DownloadIdle is Download with an idle watchdog: if idle > 0 and no response
// bytes arrive for that long, the request is canceled. There is no total cap.
func DownloadIdle(ctx context.Context, c *http.Client, base string, o Offer, dir string, maxBytes int64, idle time.Duration) (string, error) {
	if err := validateOffer(o); err != nil {
		return "", err
	}
	if maxBytes < 0 || o.Size > maxBytes {
		return "", errors.New("file exceeds --max-bytes")
	}
	dest := filepath.Join(dir, o.Name)
	if _, err := os.Lstat(dest); err == nil {
		return "", fmt.Errorf("destination already exists: %s", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if free, ok, err := freeSpace(dir); err != nil {
		return "", err
	} else if ok && uint64(o.Size) > free {
		return "", fmt.Errorf("not enough free space in %s: need %d bytes, have %d", dir, o.Size, free)
	}
	f, err := os.CreateTemp(dir, ".tailbeam-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := preallocate(f, o.Size); err != nil {
		return "", fmt.Errorf("preallocate: %w", err)
	}
	reqCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var timer *time.Timer
	if idle > 0 {
		timer = time.AfterFunc(idle, func() { cancel(errIdle) })
		defer timer.Stop()
	}
	fail := func(err error) (string, error) {
		if errors.Is(context.Cause(reqCtx), errIdle) {
			return "", fmt.Errorf("no data received for %s: %w", idle, errIdle)
		}
		return "", err
	}
	r, err := request(reqCtx, c, "GET", base+"/v1/file/"+o.ID)
	if err != nil {
		return fail(err)
	}
	defer r.Body.Close()
	var body io.Reader = r.Body
	if timer != nil {
		timer.Reset(idle)
		body = idleReader{r.Body, timer, idle}
	}
	h := sha256.New()
	// CopyN followed by a one-byte read avoids size+1 overflow for hostile offers.
	_, err = io.CopyN(io.MultiWriter(f, h), body, o.Size)
	if err != nil {
		return fail(fmt.Errorf("incomplete download: %w", err))
	}
	var extra [1]byte
	n, err := body.Read(extra[:])
	if n != 0 || err != io.EOF {
		return "", errors.New("download length does not match offer")
	}
	if hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
		return "", errors.New("SHA-256 mismatch; file was not saved")
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = os.Link(f.Name(), dest); err != nil {
		return "", fmt.Errorf("publish without overwrite: %w", err)
	}
	if err = syncDir(dir); err != nil {
		return dest, fmt.Errorf("file saved at %s, but directory sync failed: %w", dest, err)
	}
	ack, err := request(ctx, c, "POST", base+"/v1/ack/"+o.ID)
	if err != nil {
		return dest, fmt.Errorf("file saved at %s, but acknowledgement failed: %w", dest, err)
	}
	ack.Body.Close()
	return dest, nil
}

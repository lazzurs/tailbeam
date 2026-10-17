// Package transfer implements tailbeam's single-file, single-recipient pull
// protocol: chunked plaintext transfers (v2.go, v2_receive.go) and the default
// end-to-end encrypted mode (e2e.go, e2e_receive.go). This file holds the
// pieces they share.
package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/linuskendall/tailbeam/internal/tailnet"
)

const DefaultPort = 8784
const maxMetadata = 16 << 10

// Like Setec, require a forbidden-to-browser-JavaScript Sec-* header. This is
// defense against browser-based access from an otherwise authorized host,
// including same-origin requests after DNS rebinding. It is not authentication.
const browserGuardHeader = "Sec-X-Tailscale-No-Browsers"
const browserGuardValue = "tailbeam"

// Authorize must authenticate the actual TCP peer, not HTTP headers.
type Authorize func(context.Context, string) error

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

// shutdownAfterAck stops the server once the receiver has acknowledged. The
// transfer is complete, so connections that are still open (for example an
// idle parallel stream that never sent a request, which Shutdown waits on for
// 5 seconds) are closed rather than reported as an error.
func shutdownAfterAck(srv *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return srv.Close()
	}
	return err
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
		MaxIdleConnsPerHost:    v2MaxReads, // keep parallel streams' connections (and their identity checks)
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

package transfer

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linuskendall/tailbeam/internal/tailnet"
)

type identityBackend struct {
	identity *tailnet.Identity
	err      error
}

func (b identityBackend) Status(context.Context) (*tailnet.Status, error) { return nil, b.err }
func (b identityBackend) WhoIs(context.Context, string) (*tailnet.Identity, error) {
	return b.identity, b.err
}

// Only the socket's reported peer address is substituted. Actual HTTP flows over
// a loopback TCP socket; no test-only mode is exposed by the CLI or public Client.
type peerConn struct{ net.Conn }

func (c peerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 8784}
}

func TestClientAuthenticatesBeforeSendingHTTP(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	for _, kind := range []string{"correct", "wrong node", "wrong address", "daemon unavailable", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			s := senderV2(t, writeSource(t, []byte("secret")), allow)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if kind == "redirect" {
					http.Redirect(w, r, "http://example.com/leak", http.StatusFound)
					return
				}
				s.ServeHTTP(w, r)
			}))
			defer ts.Close()
			id := &tailnet.Identity{Node: &tailnet.WhoIsNode{StableID: "nSender", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}}
			b := identityBackend{identity: id}
			switch kind {
			case "wrong node":
				id.Node.StableID = "nImposter"
			case "wrong address":
				id.Node.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}
			case "daemon unavailable":
				b.err = errors.New("daemon down")
			}
			p := &tailnet.Node{ID: "nSender", TailscaleIPs: []string{"100.64.0.1"}}
			c, base, err := newClient(b, p, 8784, func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr != "100.64.0.1:8784" {
					t.Errorf("unexpected target %s", addr)
				}
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ts.Listener.Addr().String())
				if err != nil {
					return nil, err
				}
				return peerConn{conn}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = FetchPlainOffer(ctx, c, base)
			if kind == "correct" {
				if err != nil {
					t.Fatal(err)
				}
				if calls.Load() != 1 {
					t.Fatal("request did not reach authenticated peer")
				}
			} else {
				if err == nil {
					t.Fatal("accepted untrusted response")
				}
				want := int32(0)
				if kind == "redirect" {
					want = 1
				}
				if calls.Load() != want {
					t.Fatalf("sent HTTP before authorization or followed redirect: calls=%d", calls.Load())
				}
			}
		})
	}
}

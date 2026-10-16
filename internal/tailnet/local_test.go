package tailnet

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"tailscale.com/client/local"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockLocal(t *testing.T, path, body string) *Local {
	t.Helper()
	return &Local{client: &local.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != path {
			t.Errorf("unexpected API path: %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}}
}

func TestOfficialLocalAPIStatusMapping(t *testing.T) {
	body := `{"BackendState":"Running","Self":{"ID":"nSelf","DNSName":"self.tail.ts.net.","TailscaleIPs":["100.64.0.1"]},"Peer":{"nodekey:` + strings.Repeat("0", 64) + `":{"ID":"nPeer","NodeID":123,"DNSName":"peer.tail.ts.net.","TailscaleIPs":["100.64.0.2"],"Online":true,"Tags":["tag:receiver"]}}}`
	b := mockLocal(t, "/localapi/v0/status", body)
	s, err := b.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p, err := Resolve(s, "peer")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "nPeer" || !p.Online || len(p.Tags) != 1 || s.Self.ID != "nSelf" {
		t.Fatalf("incorrect status conversion: %+v", s)
	}
}

func TestOfficialLocalAPIWhoIsMapping(t *testing.T) {
	b := mockLocal(t, "/localapi/v0/whois", `{"Node":{"ID":123,"StableID":"nPeer","Addresses":["100.64.0.2/32"]},"UserProfile":{"LoginName":"alice@example.com"}}`)
	if err := Verify(context.Background(), b, "100.64.0.2:54321", "nPeer"); err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), b, "100.64.0.2:54321", "nOther"); err == nil {
		t.Fatal("accepted wrong stable ID")
	}
}

func TestOfficialLocalAPIFailsClosed(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"Node":null}`, `{"Node":{"ID":123}}`, `not-json`} {
		if _, err := mockLocal(t, "/localapi/v0/whois", body).WhoIs(context.Background(), "100.64.0.2:1"); err == nil {
			t.Fatalf("accepted whois: %s", body)
		}
	}
	for _, body := range []string{`null`, `{}`, `{"BackendState":"Stopped"}`, `{"BackendState":"Running","Self":{}}`} {
		if _, err := mockLocal(t, "/localapi/v0/status", body).Status(context.Background()); err == nil {
			t.Fatalf("accepted status: %s", body)
		}
	}
}

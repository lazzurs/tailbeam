package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
)

type fakeBackend struct {
	id  *Identity
	err error
}

func (f fakeBackend) Status(context.Context) (*Status, error)          { return nil, f.err }
func (f fakeBackend) WhoIs(context.Context, string) (*Identity, error) { return f.id, f.err }

func TestWhoIsWireSchema(t *testing.T) {
	// status uses ID:string; whois uses StableID:string and ID:number.
	const fixture = `{"Node":{"ID":123,"StableID":"nReceiver","Name":"receiver.tail.ts.net.","Addresses":["100.64.0.2/32","fd7a:115c:a1e0::2/128"],"AllowedIPs":["10.0.0.0/8"]},"UserProfile":{"LoginName":"alice@example.com"}}`
	var id Identity
	if err := json.Unmarshal([]byte(fixture), &id); err != nil {
		t.Fatal(err)
	}
	b := fakeBackend{id: &id}
	for _, addr := range []string{"100.64.0.2:1234", "[fd7a:115c:a1e0::2]:1234"} {
		if err := Verify(context.Background(), b, addr, "nReceiver"); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ addr, want string }{
		{"100.64.0.2:1234", "nOther"},
		{"100.64.0.3:1234", "nReceiver"},
		{"10.0.0.2:1234", "nReceiver"},
		{"127.0.0.1:1234", "nReceiver"},
		{"100.64.0.2", "nReceiver"},
	} {
		if err := Verify(context.Background(), b, tc.addr, tc.want); err == nil {
			t.Errorf("accepted %+v", tc)
		}
	}
	if err := Verify(context.Background(), fakeBackend{err: errors.New("daemon down")}, "100.64.0.2:1", "nReceiver"); err == nil {
		t.Fatal("accepted missing daemon")
	}
	id.Node.StableID = ""
	if err := Verify(context.Background(), b, "100.64.0.2:1", ""); err == nil {
		t.Fatal("accepted empty identity")
	}
	id.Node.StableID = "nReceiver"
	id.Node.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	if err := Verify(context.Background(), b, "100.64.0.2:1", "nReceiver"); err == nil {
		t.Fatal("accepted routed prefix as node address")
	}
}

func TestResolve(t *testing.T) {
	a := &Node{ID: "nA", DNSName: "laptop.alpha.ts.net.", TailscaleIPs: []string{"100.64.0.1"}, HostName: "untrusted-hostname"}
	s := &Status{Peer: map[string]*Node{"a": a}}
	for _, name := range []string{"laptop", "LAPTOP.ALPHA.TS.NET.", "100.64.0.1", "nA"} {
		p, err := Resolve(s, name)
		if err != nil || p != a {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"", "example.com", "untrusted-hostname", "127.0.0.1"} {
		if _, err := Resolve(s, name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	s.Peer["b"] = &Node{ID: "nB", DNSName: "laptop.beta.ts.net."}
	if _, err := Resolve(s, "laptop"); err == nil {
		t.Fatal("accepted ambiguous short name")
	}
	if _, err := Resolve(s, "laptop.alpha.ts.net"); err != nil {
		t.Fatal(err)
	}
}

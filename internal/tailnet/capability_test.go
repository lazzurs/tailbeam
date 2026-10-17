package tailnet

import (
	"context"
	"errors"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func caps(values ...string) tailcfg.PeerCapMap {
	cm := tailcfg.PeerCapMap{}
	for _, v := range values {
		cm[CapTailbeam] = append(cm[CapTailbeam], tailcfg.RawMessage(v))
	}
	return cm
}

func TestParseGrantsStrict(t *testing.T) {
	cm := caps(
		`{"actions":["receive"],"maxBytes":1024}`,
		`{"actions":["receive"],"filenames":["*.pdf"]}`, // unknown field: may be a newer restriction
		`{"actions":["recieve"]}`,                       // typo
		`{"actions":[]}`,
		`{"actions":["send"],"maxBytes":-1}`,
		`{"actions":["send"]} {"actions":["receive"]}`, // trailing data
		`not json`,
	)
	cm["example.com/cap/other"] = []tailcfg.RawMessage{`{"actions":["send"]}`}
	grants, invalid := ParseGrants(cm)
	if len(grants) != 1 || *grants[0].MaxBytes != 1024 || len(invalid) != 6 {
		t.Fatalf("grants=%+v invalid=%v", grants, invalid)
	}
}

func TestEvaluate(t *testing.T) {
	grants, invalid := ParseGrants(caps(
		`{"actions":["receive"],"maxBytes":100}`,
		`{"actions":["receive","send"],"maxBytes":1000,"requireE2E":true}`,
	))
	if len(invalid) != 0 {
		t.Fatal(invalid)
	}
	for _, tc := range []struct {
		r    Request
		want string // "" = allowed
	}{
		{Request{ActionReceive, 50, false}, ""},
		{Request{ActionReceive, 500, true}, ""},
		{Request{ActionReceive, 500, false}, "requires end-to-end encryption"},
		{Request{ActionReceive, 5000, true}, "limited to 1000 bytes"},
		{Request{ActionSend, 10, true}, ""},
		{Request{ActionSend, 10, false}, "requires end-to-end"},
	} {
		err := Evaluate(grants, tc.r)
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%+v: got %v, want %q", tc.r, err, tc.want)
		}
	}
	if err := Evaluate(nil, Request{ActionReceive, 1, true}); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("empty grants: %v", err)
	}
	// Grants are additive: an unlimited entry is not narrowed by a limited one.
	grants, _ = ParseGrants(caps(`{"actions":["receive"],"maxBytes":1}`, `{"actions":["receive"]}`))
	if err := Evaluate(grants, Request{ActionReceive, 1 << 40, false}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckModes(t *testing.T) {
	r := Request{ActionReceive, 10, false}
	if w, err := Check(ModeOff, nil, r); err != nil || w != nil {
		t.Fatal("off mode must not evaluate")
	}
	if w, err := Check(ModeWarn, caps(`bad`), r); err != nil || len(w) != 2 {
		t.Fatalf("warn: %v %v", w, err)
	}
	if _, err := Check(ModeEnforce, nil, r); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("enforce: %v", err)
	}
	if _, err := Check(ModeEnforce, caps(`{"actions":["receive"]}`), r); err != nil {
		t.Fatal(err)
	}
}

func TestNodeMode(t *testing.T) {
	attr := func(v ...string) tailcfg.NodeCapMap {
		cm := tailcfg.NodeCapMap{}
		for _, s := range v {
			cm[AttrTailbeam] = append(cm[AttrTailbeam], tailcfg.RawMessage(s))
		}
		return cm
	}
	for _, tc := range []struct {
		cm      tailcfg.NodeCapMap
		want    Mode
		wantErr bool
	}{
		{nil, ModeOff, false},
		{attr(`{"mode":"warn"}`), ModeWarn, false},
		{attr(`{"mode":"warn"}`, `{"mode":"enforce"}`), ModeEnforce, false},
		{attr(`{"mode":"off"}`, `{"mode":"warn"}`), ModeWarn, false},
		{attr(`{"mode":"lax"}`), ModeEnforce, true},
		{attr(`{"mode":"off","extra":1}`), ModeEnforce, true},
	} {
		m, err := NodeMode(tc.cm)
		if m != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%v: got %v %v", tc.cm, m, err)
		}
	}
}

// The LocalAPI WhoIs reply carries the peer's capabilities toward this node;
// they must survive the conversion and VerifyIdentity.
func TestWhoIsCarriesCapMap(t *testing.T) {
	b := mockLocal(t, "/localapi/v0/whois", `{"Node":{"ID":1,"StableID":"nPeer","Addresses":["100.64.0.2/32"]},"UserProfile":{"LoginName":"a@example.com"},"CapMap":{"linuskendall.com/cap/tailbeam":[{"actions":["receive"],"maxBytes":10}]}}`)
	id, err := VerifyIdentity(context.Background(), b, "100.64.0.2:1", "nPeer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(ModeEnforce, id.CapMap, Request{ActionReceive, 10, false}); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(ModeEnforce, id.CapMap, Request{ActionReceive, 11, false}); err == nil {
		t.Fatal("size limit ignored")
	}
}

func TestStatusCarriesSelfNodeAttrs(t *testing.T) {
	body := `{"BackendState":"Running","Self":{"ID":"nSelf","TailscaleIPs":["100.64.0.1"],"CapMap":{"linuskendall.com/cap/tailbeam-node":[{"mode":"enforce"}]}},"Peer":{}}`
	s, err := mockLocal(t, "/localapi/v0/status", body).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m, err := NodeMode(s.Self.CapMap); err != nil || m != ModeEnforce {
		t.Fatalf("mode %v %v", m, err)
	}
}

package e2e

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func testBinding(c Code) Binding {
	return Binding{SenderID: "nSENDERCNTRL", ReceiverID: "nRECVRCNTRL", OfferID: c.OfferID()}
}

// handshake runs msg1, msg2 and the confirmation, returning the receiver's
// view of the payload.
func handshake(sCode, rCode Code, sBind, rBind Binding, payload []byte) ([]byte, error) {
	init, msg1, err := Hello(rCode, rBind)
	if err != nil {
		return nil, err
	}
	p, msg2, err := Respond(sCode, sBind, msg1, payload)
	if err != nil {
		return nil, err
	}
	got, err := init.Finish(msg2)
	if err != nil {
		return nil, err
	}
	sid := []byte("session-handle")
	confirm, err := init.Confirmation(sid)
	if err != nil {
		return nil, err
	}
	return got, p.Confirm(sid, confirm)
}

func TestProtocolName(t *testing.T) {
	if got := ProtocolName(); got != "Noise_NNpsk0_25519_ChaChaPoly_SHA256" {
		t.Fatalf("protocol name %q", got)
	}
}

type fixedRand struct{ b []byte }

func (r *fixedRand) Read(p []byte) (int, error) {
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNoiseVector runs our handshake configuration against the
// Noise_NNpsk0_25519_ChaChaPoly_SHA256 test vector shipped with flynn/noise
// (vectors.txt), pinning the pattern, PSK placement and cipher suite.
func TestNoiseVector(t *testing.T) {
	psk := unhex(t, "2176657279736563726574766572797365637265747665727973656372657421")
	ie := &fixedRand{unhex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")}
	re := &fixedRand{unhex(t, "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60")}
	init, err := newHandshake(psk, nil, true, ie)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newHandshake(psk, nil, false, re)
	if err != nil {
		t.Fatal(err)
	}
	msg0, _, _, err := init.WriteMessage(nil, nil)
	if err != nil || !bytes.Equal(msg0, unhex(t, "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254e7136508cb8178281204abd62e9f2a3e")) {
		t.Fatalf("msg0 %x %v", msg0, err)
	}
	if _, _, _, err := resp.ReadMessage(nil, msg0); err != nil {
		t.Fatal(err)
	}
	msg1, rRecv, _, err := resp.WriteMessage(nil, nil)
	if err != nil || !bytes.Equal(msg1, unhex(t, "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466922f3b7824001193c077abd8b7a73030")) {
		t.Fatalf("msg1 %x %v", msg1, err)
	}
	_, iSend, _, err := init.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := iSend.Encrypt(nil, nil, unhex(t, "79656c6c6f777375626d6172696e65"))
	if err != nil || !bytes.Equal(msg2, unhex(t, "b349a522c145762c7c737ac1d1425ce1fb25c7cca626177ee4ceed3cd6fb3d")) {
		t.Fatalf("msg2 %x %v", msg2, err)
	}
	if _, err := rRecv.Decrypt(nil, nil, msg2); err != nil {
		t.Fatal(err)
	}
}

func TestCodeRoundTrip(t *testing.T) {
	c, _ := NewCode()
	s := c.String()
	if len(s) != 34 || strings.Count(s, "-") != 6 {
		t.Fatalf("unexpected format %q", s)
	}
	got, err := ParseCode(strings.ToUpper(s))
	if err != nil || got != c {
		t.Fatal(err)
	}
	typo := []byte(s)
	typo[0] ^= 1
	if _, err := ParseCode(string(typo)); err == nil {
		t.Fatal("typo accepted")
	}
}

func TestOfferIDIsOneWayAndDistinct(t *testing.T) {
	c, _ := NewCode()
	id := c.OfferID()
	if len(id) != 32 || bytes.Equal(id, c.psk()) || bytes.Contains(id, c[:]) {
		t.Fatal("offer ID must be a distinct 32-byte derivation")
	}
	d, _ := NewCode()
	if bytes.Equal(id, d.OfferID()) {
		t.Fatal("different codes share an offer ID")
	}
}

func TestSplitTarget(t *testing.T) {
	c, _ := NewCode()
	for _, tc := range []struct {
		arg, host string
		code, bad bool
	}{
		{"laptop", "laptop", false, false},
		{"laptop.tail1234.ts.net:" + c.String(), "laptop.tail1234.ts.net", true, false},
		{"100.101.102.103:" + c.String(), "100.101.102.103", true, false},
		{"fd7a:115c:a1e0::1", "fd7a:115c:a1e0::1", false, false},
		{"[fd7a:115c:a1e0::1]:" + c.String(), "fd7a:115c:a1e0::1", true, false},
		{"[fd7a:115c:a1e0::1]", "fd7a:115c:a1e0::1", false, false},
		{c.String(), "", true, false},
		{strings.ToUpper(c.String()), "", true, false},
		{"laptop:8784", "", false, true},
		{"100.101.102.103:8784", "", false, true},
		{"[fd7a:115c:a1e0::1]:8784", "", false, true},
		{"[fd7a:115c:a1e0::1", "", false, true},
	} {
		host, code, err := SplitTarget(tc.arg)
		if (err != nil) != tc.bad || host != tc.host || (code != nil) != tc.code {
			t.Errorf("%q: host=%q code=%v err=%v", tc.arg, host, code != nil, err)
		}
		if code != nil && *code != c {
			t.Errorf("%q: wrong code", tc.arg)
		}
	}
	if _, _, err := SplitTarget("laptop:8784"); err == nil || !strings.Contains(err.Error(), "--port") {
		t.Errorf("port hint missing: %v", err)
	}
}

func TestHandshake(t *testing.T) {
	c, _ := NewCode()
	b := testBinding(c)
	got, err := handshake(c, c, b, b, []byte("offer"))
	if err != nil || string(got) != "offer" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestHandshakeRejects(t *testing.T) {
	c, _ := NewCode()
	other, _ := NewCode()
	b := testBinding(c)
	for name, tc := range map[string]struct {
		rCode Code
		rBind Binding
	}{
		"wrong code":            {other, b},
		"code of another offer": {other, testBinding(other)},
		"wrong receiver ID":     {c, Binding{b.SenderID, "nOTHERCNTRL", b.OfferID}},
		"wrong sender ID":       {c, Binding{"nOTHERCNTRL", b.ReceiverID, b.OfferID}},
		"wrong offer ID":        {c, Binding{b.SenderID, b.ReceiverID, other.OfferID()}},
	} {
		init, msg1, err := Hello(tc.rCode, tc.rBind)
		if err != nil {
			t.Fatal(err)
		}
		// The sender must refuse msg1 and send nothing back.
		if _, msg2, err := Respond(c, b, msg1, []byte("secret name")); err == nil || msg2 != nil {
			t.Errorf("%s: sender accepted msg1", name)
		}
		_ = init
	}
}

func TestConfirmationBinding(t *testing.T) {
	c, _ := NewCode()
	b := testBinding(c)
	init, msg1, _ := Hello(c, b)
	p, msg2, err := Respond(c, b, msg1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := init.Finish(msg2); err != nil {
		t.Fatal(err)
	}
	confirm, _ := init.Confirmation([]byte("sid-A"))
	if p.Confirm([]byte("sid-B"), confirm) == nil {
		t.Fatal("confirmation accepted for another session handle")
	}
	// A forged confirmation from someone without the transport key fails.
	init2, msg1b, _ := Hello(c, b)
	p2, msg2b, _ := Respond(c, b, msg1b, nil)
	init2.Finish(msg2b)
	if p2.Confirm([]byte("sid"), bytes.Repeat([]byte{1}, 40)) == nil {
		t.Fatal("forged confirmation accepted")
	}
}

func TestChunks(t *testing.T) {
	fk, _ := NewFileKey()
	k, err := DeriveKeys(fk)
	if err != nil {
		t.Fatal(err)
	}
	id, root := []byte("offer-id"), []byte("root")
	pt := []byte("chunk zero data")
	sealed, _ := k.SealChunk(id, root, 0, false, pt)
	again, _ := k.SealChunk(id, root, 0, false, pt)
	if bytes.Equal(sealed, again) {
		t.Fatal("nonce reused across seals")
	}
	if got, err := k.OpenChunk(nil, id, root, 0, len(pt), false, sealed); err != nil || !bytes.Equal(got, pt) {
		t.Fatal(err)
	}
	other, _ := NewFileKey()
	k2, _ := DeriveKeys(other)
	for name, open := range map[string]func() ([]byte, error){
		"index":     func() ([]byte, error) { return k.OpenChunk(nil, id, root, 1, len(pt), false, sealed) },
		"last flag": func() ([]byte, error) { return k.OpenChunk(nil, id, root, 0, len(pt), true, sealed) },
		"size":      func() ([]byte, error) { return k.OpenChunk(nil, id, root, 0, len(pt)-1, false, sealed[:len(sealed)-1]) },
		"root":      func() ([]byte, error) { return k.OpenChunk(nil, id, []byte("other"), 0, len(pt), false, sealed) },
		"offer":     func() ([]byte, error) { return k.OpenChunk(nil, []byte("other"), root, 0, len(pt), false, sealed) },
		"session":   func() ([]byte, error) { return k2.OpenChunk(nil, id, root, 0, len(pt), false, sealed) },
		"bit flip": func() ([]byte, error) {
			bad := bytes.Clone(sealed)
			bad[len(bad)-1] ^= 1
			return k.OpenChunk(nil, id, root, 0, len(pt), false, bad)
		},
	} {
		if _, err := open(); err == nil {
			t.Errorf("%s: tampered chunk accepted", name)
		}
	}
	m, _ := k.SealManifest(id, root, []byte("hashes"))
	if _, err := k.OpenManifest(id, root, m); err != nil {
		t.Fatal(err)
	}
	if _, err := k.OpenChunk(nil, id, root, 0, len(m)-Overhead, false, m); err == nil {
		t.Fatal("manifest accepted as a chunk")
	}
	if !k.VerifyAck(id, root, k.AckTag(id, root)) || k2.VerifyAck(id, root, k.AckTag(id, root)) {
		t.Fatal("ack tag")
	}
}

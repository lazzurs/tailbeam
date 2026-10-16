package e2e

import (
	"bytes"
	"strings"
	"testing"
)

var bind = Binding{SenderID: "nSENDERCNTRL", ReceiverID: "nRECVRCNTRL", OfferID: "0123abcd"}

func handshake(t *testing.T, sCode, rCode Code, sBind, rBind Binding) (*Session, *Session, error) {
	t.Helper()
	priv, hello, err := NewHello()
	if err != nil {
		t.Fatal(err)
	}
	ss, reply, err := Respond(sCode, sBind, hello)
	if err != nil {
		t.Fatal(err)
	}
	rs, confirm, err := Finish(rCode, rBind, priv, hello, reply)
	if err != nil {
		return nil, nil, err
	}
	if err := ss.VerifyReceiver(confirm); err != nil {
		t.Fatal(err)
	}
	return ss, rs, nil
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
		{"laptop:8784", "", false, true},
	} {
		host, code, err := SplitTarget(tc.arg)
		if (err != nil) != tc.bad || host != tc.host || (code != nil) != tc.code {
			t.Errorf("%q: host=%q code=%v err=%v", tc.arg, host, code != nil, err)
		}
		if code != nil && *code != c {
			t.Errorf("%q: wrong code", tc.arg)
		}
	}
}

func TestHandshakeAndChunks(t *testing.T) {
	c, _ := NewCode()
	ss, rs, err := handshake(t, c, c, bind, bind)
	if err != nil {
		t.Fatal(err)
	}
	if ss.ID != rs.ID {
		t.Fatal("session IDs differ")
	}
	root := bytes.Repeat([]byte{7}, 32)
	chunk := bytes.Repeat([]byte("data"), 1000)
	sealed, err := ss.SealChunk(root, 3, false, chunk)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ss.SealChunk(root, 3, false, chunk)
	if bytes.Equal(sealed, again) {
		t.Fatal("nonce reused for re-served chunk")
	}
	got, err := rs.OpenChunk(root, 3, len(chunk), false, sealed)
	if err != nil || !bytes.Equal(got, chunk) {
		t.Fatal("chunk did not open", err)
	}
	for name, open := range map[string]func() error{
		"index":     func() error { _, e := rs.OpenChunk(root, 4, len(chunk), false, sealed); return e },
		"last flag": func() error { _, e := rs.OpenChunk(root, 3, len(chunk), true, sealed); return e },
		"size":      func() error { _, e := rs.OpenChunk(root, 3, len(chunk)-1, false, sealed); return e },
		"root":      func() error { _, e := rs.OpenChunk(make([]byte, 32), 3, len(chunk), false, sealed); return e },
		"tamper": func() error {
			bad := bytes.Clone(sealed)
			bad[len(bad)-1] ^= 1
			_, e := rs.OpenChunk(root, 3, len(chunk), false, bad)
			return e
		},
	} {
		if open() == nil {
			t.Errorf("%s change accepted", name)
		}
	}
	meta, _ := ss.SealMeta("offer", []byte(`{"name":"secret.pdf"}`))
	if _, err := rs.OpenMeta("manifest", meta); err == nil {
		t.Fatal("offer accepted as manifest")
	}
	if p, err := rs.OpenMeta("offer", meta); err != nil || string(p) != `{"name":"secret.pdf"}` {
		t.Fatal("offer did not open")
	}
	if !bytes.Equal(ss.AckTag(root), rs.AckTag(root)) {
		t.Fatal("ack tags differ")
	}
}

func TestHandshakeRejects(t *testing.T) {
	c, _ := NewCode()
	other, _ := NewCode()
	if _, _, err := handshake(t, c, other, bind, bind); err == nil {
		t.Fatal("wrong code accepted")
	}
	for _, b := range []Binding{
		{bind.SenderID, "nOTHERCNTRL", bind.OfferID},
		{"nOTHERCNTRL", bind.ReceiverID, bind.OfferID},
		{bind.SenderID, bind.ReceiverID, "ffff"},
	} {
		if _, _, err := handshake(t, c, c, bind, b); err == nil {
			t.Fatalf("binding mismatch accepted: %+v", b)
		}
	}
	// Separate sessions with the same code have independent keys.
	s1, _, _ := handshake(t, c, c, bind, bind)
	_, r2, _ := handshake(t, c, c, bind, bind)
	sealed, _ := s1.SealChunk(nil, 0, true, []byte("x"))
	if _, err := r2.OpenChunk(nil, 0, 1, true, sealed); err == nil {
		t.Fatal("chunk replayed across sessions")
	}
	if _, _, err := Respond(c, bind, Hello{make([]byte, 32)}); err == nil {
		t.Fatal("low-order point accepted")
	}
}

package e2e

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const protocolLabel = "tailbeam-e2e-v1"

// Binding names the parties and offer. Every value is mixed into the
// transcript, so a code cannot be replayed against another node or offer.
// Node IDs are Tailscale stable IDs from the local daemon, never from the peer.
type Binding struct {
	SenderID   string
	ReceiverID string
	OfferID    string
}

// Hello is the receiver's first message (POST /v2/e2e/hello).
type Hello struct{ Ephemeral []byte }

// Reply is the sender's answer: its ephemeral key and proof it knows the code.
type Reply struct {
	Ephemeral []byte
	Confirm   []byte
}

// Session holds the keys for one handshake. A resumed transfer runs a new
// handshake; the receiver keeps verified plaintext chunks, never keys.
type Session struct {
	ID         [16]byte // derived, never sent before the receiver has it
	transcript [32]byte
	confirmS   []byte
	confirmR   []byte
	metaKey    []byte
	dataKey    []byte
	ackKey     []byte
}

func transcript(b Binding, eR, eS []byte) [32]byte {
	h := sha256.New()
	for _, v := range [][]byte{[]byte(protocolLabel), []byte(b.SenderID), []byte(b.ReceiverID), []byte(b.OfferID), eR, eS} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		h.Write(n[:])
		h.Write(v)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func derive(code Code, b Binding, priv *ecdh.PrivateKey, peer, eR, eS []byte) (*Session, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	// ECDH rejects low-order points (all-zero shared secret).
	dh, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	th := transcript(b, eR, eS)
	prk, err := hkdf.Extract(sha256.New, append(dh, code[:]...), th[:])
	if err != nil {
		return nil, err
	}
	s := &Session{transcript: th}
	for _, k := range []struct {
		dst  *[]byte
		info string
	}{{&s.confirmS, "confirm sender"}, {&s.confirmR, "confirm receiver"}, {&s.metaKey, "metadata"}, {&s.dataKey, "chunk data"}, {&s.ackKey, "ack"}} {
		if *k.dst, err = hkdf.Expand(sha256.New, prk, protocolLabel+" "+k.info, 32); err != nil {
			return nil, err
		}
	}
	id, err := hkdf.Expand(sha256.New, prk, protocolLabel+" session id", 16)
	if err != nil {
		return nil, err
	}
	copy(s.ID[:], id)
	return s, nil
}

func mac(key []byte, th [32]byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(th[:])
	return m.Sum(nil)
}

// NewHello starts a receiver handshake.
func NewHello() (*ecdh.PrivateKey, Hello, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, Hello{}, err
	}
	return k, Hello{k.PublicKey().Bytes()}, nil
}

// Respond runs on the sender. The session is unconfirmed until
// VerifyReceiver succeeds; the caller must count failures and burn the offer.
func Respond(code Code, b Binding, h Hello) (*Session, Reply, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, Reply{}, err
	}
	eS := k.PublicKey().Bytes()
	s, err := derive(code, b, k, h.Ephemeral, h.Ephemeral, eS)
	if err != nil {
		return nil, Reply{}, err
	}
	return s, Reply{eS, mac(s.confirmS, s.transcript)}, nil
}

// Finish runs on the receiver. It authenticates the sender and returns the
// receiver's confirmation (POST /v2/e2e/confirm).
func Finish(code Code, b Binding, priv *ecdh.PrivateKey, h Hello, r Reply) (*Session, []byte, error) {
	s, err := derive(code, b, priv, r.Ephemeral, h.Ephemeral, r.Ephemeral)
	if err != nil {
		return nil, nil, err
	}
	if !hmac.Equal(r.Confirm, mac(s.confirmS, s.transcript)) {
		return nil, nil, errors.New("sender does not know the transfer code (or wrong peer/offer)")
	}
	return s, mac(s.confirmR, s.transcript), nil
}

// VerifyReceiver runs on the sender.
func (s *Session) VerifyReceiver(confirm []byte) error {
	if !hmac.Equal(confirm, mac(s.confirmR, s.transcript)) {
		return errors.New("receiver does not know the transfer code")
	}
	return nil
}

// AckTag authenticates the final acknowledgement for a manifest root, so only
// the code holder can consume the offer.
func (s *Session) AckTag(root []byte) []byte {
	m := hmac.New(sha256.New, s.ackKey)
	m.Write([]byte("ack"))
	m.Write(root)
	return m.Sum(nil)
}

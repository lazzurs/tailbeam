package e2e

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"github.com/flynn/noise"
)

// The handshake is Noise NNpsk0 from github.com/flynn/noise: both sides send
// an ephemeral X25519 key, and the code-derived PSK is mixed in before the
// first message. Nothing in the handshake is hand-assembled here; this file
// only chooses the pattern and the prologue, and carries the payloads.
//
//	receiver -> sender  msg1: psk, e          (authenticated by the PSK)
//	sender -> receiver  msg2: e, ee + payload (offer metadata and file key)
//	receiver -> sender  confirm: transport message under the split keys
//
// A wrong code, node ID or offer ID changes the PSK or prologue, so the sender
// fails to read msg1 and never answers with metadata.

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// ProtocolName is the Noise protocol name flynn/noise derives from our
// configuration; it is hashed into every handshake.
func ProtocolName() string {
	return "Noise_" + noise.HandshakeNN.Name + "psk0_" + string(suite.Name())
}

// MaxPayload bounds a handshake payload (Noise's own limit is 65535 bytes).
const MaxPayload = 16 << 10

const confirmText = Label + " confirm"

// Binding names the parties and the offer. It is the Noise prologue, so both
// sides must agree on every field. Each side takes the stable node IDs from its
// own Tailscale daemon (Status/WhoIs), never from the peer.
type Binding struct {
	SenderID   string
	ReceiverID string
	OfferID    []byte
}

func (b Binding) prologue() []byte {
	var out []byte
	for _, v := range [][]byte{[]byte(Label), []byte(b.SenderID), []byte(b.ReceiverID), b.OfferID} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	return out
}

func newHandshake(psk, prologue []byte, initiator bool, rng io.Reader) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:           suite,
		Random:                rng,
		Pattern:               noise.HandshakeNN,
		Initiator:             initiator,
		Prologue:              prologue,
		PresharedKey:          psk,
		PresharedKeyPlacement: 0,
	})
}

var errHandshake = errors.New("handshake failed: wrong transfer code, peer or offer")

// Initiator is the receiver's side of one handshake.
type Initiator struct {
	hs   *noise.HandshakeState
	send *noise.CipherState
}

// Hello starts a receiver handshake and returns msg1.
func Hello(code Code, b Binding) (*Initiator, []byte, error) {
	hs, err := newHandshake(code.psk(), b.prologue(), true, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	return &Initiator{hs: hs}, msg, nil
}

// Finish reads msg2, authenticating the sender as a holder of the code, and
// returns its payload.
func (i *Initiator) Finish(msg2 []byte) ([]byte, error) {
	if i.send != nil {
		return nil, errors.New("handshake already finished")
	}
	payload, send, _, err := i.hs.ReadMessage(nil, msg2)
	if err != nil || send == nil {
		return nil, errHandshake
	}
	i.send = send
	return payload, nil
}

// Confirmation returns the receiver's confirmation for the sender's session
// handle sid, encrypted under the post-handshake transport key.
func (i *Initiator) Confirmation(sid []byte) ([]byte, error) {
	if i.send == nil {
		return nil, errors.New("handshake not finished")
	}
	return i.send.Encrypt(nil, sid, []byte(confirmText))
}

// Pending is a sender-side handshake waiting for the receiver's confirmation.
type Pending struct{ recv *noise.CipherState }

// Respond reads msg1 and answers with payload. It fails without revealing
// anything when the receiver used a different code or binding.
func Respond(code Code, b Binding, msg1, payload []byte) (*Pending, []byte, error) {
	if len(payload) > MaxPayload {
		return nil, nil, errors.New("handshake payload too large")
	}
	hs, err := newHandshake(code.psk(), b.prologue(), false, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, nil, errHandshake
	}
	// flynn/noise returns the split CipherStates in initiator-to-responder,
	// responder-to-initiator order on both sides; the first one carries the
	// receiver's confirmation.
	msg2, recv, _, err := hs.WriteMessage(nil, payload)
	if err != nil || recv == nil {
		return nil, nil, errors.New("handshake did not complete")
	}
	return &Pending{recv}, msg2, nil
}

// Confirm checks the receiver's confirmation for session sid. A Pending is
// single-use: the transport nonce has advanced after any call.
func (p *Pending) Confirm(sid, confirm []byte) error {
	got, err := p.recv.Decrypt(nil, sid, confirm)
	if err != nil || subtle.ConstantTimeCompare(got, []byte(confirmText)) != 1 {
		return errHandshake
	}
	return nil
}

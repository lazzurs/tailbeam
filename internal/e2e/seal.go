package e2e

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Chunks and the manifest use XChaCha20-Poly1305 under keys derived from a
// random per-session file key, which the sender delivers inside the Noise
// handshake. Each seal takes a fresh random 192-bit nonce, so re-serving a
// chunk (retry, resume, parallel fetch) never reuses a nonce, even if the
// source changed. The associated data binds the offer ID, manifest root, chunk
// index, length and last-chunk flag, so chunks cannot be reordered, truncated
// or moved to another offer. Noise's own transport is not used for data: its
// counter nonces require in-order delivery and its messages cap at 64 KiB.

// FileKeySize is the length of the per-session file key.
const FileKeySize = 32

// Overhead is the ciphertext expansion of one sealed chunk or manifest.
const Overhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead

var errOpen = errors.New("sealed data failed authentication")

// Keys are the data keys for one session.
type Keys struct {
	manifest []byte
	chunk    []byte
	ack      []byte
}

// NewFileKey returns a fresh random file key.
func NewFileKey() ([]byte, error) {
	k := make([]byte, FileKeySize)
	_, err := rand.Read(k)
	return k, err
}

// DeriveKeys expands a file key into separate manifest, chunk and ack keys.
func DeriveKeys(fileKey []byte) (Keys, error) {
	if len(fileKey) != FileKeySize {
		return Keys{}, errors.New("invalid file key")
	}
	return Keys{derive(fileKey, "manifest"), derive(fileKey, "chunk"), derive(fileKey, "ack")}, nil
}

func ad(kind string, offerID, root []byte, fields ...uint64) []byte {
	out := []byte(Label + " " + kind)
	for _, v := range [][]byte{offerID, root} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	for _, f := range fields {
		out = binary.BigEndian.AppendUint64(out, f)
	}
	return out
}

func chunkAD(offerID, root []byte, index uint64, size int, last bool) []byte {
	var l uint64
	if last {
		l = 1
	}
	return ad("chunk", offerID, root, index, uint64(size), l)
}

func seal(key, ad, plaintext []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, a.NonceSize(), a.NonceSize()+len(plaintext)+a.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return a.Seal(out, out, plaintext, ad), nil
}

func open(dst, key, ad, sealed []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < a.NonceSize()+a.Overhead() {
		return nil, errOpen
	}
	p, err := a.Open(dst, sealed[:a.NonceSize()], sealed[a.NonceSize():], ad)
	if err != nil {
		return nil, errOpen
	}
	return p, nil
}

// SealChunk encrypts chunk index of the offer with the given manifest root.
func (k Keys) SealChunk(offerID, root []byte, index uint64, last bool, plaintext []byte) ([]byte, error) {
	return seal(k.chunk, chunkAD(offerID, root, index, len(plaintext), last), plaintext)
}

// OpenChunk decrypts a chunk into dst[:0]; size is the expected plaintext
// length from the offer. The caller still checks the manifest hash.
func (k Keys) OpenChunk(dst, offerID, root []byte, index uint64, size int, last bool, sealed []byte) ([]byte, error) {
	if len(sealed) != size+Overhead {
		return nil, errOpen
	}
	p, err := open(dst[:0], k.chunk, chunkAD(offerID, root, index, size, last), sealed)
	if err != nil || len(p) != size {
		return nil, errOpen
	}
	return p, nil
}

// SealManifest encrypts the chunk hash list.
func (k Keys) SealManifest(offerID, root, manifest []byte) ([]byte, error) {
	return seal(k.manifest, ad("manifest", offerID, root), manifest)
}

func (k Keys) OpenManifest(offerID, root, sealed []byte) ([]byte, error) {
	return open(nil, k.manifest, ad("manifest", offerID, root), sealed)
}

// AckTag authenticates the final acknowledgement, so only the session that
// received the file can consume the offer.
func (k Keys) AckTag(offerID, root []byte) []byte {
	m := hmac.New(sha256.New, k.ack)
	m.Write(ad("ack", offerID, root))
	return m.Sum(nil)
}

// VerifyAck checks an AckTag in constant time.
func (k Keys) VerifyAck(offerID, root, tag []byte) bool {
	return hmac.Equal(tag, k.AckTag(offerID, root))
}

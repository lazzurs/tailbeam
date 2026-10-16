package e2e

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Chunks use XChaCha20-Poly1305 with a fresh random 192-bit nonce per seal, so
// re-serving a chunk (retry, resume, parallel fetch) can never reuse a nonce,
// even if the source changed. The AAD binds transcript, manifest root, index,
// length and last-chunk flag: chunks cannot be reordered, truncated, moved to
// another offer or replayed into another session.

var errOpen = errors.New("chunk failed authentication")

func chunkAD(s *Session, root []byte, index uint64, size int, last bool) []byte {
	ad := make([]byte, 0, 5+32+len(root)+17)
	ad = append(ad, "chunk"...)
	ad = append(ad, s.transcript[:]...)
	ad = append(ad, root...)
	ad = binary.BigEndian.AppendUint64(ad, index)
	ad = binary.BigEndian.AppendUint64(ad, uint64(size))
	if last {
		return append(ad, 1)
	}
	return append(ad, 0)
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

func open(key, ad, sealed []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < a.NonceSize()+a.Overhead() {
		return nil, errOpen
	}
	p, err := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], ad)
	if err != nil {
		return nil, errOpen
	}
	return p, nil
}

// SealChunk encrypts chunk index of the manifest with the given root. The
// sender must verify the plaintext against the manifest hash first.
func (s *Session) SealChunk(root []byte, index uint64, last bool, plaintext []byte) ([]byte, error) {
	return seal(s.dataKey, chunkAD(s, root, index, len(plaintext), last), plaintext)
}

// OpenChunk decrypts a chunk; size is the expected plaintext length from the
// manifest. The caller still checks the plaintext hash before marking it done.
func (s *Session) OpenChunk(root []byte, index uint64, size int, last bool, sealed []byte) ([]byte, error) {
	p, err := open(s.dataKey, chunkAD(s, root, index, size, last), sealed)
	if err != nil || len(p) != size {
		return nil, errOpen
	}
	return p, nil
}

// SealMeta encrypts the offer (name, size, root, chunk size) or the manifest.
// label separates the two ("offer", "manifest").
func (s *Session) SealMeta(label string, plaintext []byte) ([]byte, error) {
	return seal(s.metaKey, append([]byte(label), s.transcript[:]...), plaintext)
}

func (s *Session) OpenMeta(label string, sealed []byte) ([]byte, error) {
	return open(s.metaKey, append([]byte(label), s.transcript[:]...), sealed)
}

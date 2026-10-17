// Package e2e is tailbeam's end-to-end layer: a high-entropy transfer code, a
// Noise NNpsk0 handshake (github.com/flynn/noise) bound to both Tailscale
// stable node IDs and the offer, and per-chunk XChaCha20-Poly1305 that
// composes with chunked Range resume. See docs/e2e-encryption.md.
package e2e

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// Label prefixes every derivation, so no key or identifier derived here can
// collide with another.
const Label = "tailbeam-e2e-v1"

// OfferID is the public per-offer identifier, derived one-way from the code
// under its own label. It names the offer in URLs without revealing the code,
// so no plaintext endpoint is needed to discover it.
func (c Code) OfferID() []byte { return derive(c[:], "offer-id") }

// psk is the Noise pre-shared key.
func (c Code) psk() []byte { return derive(c[:], "psk") }

func derive(secret []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, Label+" "+info, 32)
	if err != nil {
		panic(err) // only possible for invalid lengths
	}
	return k
}

// CodeSize is the secret length: 128 bits, so offline guessing is infeasible
// and no PAKE is needed.
const CodeSize = 16

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Code is the shared transfer secret.
type Code [CodeSize]byte

func NewCode() (Code, error) {
	var c Code
	_, err := rand.Read(c[:])
	return c, err
}

// String renders 26 base32 characters plus a 2-character checksum, lowercase,
// in seven dash-separated groups of four: "mfrg-gzdf-…".
func (c Code) String() string {
	s := strings.ToLower(b32.EncodeToString(c[:]) + checksum(c))
	var groups []string
	for len(s) > 0 {
		groups = append(groups, s[:4])
		s = s[4:]
	}
	return strings.Join(groups, "-")
}

func checksum(c Code) string {
	h := sha256.Sum256(append([]byte("tailbeam code checksum"), c[:]...))
	return b32.EncodeToString(h[:2])[:2]
}

// ParseCode accepts the String form, ignoring case, dashes and spaces. The
// checksum catches typos before any network round trip spends an attempt.
func ParseCode(s string) (Code, error) {
	var c Code
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
	if len(s) != 28 {
		return c, errors.New("transfer code must be 28 characters")
	}
	b, err := b32.DecodeString(s[:26])
	if err != nil || len(b) != CodeSize {
		return c, errors.New("transfer code contains invalid characters")
	}
	copy(c[:], b)
	if subtle.ConstantTimeCompare([]byte(checksum(c)), []byte(s[26:])) != 1 {
		return Code{}, errors.New("transfer code checksum mismatch (typo?)")
	}
	return c, nil
}

// SplitTarget parses the receive argument HOST, HOST:CODE or a bare CODE (host
// ""). Only a suffix that is a well-formed code is split off, so a bare IPv6
// address is never mangled; IPv6 with a code must be bracketed:
// [fd7a:115c:a1e0::1]:CODE. HOST:PORT is rejected; ports use --port.
func SplitTarget(arg string) (host string, code *Code, err error) {
	if strings.HasPrefix(arg, "[") {
		end := strings.Index(arg, "]")
		if end < 0 {
			return "", nil, errors.New("missing ] in bracketed address")
		}
		host, rest := arg[1:end], arg[end+1:]
		if rest == "" {
			return host, nil, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", nil, errors.New("expected :CODE after bracketed address")
		}
		c, err := parseCodeSuffix(rest[1:])
		if err != nil {
			return "", nil, err
		}
		return host, &c, nil
	}
	i := strings.LastIndex(arg, ":")
	if i < 0 {
		// A bare code (no host) means: discover the sender.
		if c, err := ParseCode(arg); err == nil {
			return "", &c, nil
		}
		return arg, nil, nil
	}
	if strings.Count(arg, ":") > 1 {
		// Unbracketed IPv6; never guess where the address ends.
		return arg, nil, nil
	}
	c, err := parseCodeSuffix(arg[i+1:])
	if err != nil {
		return "", nil, err
	}
	return arg[:i], &c, nil
}

// parseCodeSuffix parses the text after HOST:, explaining the likely mistake
// of passing a port there.
func parseCodeSuffix(s string) (Code, error) {
	if s != "" && strings.Trim(s, "0123456789") == "" {
		return Code{}, errors.New("HOST:CODE expects a tailbeam transfer code after the colon, not a port (ports use --port)")
	}
	c, err := ParseCode(s)
	if err != nil {
		return Code{}, fmt.Errorf("HOST:CODE: %w", err)
	}
	return c, nil
}

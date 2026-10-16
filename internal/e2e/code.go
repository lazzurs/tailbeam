// Package e2e prototypes an optional end-to-end layer for tailbeam: a
// high-entropy transfer code, a PSK-authenticated ephemeral X25519 handshake
// bound to both Tailscale stable node IDs, and per-chunk AEAD that composes
// with chunked Range resume. See docs/e2e-encryption.md. Not wired into the CLI.
package e2e

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"strings"
)

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

// SplitTarget parses the receive argument HOST[:CODE]. Only a suffix that is a
// well-formed code is split off, so a bare IPv6 address is never mangled;
// IPv6 with a code must be bracketed: [fd7a:115c:a1e0::1]:CODE.
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
		c, err := ParseCode(rest[1:])
		if err != nil {
			return "", nil, err
		}
		return host, &c, nil
	}
	i := strings.LastIndex(arg, ":")
	if i < 0 {
		return arg, nil, nil
	}
	if strings.Count(arg, ":") > 1 {
		// Unbracketed IPv6; never guess where the address ends.
		return arg, nil, nil
	}
	c, err := ParseCode(arg[i+1:])
	if err != nil {
		return "", nil, errors.New("HOST:CODE expects a tailbeam transfer code after the colon (ports use --port)")
	}
	return arg[:i], &c, nil
}

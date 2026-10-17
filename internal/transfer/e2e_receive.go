package transfer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/linuskendall/tailbeam/internal/e2e"
)

// E2EOffer is an offer received through a completed, confirmed handshake.
// Name and Size were decrypted from the handshake and are validated.
type E2EOffer struct {
	Name    string
	Size    int64
	o       OfferV2
	sid     string
	keys    e2e.Keys
	offerID []byte
	root    []byte
}

func e2eRequest(ctx context.Context, c *http.Client, method, u string, body []byte, want int) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	r.Header.Set(browserGuardHeader, browserGuardValue)
	if body != nil {
		r.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := c.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != want {
		resp.Body.Close()
		if err := modeError(resp, modePlaintext); err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusGone {
			return nil, ErrOfferGone
		}
		return nil, statusError(resp.StatusCode)
	}
	return resp, nil
}

// FetchE2EOffer runs the handshake for code against the sender at base and
// confirms it. senderID and receiverID are stable node IDs from the local
// daemon: the pinned sender and this node.
func FetchE2EOffer(ctx context.Context, c *http.Client, base string, code e2e.Code, senderID, receiverID string) (*E2EOffer, error) {
	id := code.OfferID()
	prefix := base + "/e2e/" + hex.EncodeToString(id) + "/"
	init, msg1, err := e2e.Hello(code, e2e.Binding{SenderID: senderID, ReceiverID: receiverID, OfferID: id})
	if err != nil {
		return nil, err
	}
	r, err := e2eRequest(ctx, c, "POST", prefix+"hello", msg1, http.StatusOK)
	if err != nil {
		return nil, err
	}
	msg2, err := io.ReadAll(io.LimitReader(r.Body, e2e.MaxPayload+1024))
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	payload, err := init.Finish(msg2)
	if err != nil {
		return nil, errors.New("sender failed the handshake: it does not know the transfer code, or is not the expected node")
	}
	var p e2eOffer
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	o := OfferV2{2, hex.EncodeToString(id), p.Name, p.Size, p.ChunkSize, p.Hash, p.Root}
	if err := validateOfferV2(o); err != nil {
		return nil, err
	}
	sid, err := hex.DecodeString(p.SID)
	if err != nil || len(sid) != e2eSIDSize {
		return nil, errors.New("invalid session handle")
	}
	keys, err := e2e.DeriveKeys(p.FileKey)
	if err != nil {
		return nil, err
	}
	confirm, err := init.Confirmation(sid)
	if err != nil {
		return nil, err
	}
	r, err = e2eRequest(ctx, c, "POST", prefix+"confirm", append(sid, confirm...), http.StatusNoContent)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	root, _ := hex.DecodeString(o.Root)
	return &E2EOffer{Name: o.Name, Size: o.Size, o: o, sid: p.SID, keys: keys, offerID: id, root: root}, nil
}

// Download fetches, verifies and publishes the file, resuming from verified
// chunks of an earlier attempt (in either mode) with the same sender, name and
// root. sender is the sender's stable node ID.
func (e *E2EOffer) Download(ctx context.Context, c *http.Client, base, sender, dir string, maxBytes int64, idle time.Duration) (string, error) {
	return downloadChunked(ctx, e.o, sender, dir, maxBytes, idle, &e2eSource{e: e, c: c, base: base})
}

type e2eSource struct {
	e      *E2EOffer
	c      *http.Client
	base   string
	sealed []byte
	plain  []byte
}

func (s *e2eSource) url(action string, q url.Values) string {
	q.Set("sid", s.e.sid)
	return s.base + "/e2e/" + s.e.o.ID + "/" + action + "?" + q.Encode()
}

func (s *e2eSource) manifest(ctx context.Context) ([]byte, error) {
	o := s.e.o
	want := o.chunks() * v2ChunkHashSize
	r, err := e2eRequest(ctx, s.c, "GET", s.url("manifest", url.Values{}), nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.ContentLength != want+e2e.Overhead {
		return nil, errors.New("manifest length does not match offer")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, want+e2e.Overhead+1))
	if err != nil {
		return nil, err
	}
	m, err := s.e.keys.OpenManifest(s.e.offerID, s.e.root, b)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if int64(len(m)) != want || hex.EncodeToString(v2Root(o.Size, o.ChunkSize, m)) != o.Root {
		return nil, errors.New("manifest does not match offer root")
	}
	return m, nil
}

func (s *e2eSource) request(ctx context.Context, first, last int64) (io.ReadCloser, error) {
	q := url.Values{"first": {fmt.Sprint(first)}, "last": {fmt.Sprint(last)}}
	r, err := e2eRequest(ctx, s.c, "GET", s.url("chunks", q), nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if r.ContentLength != e2eSealedLen(s.e.o, first, last) {
		r.Body.Close()
		return nil, errors.New("peer returned the wrong chunk range")
	}
	return r.Body, nil
}

func (s *e2eSource) readChunk(body io.Reader, i, n int64, w io.Writer) error {
	o := s.e.o
	if s.sealed == nil {
		s.sealed = make([]byte, o.ChunkSize+e2e.Overhead)
		s.plain = make([]byte, o.ChunkSize)
	}
	sealed := s.sealed[:n+e2e.Overhead]
	if _, err := io.ReadFull(body, sealed); err != nil {
		return err
	}
	p, err := s.e.keys.OpenChunk(s.plain, s.e.offerID, s.e.root, uint64(i), int(n), i == o.chunks()-1, sealed)
	if err != nil {
		return err
	}
	_, err = w.Write(p)
	return err
}

func (s *e2eSource) ack(ctx context.Context) error {
	r, err := e2eRequest(ctx, s.c, "POST", s.url("ack", url.Values{}), s.e.keys.AckTag(s.e.offerID, s.e.root), http.StatusNoContent)
	if err != nil {
		return err
	}
	return r.Body.Close()
}

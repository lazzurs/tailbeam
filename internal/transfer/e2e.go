package transfer

// End-to-end encrypted mode (the default). The offer is the v2 chunked offer,
// but nothing about it is served in plaintext: the receiver proves knowledge of
// the transfer code in a Noise NNpsk0 handshake, the sender answers with the
// offer and a fresh file key inside the handshake, and the manifest and every
// chunk are sealed under keys derived from that file key. The offer ID in the
// URL is derived one-way from the code. See docs/e2e-encryption.md.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/linuskendall/tailbeam/internal/e2e"
)

const (
	modeHeader    = "X-Tailbeam-Mode"
	modePlaintext = "plaintext"
	modeE2E       = "e2e"

	e2eMaxAttempts = 3           // handshakes without a valid confirmation before the offer burns
	e2ePendingTTL  = time.Minute // an unconfirmed handshake counts as failed after this long
	e2eMaxSessions = 8           // confirmed sessions kept per offer
	e2eMaxBody     = 1 << 10     // hello, confirm and ack bodies
	e2eSIDSize     = 16
)

var (
	// ErrModeMismatch means the sender and receiver disagree on --plaintext.
	ErrModeMismatch    = errors.New("encryption mode mismatch")
	ErrSenderEncrypted = fmt.Errorf("%w: the sender offers an end-to-end encrypted transfer; run receive without --plaintext and use its transfer code", ErrModeMismatch)
	ErrSenderPlaintext = fmt.Errorf("%w: the sender offers a plaintext (not end-to-end encrypted) transfer; rerun receive with --plaintext if that is acceptable", ErrModeMismatch)
	// ErrOfferGone means the offer was completed or burned; retrying cannot help.
	ErrOfferGone = errors.New("the offer is no longer available (completed, or burned after failed code attempts)")
	// ErrOfferBurned is returned by ServeE2E after too many failed handshakes.
	ErrOfferBurned = fmt.Errorf("offer burned after %d failed transfer-code attempts; start a new send", e2eMaxAttempts)
)

// notFound answers an unknown path for an authenticated peer, naming this
// sender's mode so a receiver in the other mode can say so instead of hanging.
func notFound(w http.ResponseWriter, r *http.Request, mode string) {
	w.Header().Set(modeHeader, mode)
	http.NotFound(w, r)
}

// modeError reports a 404 that names the other mode.
func modeError(resp *http.Response, other string) error {
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get(modeHeader) != other {
		return nil
	}
	if other == modeE2E {
		return ErrSenderEncrypted
	}
	return ErrSenderPlaintext
}

// e2eOffer is the handshake payload from sender to receiver.
type e2eOffer struct {
	SID       string `json:"sid"`
	FileKey   []byte `json:"file_key"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ChunkSize int64  `json:"chunk_size"`
	Hash      string `json:"hash"`
	Root      string `json:"root"`
}

type e2ePending struct {
	p       *e2e.Pending
	keys    e2e.Keys
	created time.Time
}

type SenderE2E struct {
	core    *SenderV2
	code    e2e.Code
	bind    e2e.Binding
	offerID []byte
	root    []byte

	mu       sync.Mutex
	failures int
	pending  map[string]*e2ePending
	sessions map[string]e2e.Keys
	order    []string // confirmed session IDs, oldest first
	burned   chan struct{}
	now      func() time.Time
}

// NewSenderE2E hashes the file and prepares an encrypted offer for code,
// bound to the sender's and receiver's stable node IDs (from the local daemon).
func NewSenderE2E(ctx context.Context, path string, authorize Authorize, code e2e.Code, senderID, receiverID, cacheDir string) (*SenderE2E, error) {
	return newSenderE2E(ctx, path, authorize, code, senderID, receiverID, 0, cacheDir)
}

func newSenderE2E(ctx context.Context, path string, authorize Authorize, code e2e.Code, senderID, receiverID string, chunk int64, cacheDir string) (*SenderE2E, error) {
	if senderID == "" || receiverID == "" {
		return nil, errors.New("missing node identity")
	}
	core, err := newSenderV2(ctx, path, authorize, chunk, cacheDir)
	if err != nil {
		return nil, err
	}
	id := code.OfferID()
	core.Offer.ID = hex.EncodeToString(id)
	root, _ := hex.DecodeString(core.Offer.Root)
	return &SenderE2E{
		core: core, code: code, offerID: id, root: root,
		bind:     e2e.Binding{SenderID: senderID, ReceiverID: receiverID, OfferID: id},
		pending:  make(map[string]*e2ePending),
		sessions: make(map[string]e2e.Keys),
		burned:   make(chan struct{}),
		now:      time.Now,
	}, nil
}

// Name and Size describe the offered file for local display only.
func (s *SenderE2E) Name() string             { return s.core.Offer.Name }
func (s *SenderE2E) Size() int64              { return s.core.Offer.Size }
func (s *SenderE2E) Close() error             { return s.core.Close() }
func (s *SenderE2E) Done() <-chan struct{}    { return s.core.Done() }
func (s *SenderE2E) Started() <-chan struct{} { return s.core.Started() }
func (s *SenderE2E) Burned() <-chan struct{}  { return s.burned }
func (s *SenderE2E) isBurned() bool           { return chanClosed(s.burned) }
func chanClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// fail counts a handshake that did not end in a valid confirmation and burns
// the offer at the limit. s.mu must be held.
func (s *SenderE2E) fail() {
	s.failures++
	if s.failures >= e2eMaxAttempts && !s.isBurned() {
		close(s.burned)
	}
}

// sweep expires unconfirmed handshakes. s.mu must be held.
func (s *SenderE2E) sweep() {
	for sid, p := range s.pending {
		if s.now().Sub(p.created) > e2ePendingTTL {
			delete(s.pending, sid)
			s.fail()
		}
	}
}

func (s *SenderE2E) session(r *http.Request) (e2e.Keys, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.sessions[r.URL.Query().Get("sid")]
	return k, ok
}

func (s *SenderE2E) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The same gates as v1 and v2, in the same order: browser guard, identity.
	if r.Header.Get(browserGuardHeader) != browserGuardValue || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.core.authorize(r.Context(), r.RemoteAddr); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.core.mu.Lock()
	complete := s.core.complete
	s.core.mu.Unlock()
	if complete || s.isBurned() {
		http.Error(w, "offer gone", http.StatusGone)
		return
	}
	action, ok := strings.CutPrefix(r.URL.Path, "/e2e/"+s.core.Offer.ID+"/")
	if !ok {
		if strings.HasPrefix(r.URL.Path, "/e2e/") {
			http.NotFound(w, r) // another offer's code
		} else {
			notFound(w, r, modeE2E)
		}
		return
	}
	switch {
	case r.Method == "POST" && action == "hello":
		s.hello(w, r)
	case r.Method == "POST" && action == "confirm":
		s.confirm(w, r)
	case r.Method == "GET" && action == "manifest":
		s.manifest(w, r)
	case r.Method == "GET" && action == "chunks":
		s.chunks(w, r)
	case r.Method == "POST" && action == "ack":
		s.ack(w, r)
	default:
		http.NotFound(w, r)
	}
}

func readSmall(r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(r.Body, e2eMaxBody+1))
	return b, err == nil && len(b) <= e2eMaxBody
}

func (s *SenderE2E) hello(w http.ResponseWriter, r *http.Request) {
	msg1, ok := readSmall(r)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var sid [e2eSIDSize]byte
	if _, err := rand.Read(sid[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	fk, err := e2e.NewFileKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	keys, _ := e2e.DeriveKeys(fk)
	o := s.core.Offer
	payload, _ := json.Marshal(e2eOffer{hex.EncodeToString(sid[:]), fk, o.Name, o.Size, o.ChunkSize, o.Hash, o.Root})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	p, msg2, err := e2e.Respond(s.code, s.bind, msg1, payload)
	if err != nil {
		// Wrong code, node ID or offer ID: nothing about the offer is sent.
		s.fail()
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if len(s.pending) >= e2eMaxSessions {
		// Too many open handshakes: the oldest one counts as failed.
		var oldest string
		for k, v := range s.pending {
			if oldest == "" || v.created.Before(s.pending[oldest].created) {
				oldest = k
			}
		}
		delete(s.pending, oldest)
		s.fail()
	}
	s.pending[hex.EncodeToString(sid[:])] = &e2ePending{p, keys, s.now()}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(msg2)
}

func (s *SenderE2E) confirm(w http.ResponseWriter, r *http.Request) {
	b, ok := readSmall(r)
	if !ok || len(b) < e2eSIDSize {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sid, msg := b[:e2eSIDSize], b[e2eSIDSize:]
	key := hex.EncodeToString(sid)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	p := s.pending[key]
	if p == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	delete(s.pending, key)
	if err := p.p.Confirm(sid, msg); err != nil {
		s.fail()
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.sessions[key] = p.keys
	s.order = append(s.order, key)
	if len(s.order) > e2eMaxSessions {
		delete(s.sessions, s.order[0])
		s.order = s.order[1:]
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *SenderE2E) manifest(w http.ResponseWriter, r *http.Request) {
	keys, ok := s.session(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.core.acquire(w) {
		return
	}
	defer func() { <-s.core.reads }()
	s.core.startOnce.Do(func() { close(s.core.started) })
	sealed, err := keys.SealManifest(s.offerID, s.root, s.core.manifest)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(len(sealed)))
	v2Copy(w, bytes.NewReader(sealed))
}

// e2eChunkRange parses first and last chunk indexes from the query.
func e2eChunkRange(r *http.Request, count int64) (first, last int64, ok bool) {
	q := r.URL.Query()
	a, b := q.Get("first"), q.Get("last")
	if !v2Digits(a) || !v2Digits(b) || a == "" || b == "" {
		return 0, 0, false
	}
	first, err1 := strconv.ParseInt(a, 10, 64)
	last, err2 := strconv.ParseInt(b, 10, 64)
	return first, last, err1 == nil && err2 == nil && first <= last && last < count
}

func e2eSealedLen(o OfferV2, first, last int64) int64 {
	end := min(o.Size, (last+1)*o.ChunkSize)
	return end - first*o.ChunkSize + (last-first+1)*e2e.Overhead
}

func (s *SenderE2E) chunks(w http.ResponseWriter, r *http.Request) {
	keys, ok := s.session(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	o := s.core.Offer
	first, last, ok := e2eChunkRange(r, o.chunks())
	if !ok {
		http.Error(w, "invalid chunk range", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	if !s.core.acquire(w) {
		return
	}
	defer func() { <-s.core.reads }()
	s.core.startOnce.Do(func() { close(s.core.started) })
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(e2eSealedLen(o, first, last)))
	rc := http.NewResponseController(w)
	buf := make([]byte, o.ChunkSize)
	for i := first; i <= last; i++ {
		n := o.chunkLen(i)
		if _, err := s.core.file.ReadAt(buf[:n], i*o.ChunkSize); err != nil {
			// Headers are sent; a short body makes the receiver retry.
			return
		}
		sealed, err := keys.SealChunk(s.offerID, s.root, uint64(i), i == o.chunks()-1, buf[:n])
		if err != nil {
			return
		}
		for len(sealed) > 0 {
			k := min(len(sealed), 256<<10)
			rc.SetWriteDeadline(time.Now().Add(v2WriteIdle))
			if _, err := w.Write(sealed[:k]); err != nil {
				return
			}
			sealed = sealed[k:]
		}
	}
}

func (s *SenderE2E) ack(w http.ResponseWriter, r *http.Request) {
	keys, ok := s.session(r)
	tag, okBody := readSmall(r)
	if !ok || !okBody || !keys.VerifyAck(s.offerID, s.root, tag) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.core.mu.Lock()
	defer s.core.mu.Unlock()
	if s.core.complete {
		http.Error(w, "offer gone", http.StatusGone)
		return
	}
	s.core.complete = true
	w.WriteHeader(http.StatusNoContent)
	close(s.core.done)
}

// ServeE2E is Serve for an encrypted offer. It returns nil after the
// receiver's authenticated acknowledgement and ErrOfferBurned after too many
// failed handshakes.
func ServeE2E(ctx context.Context, l net.Listener, s *SenderE2E) error {
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	result := make(chan error, 1)
	go func() { result <- srv.Serve(l) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		srv.Close()
		return ctx.Err()
	case <-s.Done():
		return shutdownAfterAck(srv)
	case <-s.Burned():
		shutdownAfterAck(srv)
		return ErrOfferBurned
	}
}

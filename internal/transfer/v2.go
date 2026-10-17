package transfer

// Protocol v2: the file is split into fixed-size chunks, each hashed with
// SHA-256. The offer carries a root hash over the chunk list, the receiver
// fetches and checks the manifest, then pulls byte ranges and verifies each
// chunk before recording it. See docs/protocol-v2.md.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	v2DefaultChunk  = 8 << 20
	v2MinChunk      = 64 << 10
	v2MaxChunk      = 64 << 20
	v2TargetChunks  = 1 << 20 // sender doubles the chunk size to stay under this
	v2MaxChunks     = 1 << 22 // receiver limit: a 128 MiB manifest
	v2Hash          = "sha256"
	v2MaxReads      = 8 // concurrent manifest/file requests per offer
	v2WriteIdle     = time.Minute
	v2MaxHashers    = 8
	v2RootDomain    = "tailbeam/v2 root\x00"
	v2ChunkHashSize = sha256.Size
)

type OfferV2 struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ChunkSize int64  `json:"chunk_size"`
	Hash      string `json:"hash"`
	Root      string `json:"root"`
}

func (o OfferV2) chunks() int64 {
	if o.Size == 0 {
		return 0
	}
	return (o.Size-1)/o.ChunkSize + 1
}

func (o OfferV2) chunkLen(i int64) int64 {
	return min(o.ChunkSize, o.Size-i*o.ChunkSize)
}

func validateOfferV2(o OfferV2) error {
	if o.Version != 2 || o.Hash != v2Hash || o.Size < 0 {
		return errors.New("invalid v2 offer version, hash or size")
	}
	if o.ChunkSize < v2MinChunk || o.ChunkSize > v2MaxChunk || o.ChunkSize&(o.ChunkSize-1) != 0 {
		return errors.New("invalid v2 chunk size")
	}
	if o.chunks() > v2MaxChunks {
		return errors.New("v2 offer has too many chunks")
	}
	for _, v := range []string{o.ID, o.Root} {
		b, e := hex.DecodeString(v)
		if e != nil || len(b) != 32 {
			return errors.New("invalid offer token or root")
		}
	}
	return validName(o.Name)
}

func v2ChunkSizeFor(size int64) int64 {
	c := int64(v2DefaultChunk)
	for c < v2MaxChunk && (size+c-1)/c > v2TargetChunks {
		c *= 2
	}
	return c
}

// v2Root binds the size and chunk size so that a manifest cannot be
// reinterpreted under different chunk boundaries.
func v2Root(size, chunk int64, manifest []byte) []byte {
	h := sha256.New()
	h.Write([]byte(v2RootDomain))
	var n [16]byte
	binary.BigEndian.PutUint64(n[:8], uint64(size))
	binary.BigEndian.PutUint64(n[8:], uint64(chunk))
	h.Write(n[:])
	h.Write(manifest)
	return h.Sum(nil)
}

// v2HashChunks hashes every chunk of f using a bounded worker pool.
func v2HashChunks(ctx context.Context, f io.ReaderAt, size, chunk int64) ([]byte, error) {
	o := OfferV2{Size: size, ChunkSize: chunk}
	count := o.chunks()
	out := make([]byte, count*v2ChunkHashSize)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int64)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	fail := func(err error) {
		once.Do(func() { firstErr = err; cancel() })
	}
	for range min(int64(runtime.GOMAXPROCS(0)), v2MaxHashers, max(count, 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1<<20)
			h := sha256.New()
			for i := range jobs {
				h.Reset()
				n := o.chunkLen(i)
				got, err := io.CopyBuffer(h, contextReader{ctx, io.NewSectionReader(f, i*chunk, n)}, buf)
				if err == nil && got != n {
					err = io.ErrUnexpectedEOF
				}
				if err != nil {
					fail(err)
					continue
				}
				copy(out[i*v2ChunkHashSize:], h.Sum(nil))
			}
		}()
	}
feed:
	for i := range count {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, ctx.Err()
}

type SenderV2 struct {
	Offer     OfferV2
	file      *os.File
	manifest  []byte
	authorize Authorize
	reads     chan struct{}
	mu        sync.Mutex
	complete  bool
	done      chan struct{}
	started   chan struct{}
	startOnce sync.Once
}

func NewSenderV2(ctx context.Context, path string, authorize Authorize) (*SenderV2, error) {
	return newSenderV2(ctx, path, authorize, 0)
}

// newSenderV2 uses chunk as the chunk size, or picks one when it is zero.
func newSenderV2(ctx context.Context, path string, authorize Authorize, chunk int64) (*SenderV2, error) {
	if authorize == nil {
		return nil, errors.New("missing peer authorization")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("only regular files are supported")
	}
	name := filepath.Base(path)
	if err := validName(name); err != nil {
		return nil, err
	}
	size := st.Size()
	if chunk == 0 {
		chunk = v2ChunkSizeFor(size)
	}
	if (OfferV2{Size: size, ChunkSize: chunk}).chunks() > v2MaxChunks {
		return nil, errors.New("file is too large for protocol v2")
	}
	manifest, err := v2HashChunks(ctx, f, size, chunk)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if after.Size() != size || !after.ModTime().Equal(st.ModTime()) {
		return nil, errors.New("file changed while hashing")
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	o := OfferV2{2, hex.EncodeToString(token[:]), name, size, chunk, v2Hash, hex.EncodeToString(v2Root(size, chunk, manifest))}
	ok = true
	return &SenderV2{Offer: o, file: f, manifest: manifest, authorize: authorize, reads: make(chan struct{}, v2MaxReads), done: make(chan struct{}), started: make(chan struct{})}, nil
}

func (s *SenderV2) Close() error          { return s.file.Close() }
func (s *SenderV2) Done() <-chan struct{} { return s.done }

// Started is closed when the first authorized manifest or file request begins.
func (s *SenderV2) Started() <-chan struct{} { return s.started }

func (s *SenderV2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The same gates as v1, in the same order: browser guard, then identity.
	if r.Header.Get(browserGuardHeader) != browserGuardValue || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.authorize(r.Context(), r.RemoteAddr); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mu.Lock()
	complete := s.complete
	s.mu.Unlock()
	if complete {
		http.Error(w, "offer completed", http.StatusGone)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v2/offer":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Offer)
	case r.Method == "GET" && r.URL.Path == "/v2/manifest/"+s.Offer.ID:
		if !s.acquire(w) {
			return
		}
		defer func() { <-s.reads }()
		s.startOnce.Do(func() { close(s.started) })
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(s.manifest)))
		v2Copy(w, bytes.NewReader(s.manifest))
	case r.Method == "GET" && r.URL.Path == "/v2/file/"+s.Offer.ID:
		if !s.acquire(w) {
			return
		}
		defer func() { <-s.reads }()
		s.startOnce.Do(func() { close(s.started) })
		s.serveFile(w, r)
	case r.Method == "POST" && r.URL.Path == "/v2/ack/"+s.Offer.ID:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.complete {
			http.Error(w, "offer completed", http.StatusGone)
			return
		}
		s.complete = true
		w.WriteHeader(http.StatusNoContent)
		close(s.done)
	default:
		notFound(w, r, modePlaintext)
	}
}

func (s *SenderV2) acquire(w http.ResponseWriter) bool {
	select {
	case s.reads <- struct{}{}:
		return true
	default:
		http.Error(w, "too many concurrent reads", http.StatusTooManyRequests)
		return false
	}
}

func (s *SenderV2) serveFile(w http.ResponseWriter, r *http.Request) {
	size := s.Offer.Size
	start, end, partial, ok := v2ParseRange(r.Header.Get("Range"), size)
	if !ok {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		http.Error(w, "invalid range", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(end-start))
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end-1, size))
		w.WriteHeader(http.StatusPartialContent)
	}
	v2Copy(w, io.NewSectionReader(s.file, start, end-start))
}

// v2ParseRange accepts no header (the whole file) or exactly one
// "bytes=first-[last]" range. It returns a half-open interval [start, end).
// Suffix ranges and multiple ranges are not used by the client and are refused.
func v2ParseRange(h string, size int64) (start, end int64, partial, ok bool) {
	if h == "" {
		return 0, size, false, true
	}
	spec, found := strings.CutPrefix(h, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, 0, false, false
	}
	a, b, found := strings.Cut(spec, "-")
	if !found || a == "" || !v2Digits(a) || (b != "" && !v2Digits(b)) {
		return 0, 0, false, false
	}
	first, err := strconv.ParseInt(a, 10, 64)
	if err != nil || first >= size {
		return 0, 0, false, false
	}
	last := size - 1
	if b != "" {
		l, err := strconv.ParseInt(b, 10, 64)
		if err != nil || l < first {
			return 0, 0, false, false
		}
		last = min(l, size-1)
	}
	return first, last + 1, true, true
}

func v2Digits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) <= 19
}

// v2Copy streams r to w, extending the connection's write deadline after
// every write so a stalled peer releases its read slot after v2WriteIdle.
func v2Copy(w http.ResponseWriter, r io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 256<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			rc.SetWriteDeadline(time.Now().Add(v2WriteIdle))
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ServeV2 is Serve for a v2 offer. It has no global write timeout: the
// per-write deadline in v2Copy bounds stalled transfers instead.
func ServeV2(ctx context.Context, l net.Listener, s *SenderV2) error {
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

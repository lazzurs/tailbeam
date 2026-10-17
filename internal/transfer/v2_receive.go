package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	v2ReadIdle = time.Minute // abort a body read with no progress for this long
	v2Attempts = 3           // consecutive failed attempts without progress
	v2MaxState = 4 << 20
	// v2SegmentBytes bounds one range request, so parallel streams share the
	// work and a failed request re-fetches at most this much.
	v2SegmentBytes = 64 << 20
	// DefaultStreams is how many range requests a receiver runs at once.
	// Each stream verifies (and in end-to-end mode decrypts) its own chunks,
	// so streams also spread that CPU work across cores. The sender serves at
	// most v2MaxReads at once.
	DefaultStreams = 2
)

// v2Backoff is a variable so tests can shorten it.
var v2Backoff = time.Second

type statusError int

func (e statusError) Error() string { return fmt.Sprintf("peer returned HTTP %d", int(e)) }

func v2Request(ctx context.Context, c *http.Client, method, url, rangeHeader string, want int) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(browserGuardHeader, browserGuardValue)
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	resp, err := c.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != want {
		resp.Body.Close()
		if err := modeError(resp, modeE2E); err != nil {
			return nil, err
		}
		return nil, statusError(resp.StatusCode)
	}
	return resp, nil
}

// Remote is a plaintext offer. Name and Size are validated.
type Remote struct {
	Name string
	Size int64
	// Streams is the number of parallel range requests for the download;
	// zero means DefaultStreams.
	Streams int
	o       OfferV2
}

// FetchPlainOffer fetches and validates a plaintext offer. An encrypted
// sender answers with ErrSenderEncrypted, never with a plaintext offer.
func FetchPlainOffer(ctx context.Context, c *http.Client, base string) (Remote, error) {
	o, err := FetchOfferV2(ctx, c, base)
	if err != nil {
		return Remote{}, err
	}
	return Remote{Name: o.Name, Size: o.Size, o: o}, nil
}

// Download fetches the offer. idle bounds how long a response may stall;
// zero uses the default.
func (r Remote) Download(ctx context.Context, c *http.Client, base, sender, dir string, maxBytes int64, idle time.Duration) (string, error) {
	return downloadChunked(ctx, r.o, sender, dir, maxBytes, idle, r.Streams, &plainSource{c: c, base: base, o: r.o})
}

func FetchOfferV2(ctx context.Context, c *http.Client, base string) (OfferV2, error) {
	var o OfferV2
	r, err := v2Request(ctx, c, "GET", base+"/v2/offer", "", http.StatusOK)
	if err != nil {
		return o, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, maxMetadata+1))
	if err != nil {
		return o, err
	}
	if len(b) > maxMetadata {
		return o, errors.New("offer too large")
	}
	if err = json.Unmarshal(b, &o); err != nil {
		return o, err
	}
	return o, validateOfferV2(o)
}

func fetchManifest(ctx context.Context, c *http.Client, base string, o OfferV2) ([]byte, error) {
	want := o.chunks() * v2ChunkHashSize
	r, err := v2Request(ctx, c, "GET", base+"/v2/manifest/"+o.ID, "", http.StatusOK)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.ContentLength != want {
		return nil, errors.New("manifest length does not match offer")
	}
	m, err := io.ReadAll(io.LimitReader(r.Body, want+1))
	if err != nil {
		return nil, err
	}
	if int64(len(m)) != want {
		return nil, errors.New("manifest length does not match offer")
	}
	if hex.EncodeToString(v2Root(o.Size, o.ChunkSize, m)) != o.Root {
		return nil, errors.New("manifest does not match offer root")
	}
	return m, nil
}

// v2State is kept beside the partial file and names the offer it belongs to.
// The partial file is reused only when every field matches the current offer.
// Which chunks are already present is not recorded: a resume re-checks the
// partial file's data against the manifest instead (see verifyExisting).
type v2State struct {
	Version   int    `json:"version"`
	Sender    string `json:"sender"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ChunkSize int64  `json:"chunk_size"`
	Root      string `json:"root"`
}

func (s *v2State) matches(o OfferV2, sender string) bool {
	return s.Version == 1 && s.Sender == sender && s.Name == o.Name && s.Size == o.Size &&
		s.ChunkSize == o.ChunkSize && s.Root == o.Root
}

// V2PartialPaths names the resume files for one sender and file name. Keying
// on the sender's stable ID and name (not the random offer ID or root) lets a
// rerun find, and if the source changed, discard the previous attempt.
func V2PartialPaths(dir, sender, name string) (part, state string) {
	k := sha256.Sum256([]byte(sender + "\x00" + name))
	base := filepath.Join(dir, ".tailbeam-v2-"+hex.EncodeToString(k[:16]))
	return base + ".part", base + ".state"
}

func v2Regular(path string) (os.FileInfo, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s is accessible to other users", path)
	}
	return st, nil
}

func loadV2State(path string, o OfferV2, sender string) *v2State {
	st, err := v2Regular(path)
	if err != nil || st.Size() > v2MaxState {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s v2State
	if json.Unmarshal(b, &s) != nil || !s.matches(o, sender) {
		return nil
	}
	return &s
}

func (s *v2State) save(path string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tailbeam-v2-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// openPartial reuses a matching partial file (resumed is true) or starts a
// new, empty one.
func openPartial(part, statePath string, o OfferV2, sender string) (f *os.File, resumed bool, err error) {
	if s := loadV2State(statePath, o, sender); s != nil {
		if st, err := v2Regular(part); err == nil && st.Size() == o.Size {
			f, err := os.OpenFile(part, os.O_RDWR, 0)
			if err != nil {
				return nil, false, err
			}
			if fst, err := f.Stat(); err != nil || !os.SameFile(st, fst) {
				f.Close()
				return nil, false, errors.New("partial file changed while opening")
			}
			return f, true, nil
		}
	}
	// Stale or mismatched (for example the source changed): start over.
	// Remove never follows a symlink.
	for _, p := range []string{statePath, part} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, false, err
		}
	}
	f, err = os.OpenFile(part, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, false, err
	}
	if err := f.Truncate(o.Size); err != nil {
		f.Close()
		os.Remove(part)
		return nil, false, err
	}
	s := &v2State{1, sender, o.Name, o.Size, o.ChunkSize, o.Root}
	if err := s.save(statePath); err != nil {
		f.Close()
		os.Remove(part)
		return nil, false, err
	}
	return f, false, nil
}

// chunkSource is where a chunked download gets its data: plaintext v2 range
// requests, or sealed chunks in end-to-end mode.
type chunkSource interface {
	manifest(ctx context.Context) ([]byte, error)
	// request opens a response that streams chunks first..last in order.
	request(ctx context.Context, first, last int64) (io.ReadCloser, error)
	// newReader returns a chunk decoder with its own buffers, one per stream.
	newReader() chunkReader
	ack(ctx context.Context) error
}

type chunkReader interface {
	// readChunk reads chunk i (n plaintext bytes) from body and writes its
	// plaintext to w. The caller checks the manifest hash.
	readChunk(body io.Reader, i, n int64, w io.Writer) error
}

// plainSource is protocol v2 without end-to-end encryption.
type plainSource struct {
	c    *http.Client
	base string
	o    OfferV2
}

func (p *plainSource) manifest(ctx context.Context) ([]byte, error) {
	return fetchManifest(ctx, p.c, p.base, p.o)
}

func (p *plainSource) request(ctx context.Context, first, last int64) (io.ReadCloser, error) {
	start, end := first*p.o.ChunkSize, min(p.o.Size, (last+1)*p.o.ChunkSize)
	r, err := v2Request(ctx, p.c, "GET", p.base+"/v2/file/"+p.o.ID, fmt.Sprintf("bytes=%d-%d", start, end-1), http.StatusPartialContent)
	if err != nil {
		return nil, err
	}
	if r.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", start, end-1, p.o.Size) || r.ContentLength != end-start {
		r.Body.Close()
		return nil, errors.New("peer returned the wrong range")
	}
	return r.Body, nil
}

func (p *plainSource) newReader() chunkReader { return &plainReader{make([]byte, 1<<20)} }

type plainReader struct{ buf []byte }

func (p *plainReader) readChunk(body io.Reader, i, n int64, w io.Writer) error {
	got, err := io.CopyBuffer(w, io.LimitReader(body, n), p.buf)
	if err == nil && got != n {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (p *plainSource) ack(ctx context.Context) error {
	r, err := v2Request(ctx, p.c, "POST", p.base+"/v2/ack/"+p.o.ID, "", http.StatusNoContent)
	if err != nil {
		return err
	}
	return r.Body.Close()
}

// v2Fetch downloads the missing chunks over several parallel range requests.
// Pending work is a queue of segments (runs of consecutive chunks); a failed
// request puts its unfinished chunks back on the queue.
type v2Fetch struct {
	src      chunkSource
	o        OfferV2
	manifest []byte
	f        *os.File
	idle     time.Duration

	mu       sync.Mutex
	cond     *sync.Cond
	queue    [][2]int64 // segments [first, last] still to fetch
	inflight int
	failures int // consecutive failed requests without progress
	err      error
}

// verifyExisting checks a resumed partial file against the manifest and
// reports which chunks already hold their final content. Only regions the
// filesystem reports as data are read, where it can tell. Chunks are accepted
// by hash alone, so this is safe whether or not earlier writes were synced.
func (d *v2Fetch) verifyExisting(ctx context.Context) ([]bool, error) {
	o, cs := d.o, d.o.ChunkSize
	present := make([]bool, o.chunks())
	var list []int64
	if regions, ok := dataRegions(d.f, o.Size); ok {
		for _, r := range regions {
			for i := r[0] / cs; i*cs < r[1]; i++ {
				if !present[i] {
					present[i] = true
					list = append(list, i)
				}
			}
		}
		clear(present)
	} else {
		for i := range o.chunks() {
			list = append(list, i)
		}
	}
	got := make([]byte, len(d.manifest))
	if err := v2HashInto(ctx, d.f, o, list, got); err != nil {
		return nil, err
	}
	for _, i := range list {
		want := d.manifest[i*v2ChunkHashSize : (i+1)*v2ChunkHashSize]
		present[i] = bytes.Equal(got[i*v2ChunkHashSize:(i+1)*v2ChunkHashSize], want)
	}
	return present, nil
}

// run fetches the chunks of seg in one request, verifying each before the
// next. It returns the first chunk not yet stored (seg[1]+1 when complete).
func (d *v2Fetch) run(ctx context.Context, rd chunkReader, seg [2]int64) (int64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	t := time.AfterFunc(d.idle, cancel)
	defer t.Stop()
	first, last := seg[0], seg[1]
	rc, err := d.src.request(ctx, first, last)
	if err != nil {
		return first, err
	}
	defer rc.Close()
	t.Reset(d.idle)
	body := idleReader{rc, t, d.idle}
	h := sha256.New()
	for i := first; i <= last; i++ {
		n := d.o.chunkLen(i)
		h.Reset()
		if err := rd.readChunk(body, i, n, io.MultiWriter(io.NewOffsetWriter(d.f, i*d.o.ChunkSize), h)); err != nil {
			return i, fmt.Errorf("chunk %d: %w", i, err)
		}
		if !bytes.Equal(h.Sum(nil), d.manifest[i*v2ChunkHashSize:(i+1)*v2ChunkHashSize]) {
			return i, fmt.Errorf("chunk %d does not match the manifest (source changed or corrupted)", i)
		}
	}
	return last + 1, nil
}

// take waits for the next segment. It reports false when the work is done or
// the download has failed.
func (d *v2Fetch) take() ([2]int64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.queue) == 0 && d.inflight > 0 && d.err == nil {
		d.cond.Wait()
	}
	if d.err != nil || len(d.queue) == 0 {
		return [2]int64{}, false
	}
	seg := d.queue[0]
	d.queue = d.queue[1:]
	d.inflight++
	return seg, true
}

// finish records the outcome of one request and returns how long the stream
// should back off before taking more work.
func (d *v2Fetch) finish(seg [2]int64, next int64, err error, stop context.CancelFunc) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer d.cond.Broadcast()
	d.inflight--
	if err == nil {
		d.failures = 0
		return 0
	}
	if next <= seg[1] {
		d.queue = append(d.queue, [2]int64{next, seg[1]})
	}
	if d.err != nil {
		return 0
	}
	if next > seg[0] {
		d.failures = 0
	} else if d.failures++; d.failures >= v2Attempts {
		d.err = err
		stop()
		return 0
	}
	return v2Backoff << d.failures
}

// fetch downloads every chunk not marked present, using streams parallel
// requests.
func (d *v2Fetch) fetch(ctx context.Context, present []bool, streams int) error {
	// Segments are at most v2SegmentBytes, and small enough that every
	// stream gets a share of a small download.
	var missing int64
	for _, p := range present {
		if !p {
			missing++
		}
	}
	per := min(max(1, (missing+int64(streams)-1)/int64(streams)), max(1, v2SegmentBytes/d.o.ChunkSize))
	for i := int64(0); i < int64(len(present)); {
		if present[i] {
			i++
			continue
		}
		last := i
		for last+1 < int64(len(present)) && !present[last+1] && last+1-i < per {
			last++
		}
		d.queue = append(d.queue, [2]int64{i, last})
		i = last + 1
	}
	d.cond = sync.NewCond(&d.mu)
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	for range max(1, min(streams, len(d.queue))) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rd := d.src.newReader()
			for {
				seg, ok := d.take()
				if !ok {
					return
				}
				next, err := d.run(ctx, rd, seg)
				if err != nil && ctx.Err() != nil {
					// Cancelled, or another stream ended the download.
					d.finish(seg, next, ctx.Err(), stop)
					return
				}
				if wait := d.finish(seg, next, err, stop); wait > 0 {
					t := time.NewTimer(wait)
					select {
					case <-ctx.Done():
						t.Stop()
					case <-t.C:
					}
				}
			}
		}()
	}
	wg.Wait()
	if d.err != nil {
		return d.err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(d.queue) > 0 {
		return errors.New("download incomplete")
	}
	return nil
}

// DownloadV2 resumes or starts a chunked download. On failure the verified
// chunks stay in a private partial file, and a rerun against the same sender
// and file name continues from them. Only a complete file whose chunks all
// match the root is published, without replacing anything.
func DownloadV2(ctx context.Context, c *http.Client, base string, o OfferV2, sender, dir string, maxBytes int64) (string, error) {
	return DownloadV2Idle(ctx, c, base, o, sender, dir, maxBytes, 0)
}

// DownloadV2Idle is DownloadV2 with a configurable stall timeout per range
// response; zero uses v2ReadIdle.
func DownloadV2Idle(ctx context.Context, c *http.Client, base string, o OfferV2, sender, dir string, maxBytes int64, idle time.Duration) (string, error) {
	return downloadChunked(ctx, o, sender, dir, maxBytes, idle, 0, &plainSource{c: c, base: base, o: o})
}

// downloadChunked is the shared resume, verify and publish logic for both
// plaintext v2 and end-to-end encrypted transfers.
//
// Every chunk of the published file was hashed against the manifest exactly
// once: either as it was written in this run, or (on resume) as it was read
// back from the partial file before fetching. There is no separate final
// pass over the whole file.
func downloadChunked(ctx context.Context, o OfferV2, sender, dir string, maxBytes int64, idle time.Duration, streams int, src chunkSource) (string, error) {
	if idle <= 0 {
		idle = v2ReadIdle
	}
	if streams <= 0 {
		streams = DefaultStreams
	}
	streams = min(streams, v2MaxReads)
	if err := validateOfferV2(o); err != nil {
		return "", err
	}
	if sender == "" {
		return "", errors.New("missing sender identity")
	}
	if maxBytes < 0 || o.Size > maxBytes {
		return "", errors.New("file exceeds --max-bytes")
	}
	dest := filepath.Join(dir, o.Name)
	if _, err := os.Lstat(dest); err == nil {
		return "", fmt.Errorf("destination already exists: %s", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	manifest, err := src.manifest(ctx)
	if err != nil {
		return "", err
	}
	part, statePath := V2PartialPaths(dir, sender, o.Name)
	f, resumed, err := openPartial(part, statePath, o, sender)
	if err != nil {
		return "", err
	}
	defer f.Close()
	d := &v2Fetch{src: src, o: o, manifest: manifest, f: f, idle: idle}
	present := make([]bool, o.chunks())
	if resumed {
		if present, err = d.verifyExisting(ctx); err != nil {
			return "", err
		}
	}
	var missing int64
	for i := range o.chunks() {
		if !present[i] {
			missing += o.chunkLen(i)
		}
	}
	if free, ok, err := freeSpace(dir); err != nil {
		return "", err
	} else if ok && uint64(missing) > free {
		return "", fmt.Errorf("not enough free space in %s: need %d more bytes, have %d (partial download kept)", dir, missing, free)
	}
	if err := preallocate(f, o.Size); err != nil {
		return "", fmt.Errorf("preallocate: %w", err)
	}
	if err := d.fetch(ctx, present, streams); err != nil {
		return "", fmt.Errorf("%w (partial download kept; rerun receive to resume)", err)
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Link(part, dest); err != nil {
		return "", fmt.Errorf("publish without overwrite: %w", err)
	}
	os.Remove(statePath)
	os.Remove(part)
	if err := syncDir(dir); err != nil {
		return dest, fmt.Errorf("file saved at %s, but syncing the directory failed: %w", dest, err)
	}
	if err := src.ack(ctx); err != nil {
		return dest, fmt.Errorf("file saved at %s, but acknowledgement failed: %w", dest, err)
	}
	return dest, nil
}

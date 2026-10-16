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
	"time"
)

const (
	v2ReadIdle        = time.Minute // abort a body read with no progress for this long
	v2CheckpointBytes = 64 << 20
	v2CheckpointEvery = 2 * time.Second
	v2Attempts        = 3 // consecutive failed attempts without progress
	v2MaxState        = 4 << 20
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
		return nil, statusError(resp.StatusCode)
	}
	return resp, nil
}

// Remote is an offer of either protocol version. Name and Size are validated.
type Remote struct {
	Version int
	Name    string
	Size    int64
	v1      Offer
	v2      OfferV2
}

// FetchAnyOffer prefers v2 and falls back to v1 only when the sender does not
// know the v2 endpoint. Both versions apply the same peer authentication.
func FetchAnyOffer(ctx context.Context, c *http.Client, base string) (Remote, error) {
	o2, err := FetchOfferV2(ctx, c, base)
	if err == nil {
		return Remote{Version: 2, Name: o2.Name, Size: o2.Size, v2: o2}, nil
	}
	var se statusError
	if !errors.As(err, &se) || se != http.StatusNotFound {
		return Remote{}, err
	}
	o1, err := FetchOffer(ctx, c, base)
	if err != nil {
		return Remote{}, err
	}
	return Remote{Version: 1, Name: o1.Name, Size: o1.Size, v1: o1}, nil
}

func (r Remote) Download(ctx context.Context, c *http.Client, base, sender, dir string, maxBytes int64) (string, error) {
	if r.Version == 2 {
		return DownloadV2(ctx, c, base, r.v2, sender, dir, maxBytes)
	}
	return Download(ctx, c, base, r.v1, dir, maxBytes)
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

// v2State is the resume record kept beside the partial file. The partial
// file is reused only when every field matches the current offer.
type v2State struct {
	Version   int    `json:"version"`
	Sender    string `json:"sender"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ChunkSize int64  `json:"chunk_size"`
	Root      string `json:"root"`
	Done      []byte `json:"done"` // bitmap of verified chunks
}

func (s *v2State) has(i int64) bool { return s.Done[i/8]&(1<<(i%8)) != 0 }
func (s *v2State) set(i int64)      { s.Done[i/8] |= 1 << (i % 8) }
func (s *v2State) clear(i int64)    { s.Done[i/8] &^= 1 << (i % 8) }

func (s *v2State) matches(o OfferV2, sender string) bool {
	return s.Version == 1 && s.Sender == sender && s.Name == o.Name && s.Size == o.Size &&
		s.ChunkSize == o.ChunkSize && s.Root == o.Root && int64(len(s.Done)) == (o.chunks()+7)/8
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

// openPartial reuses a matching partial file or starts a new one.
func openPartial(part, statePath string, o OfferV2, sender string) (*os.File, *v2State, error) {
	if s := loadV2State(statePath, o, sender); s != nil {
		if st, err := v2Regular(part); err == nil && st.Size() == o.Size {
			f, err := os.OpenFile(part, os.O_RDWR, 0)
			if err != nil {
				return nil, nil, err
			}
			if fst, err := f.Stat(); err != nil || !os.SameFile(st, fst) {
				f.Close()
				return nil, nil, errors.New("partial file changed while opening")
			}
			return f, s, nil
		}
	}
	// Stale or mismatched (for example the source changed): start over.
	// Remove never follows a symlink.
	for _, p := range []string{statePath, part} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
	}
	f, err := os.OpenFile(part, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, nil, err
	}
	if err := f.Truncate(o.Size); err != nil {
		f.Close()
		os.Remove(part)
		return nil, nil, err
	}
	s := &v2State{1, sender, o.Name, o.Size, o.ChunkSize, o.Root, make([]byte, (o.chunks()+7)/8)}
	if err := s.save(statePath); err != nil {
		f.Close()
		os.Remove(part)
		return nil, nil, err
	}
	return f, s, nil
}

type v2Fetch struct {
	ctx       context.Context
	c         *http.Client
	base      string
	o         OfferV2
	manifest  []byte
	f         *os.File
	s         *v2State
	statePath string
	pending   int64
	lastSave  time.Time
}

func (d *v2Fetch) checkpoint() error {
	if err := d.f.Sync(); err != nil {
		return err
	}
	d.pending, d.lastSave = 0, time.Now()
	return d.s.save(d.statePath)
}

// idleReader cancels the request when no bytes arrive for v2ReadIdle.
type idleReader struct {
	r io.Reader
	t *time.Timer
}

func (r idleReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	r.t.Reset(v2ReadIdle)
	return n, err
}

// run fetches chunks first..last in one range request, verifying and
// recording each chunk before the next. It reports whether any chunk landed.
func (d *v2Fetch) run(first, last int64) (bool, error) {
	ctx, cancel := context.WithCancel(d.ctx)
	defer cancel()
	t := time.AfterFunc(v2ReadIdle, cancel)
	defer t.Stop()
	start, end := first*d.o.ChunkSize, min(d.o.Size, (last+1)*d.o.ChunkSize)
	r, err := v2Request(ctx, d.c, "GET", d.base+"/v2/file/"+d.o.ID, fmt.Sprintf("bytes=%d-%d", start, end-1), http.StatusPartialContent)
	if err != nil {
		return false, err
	}
	defer r.Body.Close()
	if r.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", start, end-1, d.o.Size) || r.ContentLength != end-start {
		return false, errors.New("peer returned the wrong range")
	}
	body := idleReader{r.Body, t}
	buf := make([]byte, 1<<20)
	h := sha256.New()
	progressed := false
	for i := first; i <= last; i++ {
		n := d.o.chunkLen(i)
		h.Reset()
		got, err := io.CopyBuffer(io.MultiWriter(io.NewOffsetWriter(d.f, i*d.o.ChunkSize), h), io.LimitReader(body, n), buf)
		if err == nil && got != n {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return progressed, fmt.Errorf("incomplete chunk %d: %w", i, err)
		}
		if !bytes.Equal(h.Sum(nil), d.manifest[i*v2ChunkHashSize:(i+1)*v2ChunkHashSize]) {
			return progressed, fmt.Errorf("chunk %d does not match the manifest (source changed or corrupted)", i)
		}
		d.s.set(i)
		progressed = true
		d.pending += n
		if d.pending >= v2CheckpointBytes || time.Since(d.lastSave) >= v2CheckpointEvery {
			if err := d.checkpoint(); err != nil {
				return progressed, err
			}
		}
	}
	return progressed, nil
}

func (d *v2Fetch) fetchMissing() error {
	count, failures := d.o.chunks(), 0
	for i := int64(0); i < count; {
		if d.s.has(i) {
			i++
			continue
		}
		last := i
		for last+1 < count && !d.s.has(last+1) {
			last++
		}
		progressed, err := d.run(i, last)
		if err == nil {
			continue
		}
		if cerr := d.checkpoint(); cerr != nil {
			return cerr
		}
		if d.ctx.Err() != nil {
			return d.ctx.Err()
		}
		if progressed {
			failures = 0
		} else if failures++; failures >= v2Attempts {
			return err
		}
		t := time.NewTimer(v2Backoff << failures)
		select {
		case <-d.ctx.Done():
			t.Stop()
			return d.ctx.Err()
		case <-t.C:
		}
	}
	return d.checkpoint()
}

// DownloadV2 resumes or starts a chunked download. On failure the verified
// chunks stay in a private partial file, and a rerun against the same sender
// and file name continues from them. Like v1, only a complete file whose
// chunks all match the root is published, without replacing anything.
func DownloadV2(ctx context.Context, c *http.Client, base string, o OfferV2, sender, dir string, maxBytes int64) (string, error) {
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
	manifest, err := fetchManifest(ctx, c, base, o)
	if err != nil {
		return "", err
	}
	part, statePath := V2PartialPaths(dir, sender, o.Name)
	f, s, err := openPartial(part, statePath, o, sender)
	if err != nil {
		return "", err
	}
	defer f.Close()
	d := &v2Fetch{ctx: ctx, c: c, base: base, o: o, manifest: manifest, f: f, s: s, statePath: statePath, lastSave: time.Now()}
	verified := false
	for round := 0; round < 2 && !verified; round++ {
		if err := d.fetchMissing(); err != nil {
			return "", fmt.Errorf("%w (partial download kept; rerun receive to resume)", err)
		}
		// Re-read the whole partial file before publishing, so a bad bitmap or
		// a disk fault cannot publish a file that does not match the root.
		got, err := v2HashChunks(ctx, f, o.Size, o.ChunkSize)
		if err != nil {
			return "", err
		}
		verified = true
		for i := range o.chunks() {
			if !bytes.Equal(got[i*v2ChunkHashSize:(i+1)*v2ChunkHashSize], manifest[i*v2ChunkHashSize:(i+1)*v2ChunkHashSize]) {
				s.clear(i)
				verified = false
			}
		}
	}
	if !verified {
		return "", errors.New("partial file failed final verification; file was not saved")
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
	if runtime.GOOS != "windows" {
		if dirf, err := os.Open(dir); err == nil {
			dirf.Sync()
			dirf.Close()
		}
	}
	ack, err := v2Request(ctx, c, "POST", base+"/v2/ack/"+o.ID, "", http.StatusNoContent)
	if err != nil {
		return dest, fmt.Errorf("file saved at %s, but acknowledgement failed: %w", dest, err)
	}
	ack.Body.Close()
	return dest, nil
}

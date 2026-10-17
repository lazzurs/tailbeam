package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/linuskendall/tailbeam/internal/e2e"
	"github.com/linuskendall/tailbeam/internal/tailnet"
	"github.com/linuskendall/tailbeam/internal/transfer"
)

const usage = `tailbeam: single-file transfers authenticated by Tailscale

  tailbeam send [flags] FILE DESTINATION
  tailbeam receive [flags] [SENDER[:CODE] | CODE]

Start send first, then run receive on the destination. Both commands must remain
running during the transfer. Hosts may be MagicDNS names, Tailscale IPs, or node IDs.
Use receive SENDER to accept offers from only that host. Flags precede arguments.

Transfers are end-to-end encrypted by default: send prints a one-time transfer
code, and receive needs it. Give it as SENDER:CODE (IPv6: [ADDR]:CODE), as a
bare CODE (discovers the sender), in TAILBEAM_CODE, or at the hidden prompt.
The prompt and TAILBEAM_CODE keep the code out of the process list.

Common flags: --port 8784 --timeout 1h --deadline 0 --socket PATH --plaintext
  --timeout   how long to wait for a peer (send: until the receiver starts
              downloading; receive: until an offer is found)
  --deadline  absolute cap on the whole command, including an active transfer
              (default 0 = none)
  --plaintext rely on Tailscale's encryption only, with no transfer code; both
              sides must use it
Send flags: --v1 (with --plaintext: serve protocol v1, without resume, for
              older receivers)
  --no-cache  re-hash a large file even if its manifest is cached (in the
              user cache directory, keyed by inode, size, mtime and ctime)
Receive flags: --dir . --max-bytes 1073741824 --idle-timeout 5m --yes
  --idle-timeout  abort a download when no bytes arrive for this long; an
                  interrupted download resumes when receive is rerun
  --yes           accept without the interactive confirmation prompt
  --streams       parallel range requests per download, 1..8 (default 2)
receive asks "Accept? [y/N]" on the terminal; without a terminal it requires --yes.
`

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tailbeam:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(usage)
		return nil
	}
	mode := args[0]
	if mode != "send" && mode != "receive" {
		return fmt.Errorf("unknown command %q; use --help", mode)
	}
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	port := fs.Int("port", transfer.DefaultPort, "TCP port on the sender")
	timeout := fs.Duration("timeout", time.Hour, "maximum time waiting for a peer; does not limit an active transfer")
	deadline := fs.Duration("deadline", 0, "absolute cap on the whole command (0 = none)")
	socket := fs.String("socket", "", "Tailscale daemon socket (default: LocalAPI platform default)")
	plaintext := fs.Bool("plaintext", false, "no end-to-end encryption or transfer code; both sides must agree")
	var dir *string
	var max *int64
	var idle *time.Duration
	var yes *bool
	streams := new(int)
	v1 := new(bool)
	noCache := new(bool)
	if mode == "send" {
		v1 = fs.Bool("v1", false, "with --plaintext: serve protocol v1 (no resume) for older receivers")
		noCache = fs.Bool("no-cache", false, "do not read or write the cached manifest of a large file")
	}
	if mode == "receive" {
		idle = fs.Duration("idle-timeout", 5*time.Minute, "abort a download when no bytes arrive for this long")
		yes = fs.Bool("yes", false, "skip the confirmation prompt")
		dir = fs.String("dir", ".", "existing output directory")
		max = fs.Int64("max-bytes", 1<<30, "maximum accepted file size")
		streams = fs.Int("streams", transfer.DefaultStreams, "parallel range requests per download, 1..8")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *port < 1 || *port > 65535 || *timeout <= 0 || *deadline < 0 || (idle != nil && *idle <= 0) {
		return errors.New("port must be 1..65535, timeouts must be positive, and deadline nonnegative")
	}
	if mode == "receive" && (*streams < 1 || *streams > 8) {
		return errors.New("streams must be 1..8")
	}
	if (mode == "send" && fs.NArg() != 2) || (mode == "receive" && fs.NArg() > 1) {
		return errors.New("usage: " + usage)
	}
	if max != nil && *max < 0 {
		return errors.New("max-bytes must be nonnegative")
	}
	if *v1 && !*plaintext {
		return errors.New("--v1 has no end-to-end encryption; it requires --plaintext")
	}
	if mode == "receive" && !*yes && !isTerminal(os.Stdin) {
		return errors.New("stdin is not a terminal; pass --yes to receive without confirmation")
	}
	var host string
	var code *e2e.Code
	if mode == "receive" {
		// Parse the code before any network activity, so typos fail fast.
		var fromArgs bool
		var err error
		host, code, fromArgs, err = receiveTarget(fs.Arg(0), *plaintext, os.Getenv)
		if err != nil {
			return err
		}
		if fromArgs {
			fmt.Fprintln(os.Stderr, "warning: a code on the command line is visible to other local users (ps); prefer TAILBEAM_CODE or the prompt")
		}
		if code == nil && !*plaintext {
			if code, err = promptCode(os.Stdin, os.Stderr); err != nil {
				return err
			}
		}
	}
	if *deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *deadline)
		defer cancel()
	}
	b := tailnet.NewLocal(*socket)
	sctx, scancel := context.WithTimeout(ctx, *timeout)
	s, err := b.Status(sctx)
	scancel()
	if err != nil {
		return err
	}
	if mode == "send" {
		cacheDir := transfer.DefaultManifestCacheDir()
		if *noCache {
			cacheDir = ""
		}
		return send(ctx, b, s, fs.Arg(0), fs.Arg(1), *port, *timeout, *plaintext, *v1, cacheDir)
	}
	return receive(ctx, b, s, host, code, *port, *dir, *max, *timeout, *idle, *yes, *streams)
}

func send(ctx context.Context, b tailnet.Backend, status *tailnet.Status, path, host string, port int, timeout time.Duration, plaintext, v1 bool, cacheDir string) error {
	peer, err := tailnet.Resolve(status, host)
	if err != nil {
		return err
	}
	ip, err := tailnet.IP(status.Self)
	if err != nil {
		return err
	}
	authorize := func(ctx context.Context, addr string) error { return tailnet.Verify(ctx, b, addr, peer.ID) }
	if !plaintext {
		return sendE2E(ctx, status, peer, ip, path, port, timeout, authorize, cacheDir)
	}
	if !v1 {
		return sendV2(ctx, status, peer, ip, path, port, timeout, authorize, cacheDir)
	}
	s, err := transfer.NewSender(ctx, path, authorize)
	if err != nil {
		return err
	}
	defer s.Close()
	l, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return fmt.Errorf("listen on Tailscale address (requires the OS TUN interface): %w", err)
	}
	defer l.Close()
	// --timeout bounds only the wait for a receiver; once the first file request
	// begins, the sender's per-write deadline handles stalls.
	ctx, stop := waitForReceiver(ctx, timeout, s.Started())
	defer stop()
	fmt.Fprintf(os.Stderr, "Offering %q (%d bytes, plaintext v1) to %q [%s] only.\n", s.Offer.Name, s.Offer.Size, peer.DNSName, peer.ID)
	fmt.Fprintf(os.Stderr, "On that host run: tailbeam receive --plaintext %s%s\n", portFlag(port), status.Self.ID)
	if err := transfer.Serve(ctx, l, s); err != nil {
		return serveErr(ctx, err, timeout)
	}
	fmt.Fprintln(os.Stderr, "Receiver acknowledged the saved file.")
	return nil
}

func portFlag(port int) string {
	if port == transfer.DefaultPort {
		return ""
	}
	return fmt.Sprintf("--port %d ", port)
}

var errWaitTimeout = errors.New("wait timeout")

// waitForReceiver bounds ctx by timeout until started is closed; after that an
// active transfer is limited only by the sender's per-write deadlines.
func waitForReceiver(ctx context.Context, timeout time.Duration, started <-chan struct{}) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	wait := time.AfterFunc(timeout, func() { cancel(errWaitTimeout) })
	go func() {
		select {
		case <-started:
			wait.Stop()
		case <-ctx.Done():
		}
	}()
	return ctx, func() { wait.Stop(); cancel(nil) }
}

func serveErr(ctx context.Context, err error, timeout time.Duration) error {
	if errors.Is(context.Cause(ctx), errWaitTimeout) {
		return fmt.Errorf("timed out after %s waiting for the receiver", timeout)
	}
	return err
}

func sendV2(ctx context.Context, status *tailnet.Status, peer *tailnet.Node, ip, path string, port int, timeout time.Duration, authorize transfer.Authorize, cacheDir string) error {
	s, err := transfer.NewSenderV2(ctx, path, authorize, cacheDir)
	if err != nil {
		return err
	}
	defer s.Close()
	l, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return fmt.Errorf("listen on Tailscale address (requires the OS TUN interface): %w", err)
	}
	defer l.Close()
	ctx, stop := waitForReceiver(ctx, timeout, s.Started())
	defer stop()
	fmt.Fprintf(os.Stderr, "Offering %q (%d bytes, plaintext, resumable) to %q [%s] only.\n", s.Offer.Name, s.Offer.Size, peer.DNSName, peer.ID)
	fmt.Fprintf(os.Stderr, "On that host run: tailbeam receive --plaintext %s%s\n", portFlag(port), status.Self.ID)
	if err := transfer.ServeV2(ctx, l, s); err != nil {
		return serveErr(ctx, err, timeout)
	}
	fmt.Fprintln(os.Stderr, "Receiver acknowledged the saved file.")
	return nil
}

func sendE2E(ctx context.Context, status *tailnet.Status, peer *tailnet.Node, ip, path string, port int, timeout time.Duration, authorize transfer.Authorize, cacheDir string) error {
	code, err := e2e.NewCode()
	if err != nil {
		return err
	}
	s, err := transfer.NewSenderE2E(ctx, path, authorize, code, status.Self.ID, peer.ID, cacheDir)
	if err != nil {
		return err
	}
	defer s.Close()
	l, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return fmt.Errorf("listen on Tailscale address (requires the OS TUN interface): %w", err)
	}
	defer l.Close()
	ctx, stop := waitForReceiver(ctx, timeout, s.Started())
	defer stop()
	fmt.Fprintf(os.Stderr, "Offering %q (%d bytes, end-to-end encrypted, resumable) to %q [%s] only.\n", s.Name(), s.Size(), peer.DNSName, peer.ID)
	fmt.Fprintf(os.Stderr, "Transfer code: %s\n", code)
	fmt.Fprintf(os.Stderr, "On that host run: tailbeam receive %s%s:%s\n", portFlag(port), status.Self.ID, code)
	fmt.Fprintf(os.Stderr, "  (or run tailbeam receive %s%s and enter the code at the prompt)\n", portFlag(port), status.Self.ID)
	if err := transfer.ServeE2E(ctx, l, s); err != nil {
		return serveErr(ctx, err, timeout)
	}
	fmt.Fprintln(os.Stderr, "Receiver acknowledged the saved file.")
	return nil
}

// candidate is an offer found on a peer: decrypted in the default mode,
// plaintext with --plaintext.
type candidate struct {
	peer     *tailnet.Node
	name     string
	size     int64
	client   *http.Client
	download func(ctx context.Context, dir string, max int64, idle time.Duration, streams int) (string, error)
}

func (c candidate) close() { c.client.CloseIdleConnections() }

// probe fetches an offer from one authenticated peer.
type probe func(ctx context.Context, c *http.Client, base string, p *tailnet.Node) (candidate, error)

func plaintextProbe(ctx context.Context, c *http.Client, base string, p *tailnet.Node) (candidate, error) {
	r, err := transfer.FetchAnyOffer(ctx, c, base)
	if err != nil {
		return candidate{}, err
	}
	return candidate{p, r.Name, r.Size, c, func(ctx context.Context, dir string, max int64, idle time.Duration, streams int) (string, error) {
		r.Streams = streams
		return r.Download(ctx, c, base, p.ID, dir, max, idle)
	}}, nil
}

func e2eProbe(code e2e.Code, self string) probe {
	return func(ctx context.Context, c *http.Client, base string, p *tailnet.Node) (candidate, error) {
		o, err := transfer.FetchE2EOffer(ctx, c, base, code, p.ID, self)
		if err != nil {
			return candidate{}, err
		}
		return candidate{p, o.Name, o.Size, c, func(ctx context.Context, dir string, max int64, idle time.Duration, streams int) (string, error) {
			o.Streams = streams
			return o.Download(ctx, c, base, p.ID, dir, max, idle)
		}}, nil
	}
}

func receive(ctx context.Context, b tailnet.Backend, status *tailnet.Status, host string, code *e2e.Code, port int, dir string, max int64, timeout, idle time.Duration, yes bool, streams int) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("output path must be an existing directory")
	}
	var pinned *tailnet.Node
	if host != "" {
		pinned, err = tailnet.Resolve(status, host)
		if err != nil {
			return err
		}
	}
	fetch, mode := probe(plaintextProbe), "plaintext"
	if code != nil {
		fetch, mode = e2eProbe(*code, status.Self.ID), "end-to-end encrypted"
	}
	// --timeout bounds discovery only; the transfer itself is bounded by the
	// idle timeout (and --deadline, if set, via parent).
	parent := ctx
	ctx, stopWait := context.WithTimeout(ctx, timeout)
	defer stopWait()
	fmt.Fprintln(os.Stderr, "Waiting for an authorized offer…")
	var lastErr error
	for {
		var peers []*tailnet.Node
		if pinned != nil {
			peers = []*tailnet.Node{pinned}
		} else {
			status, err = b.Status(ctx)
			if err != nil {
				return err
			}
			for _, p := range status.Peer {
				if p != nil && p.Online && p.ID != "" {
					peers = append(peers, p)
				}
			}
			if len(peers) > 256 {
				return errors.New("more than 256 online peers; specify receive SENDER")
			}
		}
		sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
		found, probeErr, fatal := discover(ctx, b, peers, port, fetch)
		if fatal != nil && len(found) == 0 {
			return fatal
		}
		if probeErr != nil {
			lastErr = probeErr
		}
		if len(found) > 1 {
			for _, c := range found {
				c.close()
			}
			return errors.New("multiple offers; specify receive SENDER")
		}
		if len(found) == 1 {
			c := found[0]
			defer c.close()
			stopWait()
			if !yes {
				ok, err := accept(parent, os.Stdin, os.Stderr, c.peer.DNSName, c.peer.ID, c.name, c.size)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("transfer declined")
				}
			}
			fmt.Fprintf(os.Stderr, "Receiving %q (%d bytes, %s) from %q [%s].\n", c.name, c.size, mode, c.peer.DNSName, c.peer.ID)
			path, err := c.download(parent, dir, max, idle, streams)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Saved %q (SHA-256 verified).\n", path)
			return nil
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			if lastErr != nil {
				return fmt.Errorf("%w; last peer probe: %v", ctx.Err(), lastErr)
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// discover probes peers concurrently. A mode mismatch or a finished offer is
// fatal: polling again cannot help, and waiting silently would hide it.
func discover(ctx context.Context, b tailnet.Backend, peers []*tailnet.Node, port int, fetch probe) (found []candidate, lastErr, fatal error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, peer := range peers {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(p *tailnet.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			c, base, err := transfer.Client(b, p, port)
			var cand candidate
			if err == nil {
				cand, err = fetch(probeCtx, c, base, p)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				lastErr = err
				if errors.Is(err, transfer.ErrModeMismatch) || errors.Is(err, transfer.ErrOfferGone) {
					fatal = fmt.Errorf("%s [%s]: %w", p.DNSName, p.ID, err)
				}
				if c != nil {
					c.CloseIdleConnections()
				}
				return
			}
			found = append(found, cand)
		}(peer)
	}
	wg.Wait()
	return found, lastErr, fatal
}

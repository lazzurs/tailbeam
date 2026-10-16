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

	"github.com/linuskendall/tailbeam/internal/tailnet"
	"github.com/linuskendall/tailbeam/internal/transfer"
)

const usage = `tailbeam: single-file transfers authenticated by Tailscale

  tailbeam send [flags] FILE DESTINATION
  tailbeam receive [flags] [SENDER]

Start send first, then run receive on the destination. Both commands must remain
running during the transfer. Hosts may be MagicDNS names, Tailscale IPs, or node IDs.
Use receive SENDER to accept offers from only that host. Flags precede arguments.

Common flags: --port 8784 --timeout 1h --deadline 0 --socket PATH
  --timeout   how long to wait for a peer (send: until the receiver starts
              downloading; receive: until an offer is found)
  --deadline  absolute cap on the whole command, including an active transfer
              (default 0 = none)
Send flags: --v1 (serve protocol v1, without resume, for older receivers)
Receive flags: --dir . --max-bytes 1073741824 --idle-timeout 5m --yes
  --idle-timeout  abort a download when no bytes arrive for this long; an
                  interrupted v2 download resumes when receive is rerun
  --yes           accept without the interactive confirmation prompt
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
	var dir *string
	var max *int64
	var idle *time.Duration
	var yes *bool
	v1 := new(bool)
	if mode == "send" {
		v1 = fs.Bool("v1", false, "serve protocol v1 (no resume) for older receivers")
	}
	if mode == "receive" {
		idle = fs.Duration("idle-timeout", 5*time.Minute, "abort a download when no bytes arrive for this long")
		yes = fs.Bool("yes", false, "skip the confirmation prompt")
		dir = fs.String("dir", ".", "existing output directory")
		max = fs.Int64("max-bytes", 1<<30, "maximum accepted file size")
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
	if (mode == "send" && fs.NArg() != 2) || (mode == "receive" && fs.NArg() > 1) {
		return errors.New("usage: " + usage)
	}
	if max != nil && *max < 0 {
		return errors.New("max-bytes must be nonnegative")
	}
	if mode == "receive" && !*yes && !isTerminal(os.Stdin) {
		return errors.New("stdin is not a terminal; pass --yes to receive without confirmation")
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
		return send(ctx, b, s, fs.Arg(0), fs.Arg(1), *port, *timeout, *v1)
	}
	return receive(ctx, b, s, fs.Arg(0), *port, *dir, *max, *timeout, *idle, *yes)
}

func send(ctx context.Context, b tailnet.Backend, status *tailnet.Status, path, host string, port int, timeout time.Duration, v1 bool) error {
	peer, err := tailnet.Resolve(status, host)
	if err != nil {
		return err
	}
	ip, err := tailnet.IP(status.Self)
	if err != nil {
		return err
	}
	authorize := func(ctx context.Context, addr string) error { return tailnet.Verify(ctx, b, addr, peer.ID) }
	if !v1 {
		return sendV2(ctx, status, peer, ip, path, port, timeout, authorize)
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
	fmt.Fprintf(os.Stderr, "Offering %q (%d bytes) to %q [%s] only.\n", s.Offer.Name, s.Offer.Size, peer.DNSName, peer.ID)
	fmt.Fprintf(os.Stderr, "On that host run: tailbeam receive --port %d %s\n", port, status.Self.ID)
	if err := transfer.Serve(ctx, l, s); err != nil {
		return serveErr(ctx, err, timeout)
	}
	fmt.Fprintln(os.Stderr, "Receiver acknowledged the saved file.")
	return nil
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

func sendV2(ctx context.Context, status *tailnet.Status, peer *tailnet.Node, ip, path string, port int, timeout time.Duration, authorize transfer.Authorize) error {
	s, err := transfer.NewSenderV2(ctx, path, authorize)
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
	fmt.Fprintf(os.Stderr, "Offering %q (%d bytes, resumable) to %q [%s] only.\n", s.Offer.Name, s.Offer.Size, peer.DNSName, peer.ID)
	fmt.Fprintf(os.Stderr, "On that host run: tailbeam receive --port %d %s\n", port, status.Self.ID)
	if err := transfer.ServeV2(ctx, l, s); err != nil {
		return serveErr(ctx, err, timeout)
	}
	fmt.Fprintln(os.Stderr, "Receiver acknowledged the saved file.")
	return nil
}

type candidate struct {
	peer   *tailnet.Node
	offer  transfer.Remote
	client *http.Client
	base   string
}

func (c candidate) close() { c.client.CloseIdleConnections() }

func receive(ctx context.Context, b tailnet.Backend, status *tailnet.Status, host string, port int, dir string, max int64, timeout, idle time.Duration, yes bool) error {
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
		found, probeErr := discover(ctx, b, peers, port)
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
				ok, err := accept(parent, os.Stdin, os.Stderr, c.peer.DNSName, c.peer.ID, c.offer.Name, c.offer.Size)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("transfer declined")
				}
			}
			fmt.Fprintf(os.Stderr, "Receiving %q (%d bytes) from %q [%s].\n", c.offer.Name, c.offer.Size, c.peer.DNSName, c.peer.ID)
			path, err := c.offer.Download(parent, c.client, c.base, c.peer.ID, dir, max, idle)
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

func discover(ctx context.Context, b tailnet.Backend, peers []*tailnet.Node, port int) ([]candidate, error) {
	var mu sync.Mutex
	var found []candidate
	var lastErr error
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
			var o transfer.Remote
			if err == nil {
				o, err = transfer.FetchAnyOffer(probeCtx, c, base)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				lastErr = err
				if c != nil {
					c.CloseIdleConnections()
				}
				return
			}
			found = append(found, candidate{p, o, c, base})
		}(peer)
	}
	wg.Wait()
	return found, lastErr
}

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

Common flags: --port 8784 --timeout 1h --socket PATH
Receive flags: --dir . --max-bytes 1073741824
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
	timeout := fs.Duration("timeout", time.Hour, "maximum total waiting and transfer time")
	socket := fs.String("socket", "", "Tailscale daemon socket (default: LocalAPI platform default)")
	var dir *string
	var max *int64
	if mode == "receive" {
		dir = fs.String("dir", ".", "existing output directory")
		max = fs.Int64("max-bytes", 1<<30, "maximum accepted file size")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *port < 1 || *port > 65535 || *timeout <= 0 {
		return errors.New("port must be 1..65535 and timeout must be positive")
	}
	if (mode == "send" && fs.NArg() != 2) || (mode == "receive" && fs.NArg() > 1) {
		return errors.New("usage: " + usage)
	}
	if max != nil && *max < 0 {
		return errors.New("max-bytes must be nonnegative")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	b := tailnet.NewLocal(*socket)
	s, err := b.Status(ctx)
	if err != nil {
		return err
	}
	if mode == "send" {
		return send(ctx, b, s, fs.Arg(0), fs.Arg(1), *port)
	}
	return receive(ctx, b, s, fs.Arg(0), *port, *dir, *max)
}

func send(ctx context.Context, b tailnet.Backend, status *tailnet.Status, path, host string, port int) error {
	peer, err := tailnet.Resolve(status, host)
	if err != nil {
		return err
	}
	ip, err := tailnet.IP(status.Self)
	if err != nil {
		return err
	}
	s, err := transfer.NewSender(ctx, path, func(ctx context.Context, addr string) error { return tailnet.Verify(ctx, b, addr, peer.ID) })
	if err != nil {
		return err
	}
	defer s.Close()
	l, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return fmt.Errorf("listen on Tailscale address (requires the OS TUN interface): %w", err)
	}
	defer l.Close()
	fmt.Fprintf(os.Stderr, "Offering %q (%d bytes) to %q [%s] only.\n", s.Offer.Name, s.Offer.Size, peer.DNSName, peer.ID)
	fmt.Fprintf(os.Stderr, "On that host run: tailbeam receive --port %d %s\n", port, status.Self.ID)
	if err := transfer.Serve(ctx, l, s); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Receiver acknowledged the saved file.")
	return nil
}

type candidate struct {
	peer   *tailnet.Node
	offer  transfer.Offer
	client *http.Client
	base   string
}

func (c candidate) close() { c.client.CloseIdleConnections() }

func receive(ctx context.Context, b tailnet.Backend, status *tailnet.Status, host string, port int, dir string, max int64) error {
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
			fmt.Fprintf(os.Stderr, "Receiving %q (%d bytes) from %q [%s].\n", c.offer.Name, c.offer.Size, c.peer.DNSName, c.peer.ID)
			path, err := transfer.Download(ctx, c.client, c.base, c.offer, dir, max)
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
			var o transfer.Offer
			if err == nil {
				o, err = transfer.FetchOffer(probeCtx, c, base)
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

// Package tailnet obtains identities from the local, trusted Tailscale daemon
// through the official Go LocalAPI client. No identity supplied by a remote HTTP
// peer is trusted.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

type Node struct {
	ID           string
	DNSName      string
	HostName     string
	TailscaleIPs []string
	Online       bool
	Tags         []string
	// CapMap holds node attributes (policy nodeAttrs) from the daemon's netmap.
	CapMap tailcfg.NodeCapMap
}

type Status struct {
	BackendState string
	Self         *Node
	Peer         map[string]*Node
}

type WhoIsNode struct {
	StableID  string
	Addresses []netip.Prefix
}

type Identity struct {
	Node        *WhoIsNode
	UserProfile *struct{ LoginName string }
	// CapMap holds the app capabilities the identified peer has toward this
	// node, computed by the local daemon from the tailnet policy.
	CapMap tailcfg.PeerCapMap
}

type Backend interface {
	Status(context.Context) (*Status, error)
	WhoIs(context.Context, string) (*Identity, error)
}

// Local uses the typed LocalAPI client against the existing host daemon,
// rather than enrolling an application-owned tsnet node.
type Local struct{ client *local.Client }

func NewLocal(socket string) *Local {
	return &Local{client: &local.Client{Socket: socket, UseSocketOnly: socket != ""}}
}

func node(p *ipnstate.PeerStatus) *Node {
	if p == nil {
		return nil
	}
	n := &Node{ID: string(p.ID), DNSName: p.DNSName, HostName: p.HostName, Online: p.Online}
	for _, ip := range p.TailscaleIPs {
		n.TailscaleIPs = append(n.TailscaleIPs, ip.String())
	}
	if p.Tags != nil {
		n.Tags = p.Tags.AsSlice()
	}
	n.CapMap = p.CapMap
	return n
}

func (c *Local) Status(ctx context.Context) (*Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, err := c.client.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("Tailscale status (is the local daemon accessible?): %w", err)
	}
	if s == nil || s.BackendState != "Running" || s.Self == nil || s.Self.ID == "" {
		return nil, errors.New("Tailscale must be logged in and running")
	}
	out := &Status{BackendState: s.BackendState, Self: node(s.Self), Peer: make(map[string]*Node)}
	for k, p := range s.Peer {
		out.Peer[k.String()] = node(p)
	}
	return out, nil
}

func (c *Local) WhoIs(ctx context.Context, addr string) (*Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, err := c.client.WhoIs(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("Tailscale identity: %w", err)
	}
	if id == nil || id.Node == nil || id.Node.StableID == "" {
		return nil, errors.New("Tailscale did not identify the connection")
	}
	return &Identity{Node: &WhoIsNode{StableID: string(id.Node.StableID), Addresses: id.Node.Addresses}, CapMap: id.CapMap}, nil
}

// Resolve matches only daemon-supplied peer names/addresses, never public DNS.
// Ambiguous short names fail closed. HostName is intentionally not used because
// it is not necessarily unique and can be advertised by another node.
func Resolve(s *Status, name string) (*Node, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil, errors.New("empty host name")
	}
	var found *Node
	for _, n := range s.Peer {
		if n == nil || n.ID == "" {
			continue
		}
		dns := strings.ToLower(strings.TrimSuffix(n.DNSName, "."))
		match := name == dns || (dns != "" && name == strings.Split(dns, ".")[0]) || name == strings.ToLower(n.ID)
		for _, ip := range n.TailscaleIPs {
			match = match || ip == name
		}
		if match {
			if found != nil && found.ID != n.ID {
				return nil, fmt.Errorf("ambiguous host %q; use a full MagicDNS name or Tailscale IP", name)
			}
			found = n
		}
	}
	if found == nil {
		return nil, fmt.Errorf("host %q is not a visible Tailscale peer", name)
	}
	return found, nil
}

func IP(n *Node) (string, error) {
	for _, s := range n.TailscaleIPs {
		a, err := netip.ParseAddr(s)
		if err == nil && IsTailscaleIP(a) {
			return a.String(), nil
		}
	}
	return "", errors.New("node has no Tailscale address")
}

func IsTailscaleIP(a netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(a) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(a)
}

// Verify checks both the node ID and address ownership reported by the daemon.
// Forwarded-for headers and HTTP identity claims are deliberately ignored.
func Verify(ctx context.Context, b Backend, addr string, expected string) error {
	_, err := VerifyIdentity(ctx, b, addr, expected)
	return err
}

// VerifyIdentity is Verify, returning the verified identity so callers can
// evaluate the app capabilities it carries.
func VerifyIdentity(ctx context.Context, b Backend, addr string, expected string) (*Identity, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !IsTailscaleIP(a) {
		return nil, errors.New("connection is not from a Tailscale address")
	}
	id, err := b.WhoIs(ctx, addr)
	if err != nil {
		return nil, err
	}
	if id == nil || id.Node == nil || id.Node.StableID == "" || id.Node.StableID != expected {
		return nil, errors.New("unexpected Tailscale node identity")
	}
	for _, ip := range id.Node.Addresses {
		if ip.Addr() == a && ip.IsSingleIP() {
			return id, nil
		}
	}
	return nil, errors.New("Tailscale identity does not own the connection address")
}

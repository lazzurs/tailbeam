package tailnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"tailscale.com/tailcfg"
)

// Tailnet policy can restrict tailbeam with an application capability. Values
// come only from the local daemon (WhoIs/Status), which computes them from the
// policy delivered by the control plane; a peer cannot supply or alter them.
//
// A grant reaches only its destination node, so each side checks the
// capability the *other* side holds toward it:
//
//   - the sender checks that the connecting receiver holds "receive";
//   - the receiver checks (WhoIs on the sender's address) that the sender
//     holds "send".
//
// This is an addition to stable node ID pinning, never a replacement for it.
// The domain is a placeholder for one the project controls.
const (
	CapTailbeam  tailcfg.PeerCapability = "linuskendall.com/cap/tailbeam"
	AttrTailbeam tailcfg.NodeCapability = "linuskendall.com/cap/tailbeam-node"
)

type Action string

const (
	ActionSend    Action = "send"
	ActionReceive Action = "receive"
)

// Grant is one value of CapTailbeam. A missing maxBytes means no limit.
type Grant struct {
	Actions    []Action `json:"actions"`
	MaxBytes   *int64   `json:"maxBytes,omitempty"`
	RequireE2E bool     `json:"requireE2E,omitempty"`
}

// Request describes the transfer a peer wants to take part in.
type Request struct {
	Action Action
	Size   int64
	E2E    bool
}

// strictDecode rejects unknown fields and trailing data. An unknown field may
// be a restriction added by a newer policy, so ignoring it could grant more
// than the administrator intended.
func strictDecode(raw tailcfg.RawMessage, v any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// ParseGrants decodes every CapTailbeam value. Invalid entries grant nothing
// and are reported, so one typo fails closed without hiding other grants.
func ParseGrants(cm tailcfg.PeerCapMap) (grants []Grant, invalid []error) {
	for i, raw := range cm[CapTailbeam] {
		var g Grant
		err := strictDecode(raw, &g)
		if err == nil {
			err = g.validate()
		}
		if err != nil {
			invalid = append(invalid, fmt.Errorf("%s value %d: %w", CapTailbeam, i, err))
			continue
		}
		grants = append(grants, g)
	}
	return grants, invalid
}

func (g Grant) validate() error {
	if len(g.Actions) == 0 {
		return errors.New("no actions")
	}
	for _, a := range g.Actions {
		if a != ActionSend && a != ActionReceive {
			return fmt.Errorf("unknown action %q", a)
		}
	}
	if g.MaxBytes != nil && *g.MaxBytes < 0 {
		return errors.New("negative maxBytes")
	}
	return nil
}

// ErrNotGranted means no grant mentions the requested action.
var ErrNotGranted = errors.New("not granted by tailnet policy")

// Evaluate permits r if any single grant permits it. Grants add to one another,
// as Tailscale merges them, so each value is judged as a unit: a broad entry
// without limits is not narrowed by a stricter one.
func Evaluate(grants []Grant, r Request) error {
	var tooLarge, needE2E bool
	var largest int64 = -1
	for _, g := range grants {
		if !hasAction(g.Actions, r.Action) {
			continue
		}
		if g.MaxBytes != nil && r.Size > *g.MaxBytes {
			tooLarge, largest = true, max(largest, *g.MaxBytes)
			continue
		}
		if g.RequireE2E && !r.E2E {
			needE2E = true
			continue
		}
		return nil
	}
	switch {
	case needE2E:
		return fmt.Errorf("%q requires end-to-end encryption under tailnet policy", r.Action)
	case tooLarge:
		return fmt.Errorf("%q is limited to %d bytes under tailnet policy (file is %d)", r.Action, largest, r.Size)
	}
	return fmt.Errorf("%q %w", r.Action, ErrNotGranted)
}

func hasAction(as []Action, a Action) bool {
	for _, x := range as {
		if x == a {
			return true
		}
	}
	return false
}

// Mode is how a node applies the capability.
type Mode int

const (
	ModeOff Mode = iota
	ModeWarn
	ModeEnforce
)

func ParseMode(s string) (Mode, error) {
	switch s {
	case "off":
		return ModeOff, nil
	case "warn":
		return ModeWarn, nil
	case "enforce":
		return ModeEnforce, nil
	}
	return ModeEnforce, fmt.Errorf("unknown policy mode %q (use off, warn, or enforce)", s)
}

// NodeMode reads the administrator's mode from this node's own AttrTailbeam
// attribute. The strictest value wins, and an invalid one enforces.
func NodeMode(cm tailcfg.NodeCapMap) (Mode, error) {
	mode := ModeOff
	var errs []error
	for i, raw := range cm[AttrTailbeam] {
		var v struct {
			Mode string `json:"mode"`
		}
		err := strictDecode(raw, &v)
		m := ModeEnforce
		if err == nil {
			m, err = ParseMode(v.Mode)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s value %d: %w", AttrTailbeam, i, err))
		}
		mode = max(mode, m)
	}
	return mode, errors.Join(errs...)
}

// Check applies mode to the peer's capabilities. In warn mode a denial is
// returned as a warning and the transfer proceeds; in enforce mode it is an
// error. Invalid grant entries are always reported as warnings.
func Check(mode Mode, cm tailcfg.PeerCapMap, r Request) (warnings []string, err error) {
	if mode == ModeOff {
		return nil, nil
	}
	grants, invalid := ParseGrants(cm)
	for _, e := range invalid {
		warnings = append(warnings, "ignoring invalid policy entry: "+e.Error())
	}
	if err := Evaluate(grants, r); err != nil {
		if mode == ModeWarn {
			return append(warnings, "policy would deny: "+err.Error()), nil
		}
		return warnings, err
	}
	return warnings, nil
}

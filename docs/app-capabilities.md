# Tailnet policy control with application capabilities

Researched 2026-10-17 against the Tailscale docs and `tailscale.com` v1.104.1
(the version tailbeam pins). This is a design with a tested prototype
(`internal/tailnet/capability.go`); the CLI is not wired to it yet.

**Recommendation.** Use one custom app capability, checked on *both* ends, on
top of the existing stable-ID pinning:

- the **sender** checks that the connecting receiver holds `receive` toward it;
- the **receiver** checks that the sender holds `send` toward it.

Each side reads the capability the *other* node holds toward *itself*, via
`WhoIs`. That is the only direction Tailscale delivers. Receiver-side
enforcement therefore works without a reverse connection. For hard limits on
who can pull files at all, the network grant on `tcp:8784` remains the stronger
lever: `tailscaled` enforces it, whatever binary the user runs.

## How app capabilities work

Sources: [grants syntax](https://tailscale.com/docs/reference/syntax/grants),
[app capabilities](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities),
[policy file: nodeAttrs](https://tailscale.com/docs/reference/syntax/policy-file).
Source paths below are under the module cache, `tailscale.com@v1.104.1/`.

- **Policy syntax.** A grant's `app` field maps `<domain>/<name>` to an array
  of JSON objects. `tailscale.com` and `tailscale.io` are reserved; a custom
  capability should use a domain you control. The policy engine checks only
  that values are valid JSON, and the application interprets them.
- **Merging.** Matching grants add to each other; a more specific grant does
  not override a broader one. In the code, values for one capability are
  appended across matching rules (`wgengine/filter/filter.go:410-435`).
- **Delivery.** Control sends the grant to the **destination** node as a packet
  filter rule with `CapGrant` (`tailcfg/tailcfg.go:1580-1595`, `1764-1774`).
  `tailcfg.Node.CapMap`'s comment lists three channels (`tailcfg/tailcfg.go:477-485`):
  - the node's own `CapMap`, which holds node attributes;
  - the `PacketFilter`, which holds access granted *to peers*;
  - peers' `CapMap`, which holds attributes about peers.
- **Reading.** The LocalAPI `/whois?addr=IP[:port]` handler fills
  `apitype.WhoIsResponse.CapMap` (`client/tailscale/apitype/apitype.go:35-42`)
  from `PeerCaps(src)` (`ipn/localapi/localapi.go:596-619`). That function
  computes the capabilities the *remote* IP has toward this node's own
  addresses from the local filter (`ipn/ipnlocal/node_backend.go:407-466`). The
  type is `tailcfg.PeerCapMap` = `map[peercap.Cap][]RawMessage`, decoded with
  `tailcfg.UnmarshalCapJSON` (`tailcfg/tailcfg.go:1672-1712`).
- **Precedent.** Setec reads `tailscale.com/cap/secrets` from `WhoIs` `CapMap`
  the same way ([`server.go#L330`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/server/server.go#L330)).
- **Node attributes.** `nodeAttrs` entries take `target`, `attr` and `app`.
  `app` values land in the target node's *own* `CapMap`, which LocalAPI
  `Status` exposes as `Self.CapMap` (`ipn/ipnlocal/local.go:1565-1570`;
  `ipn/ipnstate/ipnstate.go:312-313`). App connectors read their configuration
  this way (`ipn/ipnlocal/local.go:6001`).

## Directionality

Tailbeam's receiver opens the TCP connection to the sender. Grants, though, are
visible only at their `dst`, and a `WhoIs` lookup is a pure function of the
peer's IP. Neither needs a connection in any particular direction.

| Question | Answer |
| --- | --- |
| (a) Can the sender enforce "this receiver may receive from me"? | **Yes.** Grant `src: receiver, dst: sender`. The sender is the dst, and the `WhoIs` it already runs on each request returns the receiver's capability. It is re-checked on every request, so revoking mid-transfer stops the next v2 range read. |
| (b) Can the receiver enforce "I may receive from this sender"? | **Yes, without a reverse connection.** Grant `src: sender, dst: receiver`. The receiver is that grant's dst. `WhoIs(senderIP)`, which `Verify` already calls when dialing, computes `PeerCaps(src=sender)` toward the receiver. The receiver never sees grants where *it* is the src: they are not in its filter, and peers' `CapMap` carries attributes, not grants. |
| (c) Can tailbeam be switched off for a node? | `nodeAttrs` `app` on the node itself (`Self.CapMap`) can set a mode, but only that node's own binary enforces it, so a user can bypass it on their own machine. The robust switch is the **network** grant: a node with no `tcp:8784` path to senders cannot pull, enforced by `tailscaled`. |
| (d) Can a peer spoof a capability? | **No.** Values come from the local daemon's netmap as delivered by control; nothing a peer sends is consulted. A malicious control plane can grant anything (tailnet lock strips caps only from unsigned peers, `node_backend.go:429-441`). Caps are keyed by IP, so they share the IP-binding caveat of `Verify` (review finding 2). |
| Reverse "doorbell" connection? | **Not needed for capabilities.** It would give the receiver the same `WhoIs(senderIP)` answer it can already get. A doorbell may still be worth it for discovery (review finding 7), but that is a separate decision. |

What each enforcing side guarantees:

| Enforced by | Protects | Bypassed by |
| --- | --- | --- |
| Sender | Data leaving the sender goes only to granted receivers, within size and E2E limits | A modified binary *on the sender*. The sender's own user can always leak their file by other means; this is a guardrail, not data-loss prevention |
| Receiver | The receiver accepts files only from granted senders (stops planting) | A modified binary *on the receiver* |
| Network grant `tcp:8784` (receiver to sender) | Whether the receiver can connect at all | Nothing at the application level; `tailscaled` enforces it |

## Policy design

Capability `linuskendall.com/cap/tailbeam`. The domain is a placeholder for one
the project controls; it must not be under `tailscale.com`. Each value:

```json
{"actions": ["send", "receive"], "maxBytes": 10737418240, "requireE2E": true}
```

- `actions` (required): `send` is checked by the receiver, `receive` by the sender.
- `maxBytes` (optional): an absent field means no limit; a negative value is invalid.
- `requireE2E` (optional): plaintext mode is refused.
- Filename patterns are left out. Globs over names are weak, and names are
  sender-chosen.

**Evaluation.** A request is allowed if **any single value** allows it. Each
value is judged as a unit, matching Tailscale's additive merge. One
consequence: an unlimited entry from a broad grant defeats a limited one from a
narrow grant. Admins must put limits on every entry that matches the people
they mean to limit.

**Unknown fields fail closed per entry.** A field we don't understand may be a
restriction from a newer policy, and ignoring it would grant more than
intended. That entry grants nothing and produces a warning; other valid entries
still apply. Typos in action names are handled the same way.

**Modes.**
- `off`: today's behaviour.
- `warn`: evaluate and print what would be denied.
- `enforce`: deny unless granted.

The admin sets the mode with a node attribute, so users cannot lower it:

```json
"nodeAttrs": [{"target": ["tag:build"], "app": {"linuskendall.com/cap/tailbeam-node": [{"mode": "enforce"}]}}]
```

A `--policy=off|warn|enforce` flag may only **raise** the mode. With no
attribute and no flag, the mode is `off`. If several entries apply, the
strictest wins, and an invalid entry means `enforce`.

**Layering.** Capability checks run only after `VerifyIdentity` has confirmed
the pinned stable ID and address ownership; they never replace it. Network
grants still decide connectivity, and the receiver needs `tcp:8784` toward the
sender as today.

## Prototype

- `internal/tailnet/capability.go`:
  - capability constants;
  - strict `ParseGrants`, rejecting unknown fields and trailing data;
  - `Evaluate`, `NodeMode` and `Check(mode, capMap, Request)`.
- `internal/tailnet/tailnet.go` (small edits): `Identity.CapMap` from `WhoIs`,
  `Node.CapMap` from `Status`, and `VerifyIdentity`, which `Verify` now wraps.
- Tests (`capability_test.go`):
  - strict parsing;
  - additive evaluation, size and E2E limits;
  - modes, with the strictest node attribute winning;
  - `CapMap` surviving LocalAPI decoding for both `WhoIs` and `Status`.

**Wiring plan, deferred to avoid conflicts with the E2E branch:**
- **Sender:** the `authorize` closure calls `VerifyIdentity`, then
  `Check(mode, id.CapMap, {receive, size, e2e})`.
- **Receiver:** after the offer, or after decrypting it in E2E mode, call
  `VerifyIdentity` on the sender's address and `Check(..., {send, size, e2e})`
  before the confirmation prompt.
- **Mode:** comes from `NodeMode(status.Self.CapMap)`, raised by the flag.
- **Sender's 403:** may say "denied by tailnet policy". The peer has already
  been identified as the pinned receiver, so this tells it only that the
  policy said no.

## Admin examples

Merge these into an existing policy. The `ip` grants on `tcp:8784` (receiver to
sender) are still needed for connectivity.

1. **Only eng may receive from build servers.** Build servers enforce.
   ```json
   "grants": [{"src": ["group:eng"], "dst": ["tag:build"], "ip": ["tcp:8784"],
               "app": {"linuskendall.com/cap/tailbeam": [{"actions": ["receive"]}]}}],
   "nodeAttrs": [{"target": ["tag:build"], "app": {"linuskendall.com/cap/tailbeam-node": [{"mode": "enforce"}]}}]
   ```
   Granting `tcp:8784` only to `group:eng` gives the same rule at network level,
   without trusting the binary.
2. **Nobody may send to `tag:prod`.** Prod nodes run in `enforce` mode and no
   grant gives anyone `send` toward `tag:prod`. Stronger still: grant prod no
   `tcp:8784` path to any sender. Prod can then never pull, whatever binary it
   runs.
3. **Require E2E for contractors.**
   ```json
   {"src": ["group:contractors"], "dst": ["tag:file-server"],
    "app": {"linuskendall.com/cap/tailbeam": [{"actions": ["receive"], "requireE2E": true}]}}
   ```
   Make sure no broader grant, such as `autogroup:member` receive without
   `requireE2E`, also matches contractors, because grants add.
4. **Disable tailbeam for a group.** Give the group no `tcp:8784` grant toward
   anyone (network level), and no `send`/`receive` capabilities, with peers in
   `enforce` mode. A node attribute alone is self-enforced and can be bypassed
   on the user's own machine.

**Messages users would see:**
- Sender, enforce: `denied <receiver> [nID]: "receive" not granted by tailnet policy`
- Receiver, enforce: `sender <host> [nID] is not allowed to send to this node: "send" not granted by tailnet policy`
- Size: `"receive" is limited to 10737418240 bytes under tailnet policy (file is 21474836480)`
- E2E: `"receive" requires end-to-end encryption under tailnet policy`; remove `--plaintext`
- Warn mode: `warning: policy would deny: …` and the transfer proceeds
- Invalid policy: `warning: ignoring invalid policy entry: linuskendall.com/cap/tailbeam value 1: json: unknown field "filenames"`

## Live test (2026-10-17)

Tested on the `royal-banfish.ts.net` tailnet between mini-ws and khb-pve11,
with temporary grants under `linuskendall.com/cap/tailbeam-test` and
`linuskendall.com/cap/tailbeam-node-test`. They were added in
linuskendall/khb-setup#304 and removed in #305. Both nodes already had network
access in both directions.

| Check | Result |
| --- | --- |
| Sender (mini-ws) `WhoIs` of the receiver | receiver's `receive` grant visible |
| Receiver (khb-pve11) `WhoIs` of the sender | sender's `send` grant visible; receiver-side enforcement works without a reverse connection |
| mini-ws `Self.CapMap` | custom-domain `nodeAttrs` `app` value visible, so the admin mode can come from policy |
| khb-pve12 `WhoIs` of mini-ws (control) | no capability |
| `ParseGrants` / `Check` in enforce mode on the live values | allowed and denied exactly as granted (action, `maxBytes`, `requireE2E`) |

## Open questions

1. **Is a cap-only grant delivered without network access?** The docs say app
   capabilities "apply only if the device has network-level access". The live
   test could not settle this: both nodes already had broad network access, and
   removing it was out of scope. Until it is verified, document that the
   receiver-side grant (sender to receiver) may need a harmless `ip` rule in that
   direction.
2. **Capability domain:** `linuskendall.com` (decided). The names are
   `linuskendall.com/cap/tailbeam` and `linuskendall.com/cap/tailbeam-node`.
3. **Should `warn` be the default** when a tailnet uses the capability at all,
   that is, when a peer's `CapMap` has the key? Absence is exactly the denial
   case, so that signal can't be relied on in general.
4. **Shared or multi-user nodes:** capabilities are per node, like the rest of
   the model. Pairing them with the E2E code addresses the per-user part.

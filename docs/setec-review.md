# Setec security and integration review

Reviewed 2026-10-15 against
[`tailscale/setec` at `bc168fdb236279b5c5a43d14685df674d7fefb35`](https://github.com/tailscale/setec/tree/bc168fdb236279b5c5a43d14685df674d7fefb35).
This is a source-level comparison and implementation review, not an independent
security audit or a live tailnet deployment test.

The core approach is consistent with Setec: authenticate the actual connection
using the trusted daemon's WhoIs result, then apply a separate authorization
decision before releasing data. The initial implementation missed Setec's browser
defense and used CLI JSON instead of the official LocalAPI SDK. Both were changed.
Tailbeam deliberately retains the existing host's identity rather than enrolling
an application-specific node. It does not claim feature or assurance parity with
Setec's persistent secrets service.

## Evidence and comparison

| Concern | Setec implementation | Tailbeam decision |
| --- | --- | --- |
| Network identity | [`getIdentity`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/server/server.go#L307) calls the injected LocalAPI `WhoIs` with `r.RemoteAddr`. | Uses the official `client/local` SDK and the actual socket address. No forwarded headers or remote identity claims. Rejects failed or incomplete lookups. |
| Listener isolation | [`runServer`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/cmd/setec/setec.go#L264) creates a `tsnet.Server`, with its own keys, state directory and node enrollment. | Binds only the existing host's daemon-supplied Tailscale IP. Appropriate for a temporary host-to-host offer; requires an OS TUN interface and trusted OS routing. Does not support userspace-only mode. |
| Application authorization | [`getIdentity`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/server/server.go#L330) reads `tailscale.com/cap/secrets` from WhoIs `CapMap`; [`acl.Rule`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/acl/acl.go#L51) checks actions and secret patterns. Network access alone does not grant secret access. | Network access alone does not grant file access. Starting `send FILE HOST` creates a temporary application authorization for exactly HOST's stable node ID and one offered file. There are no central per-file app grants in this version. |
| Human versus machine principals | Setec records the user login of an untagged node, or tags for tagged nodes, and evaluates the supplied capabilities. | Authorization pins a machine, including a tagged machine. It does not authenticate a particular local OS user or independently pin a human owner. Shared-host processes share access. This is a material security boundary. |
| Browser attacks | [`serveJSON`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/server/server.go#L350) requires POST, JSON content type, and `Sec-X-Tailscale-No-Browsers: setec`. | Adopted the forbidden `Sec-*` header pattern with an app-specific value on **all** endpoints. Also rejects `Origin` and `Sec-Fetch-Site`. The native streaming protocol retains GET for metadata and file data; the forbidden header is mandatory regardless of method. |
| Encryption | [`ListenTLS`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/cmd/setec/setec.go#L329) provides HTTPS in addition to WireGuard, with a tailnet certificate and HTTPS identity. | HTTP inside WireGuard with daemon-verified node identity on both ends. No certificate issuance or HTTPS requirement. This has fewer independent transport protections than Setec and relies on the trusted daemon and OS path; it must never be served through a public/proxy endpoint. |
| Client identity of server | Setec's normal client uses HTTPS certificate validation through `http.DefaultClient`. | Pins a daemon-resolved address and stable node ID and verifies WhoIs before sending HTTP on each new TCP connection. Redirects and HTTP proxies are disabled. |
| Audit | [`audit.Writer`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/audit/audit.go#L49) persists action, authorization, principal and timestamp records. | Emits transfer status to stderr. No durable audit ledger. Appropriate only if persistent auditing is not required. |
| Stored secrets | Setec supports KMS/TPM-backed key management, encrypted storage and backups. | No persistent application database. Source and verified output are ordinary user files. It does not encrypt either file at rest. |
| Test boundary | [`setectest`](https://github.com/tailscale/setec/blob/bc168fdb236279b5c5a43d14685df674d7fefb35/setectest/server.go) injects identities for server tests. | Uses mocked identities plus real loopback HTTP, and exercises the official LocalAPI decoder using fixture responses. This validates app behavior, not real tailnet enrollment, WireGuard, or routing. |

## Fixed: browser access from an authorized host

Before this review, a browser on the intended destination could satisfy the
node-level identity check. Cross-origin restrictions alone are insufficient:
DNS rebinding can make an attacker-controlled origin address the sender while
remaining same-origin from the browser's perspective. Browser-triggered requests
could also consume an offer or initiate unwanted downloads.

The server now requires `Sec-X-Tailscale-No-Browsers: tailbeam` before doing
identity lookup or returning data. Browser JavaScript cannot set headers with
the `Sec-` prefix, while normal navigations and form submissions do not supply
this header. No CORS access is enabled. Requests with an Origin or fetch metadata
are rejected even if they also supply the guard. Native clients must still pass
the exact-node authorization check; knowledge of this public header grants no
file access.

Regression tests cover missing and incorrect guards, Origin and fetch metadata,
rebinding-style Host values without the guard, every data/ack endpoint, and
unauthorized native clients that do supply the guard. The client sets the guard
for metadata, streaming and acknowledgement requests.

## Improved: typed LocalAPI integration

The first version invoked `tailscale status --json` and `tailscale whois --json`.
Those query the same daemon but add subprocess overhead and manually decoded
schemas. The revised implementation uses Setec's `tailscale.com/client/local`
API directly, pinned to Tailscale SDK v1.104.1. The SDK handles daemon socket
selection and platform-specific local authentication. A specified socket is
used exclusively.

The app still verifies the stable node ID rather than the numeric node ID. It
requires the exact remote address to appear as a single-node address prefix,
not merely within a routed subnet. Tests exercise typed SDK decoding, status-to-
peer conversion, absent stable IDs, null/malformed replies, wrong nodes and
address mismatches. Each daemon call has a five-second maximum.

## Deployment limits and follow-up decisions

* Test a real transfer and a third-node rejection on the target tailnet. This
  environment has no configured Tailscale daemon or tailnet credentials; mocked
  tests cannot establish deployment correctness.
* For distinct per-application identity, userspace networking, service discovery,
  or long-lived deployments, add a separate `tsnet` mode with its own enrollment
  and state. This changes what destination host identity means and should be an
  explicit mode rather than silently replacing the user's host identity.
* For centralized resource/action policy, add application grants evaluated from
  `WhoIs.CapMap` **in addition to** exact recipient-node pinning. Setec's secrets
  capability is not a file-transfer permission and must not be reused.
* For deployments requiring independently authenticated HTTPS, add a certificate-
  backed mode with verified names and no plaintext fallback. The present release
  relies on Tailscale's encryption and trusted host routing.
* Shared hosts need additional per-user authentication or OS isolation. Choosing
  a machine is not equivalent to choosing a human login.

These are explicit differences from Setec, not claims that its protections are
unnecessary. The current scope is one temporary file offer to one existing host.

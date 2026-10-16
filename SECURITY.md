# Security model

This is an initial implementation, not an independently audited transfer system.

## Trust and authorization

The local Tailscale daemon is the identity authority, queried through the official
`tailscale.com/client/local` Go SDK. No CLI subprocesses or extra auth keys are used.
All identities come from that daemon, never from HTTP headers or offer JSON.
Status returns a stable ID in `Peer.ID`; WhoIs returns it in `Node.StableID`,
with node-owned address prefixes in `Node.Addresses`. Numeric `WhoIs.Node.ID`,
display hostnames, user login names, and routed `AllowedIPs` do not establish
authorization. The actual TCP IP must exactly match a single-address prefix in
the authenticated node's owned addresses.

Both peers pin the selected stable ID for the operation. Replacing a node under
the same DNS name or IP with a different stable ID does not authorize the new
node. Receiving with an explicit sender pins it before polling; discovery pins
each candidate before connecting. A fresh identity check runs for every incoming
request and every outgoing TCP connection. Lookup failures deny access.

As in Setec, every API request requires the forbidden-to-browser-JavaScript
`Sec-X-Tailscale-No-Browsers` header, with the value `tailbeam`. Requests carrying
`Origin` or `Sec-Fetch-Site` are rejected too. This blocks browser-based access
from an otherwise authorized machine, including DNS rebinding. This public header
does not authenticate native clients; the independent WhoIs check is mandatory.

No forwarding proxy is trusted, no public name resolution is used for peers,
and HTTP redirects and environment proxies are disabled. The sender binds only
its daemon-supplied Tailscale address, never a wildcard or LAN address. The
Tailscale transport provides encryption and peer authentication; HTTP itself is
plaintext within that transport. Do not expose the service through another proxy.

Authorization is at node granularity. It does not distinguish local users or
processes sharing a node, nor does it pin a human owner independently of that
node. Tailnet administrators and compromised endpoints remain inside the trust
boundary. Tagged and shared nodes are subject to the same exact-node test.

## Protocol v1

* `GET /v1/offer` returns version, random 256-bit offer ID, base filename, size,
  and SHA-256 hash, only after destination-node verification.
* `GET /v1/file/ID` streams that single file. The ID also binds a receiver to the
  offer it selected; it does not replace node authentication.
* `POST /v1/ack/ID` consumes the offer. The intended receiver is trusted to
  acknowledge honestly. Consumption does not prove future durability or erasure.

There are no listings of directories, arbitrary paths, upload endpoints, or shell
execution. One handler operates on an offer at a time. Completed offers are
inaccessible, and all offers expire when the sender process or timeout ends.
Unauthorized requests receive a generic 403 without transfer metadata.

## File safety and resource bounds

Only regular source files are offered. Source data is hashed before serving;
modification after hashing causes verification failure rather than a valid
download. Do not modify the source during a transfer. Memory use is streaming,
independent of file size. Receive defaults to a 1 GiB limit. `--timeout` (one hour) bounds only waiting for
a peer; active transfers are bounded by a receiver idle timeout (`--idle-timeout`,
5m, no bytes received) and a sender per-write deadline (60s, renewed on every
successful write), plus an optional absolute `--deadline`. The sender serves the
offer and file without an exclusive lock, so a black-holed connection cannot block
a retry; only the completion flag is mutex-guarded, and completed offers return
410 on every endpoint. Metadata and HTTP headers are bounded, discovery concurrency is limited,
and request headers have a deadline. The normal OS/Tailscale network stack and
local daemon still need operational protection against connection floods.

Filenames reject traversal, separators, leading dots (planted dotfiles such as
.profile or .envrc), invalid UTF-8, control, C1, Unicode format (bidi override,
zero-width) and other non-printable characters, drive prefixes, and common Windows
device names. NFC normalization is not enforced. Before any download, the
receiver displays sender, quoted name, and size and requires explicit
confirmation (`--yes` to skip; no terminal and no `--yes` is an error), so a
peer with node access cannot silently write files. The receiver uses a private temporary file and an
atomic hard-link publication, so a concurrently created file or symlink cannot
be overwritten. The output directory and its ancestors must be controlled by the
receiving user; defending against a malicious local user replacing those
directories is outside this model. Unix private mode bits do not implement
Windows ACL policy. Users must choose a suitably restricted output directory.

Temporary downloads are removed on normal error and cancellation paths. A forced
kill or power loss can leave a private `.tailbeam-*` file; remove it manually.
Files are synced before publication and the output directory is synced (Unix)
after linking and before acknowledgement; Windows does not sync the directory.
On Linux, free space is checked and the temporary file is preallocated.
There is no automatic deletion of source files. Disk exhaustion and unsupported
hard links produce errors. A verified final file is retained if acknowledgement
fails; retrying into the same filename is deliberately rejected.

## Testing scope

Automated tests use real loopback HTTP with mocked Tailscale identities and cover
the rejection cases described in the README. They do not prove the correctness
of WireGuard, daemon behavior, tailnet policy, or OS routing. Live cross-host
validation remains necessary in the intended deployment. No live tailnet
credentials or configured daemon were available in the build environment.

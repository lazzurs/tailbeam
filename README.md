# Tailbeam

A small Go CLI for single-file transfers between Tailscale hosts. Start an offer
with a filename and destination; run `receive` at the destination to pull it.
No application server, accounts, or additional auth keys. Transfers are
end-to-end encrypted by default with a one-time transfer code that `send`
prints.

```sh
# Build with Go 1.27.1 or newer (required by the pinned Tailscale SDK).
go build -buildvcs=false -o bin/tailbeam ./cmd/tailbeam

# On your laptop:
./bin/tailbeam send ./report.pdf desktop
#   Transfer code: mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx
#   On that host run: tailbeam receive nLAPTOPCNTRL:mfrg-gzdf-…

# On desktop, in the directory where you want the file. Enter the code at the
# hidden prompt (or set TAILBEAM_CODE) to keep it out of the process list:
./bin/tailbeam receive laptop
# Or paste the printed one-liner (prints a warning: other local users can see
# command-line arguments):
./bin/tailbeam receive laptop:mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx
# Or give only the code, to discover the sender:
TAILBEAM_CODE=mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx ./bin/tailbeam receive

# Without end-to-end encryption (Tailscale's WireGuard only), on both sides:
./bin/tailbeam send --plaintext ./report.pdf desktop
./bin/tailbeam receive --plaintext laptop
```

Install the binary on both hosts. Both hosts
must be logged into Tailscale, able to see one another, and using its normal OS
network interface. Linux with `tailscaled` in TUN mode is the primary target.
Userspace-only networking, Funnel, Serve proxies, and public HTTP endpoints are
not supported. macOS and Windows builds compile, but live transfers on those
platforms have not been validated.

Flags go **before** positional arguments:

```sh
tailbeam send --timeout 20m --port 8784 ./archive.tar.gz desktop
tailbeam receive --timeout 20m --idle-timeout 5m --port 8784 --dir ./downloads --max-bytes 5368709120 laptop
# Non-interactive receive (stdin is not a terminal) requires --yes, and the
# code from the argument or TAILBEAM_CODE:
TAILBEAM_CODE=… tailbeam receive --yes laptop
# A custom daemon socket, if needed:
tailbeam receive --socket /var/run/tailscale/tailscaled.sock laptop
```

The output directory must already exist. Default maximum receive size is 1 GiB;
`--timeout` (default one hour) bounds only *waiting*: discovery on the receiver,
and on the sender the wait until a receiver starts downloading. It never cuts
off an active transfer. `--idle-timeout` (default 5m, receiver) aborts a download
when no bytes arrive for that long; the sender likewise drops a connection that
makes no write progress for 60 seconds. `--deadline` (default 0, none) is an
optional absolute cap on the whole command. The sender remains running until the
receiver acknowledges the saved file or it is canceled. An interrupted or stalled
download can be retried immediately while the offer is still running. Keep the
source file unchanged until completion.

Transfers use chunked [protocol v2](docs/protocol-v2.md), wrapped by default
in the [end-to-end encrypted mode](docs/e2e-encryption.md). The file is
verified in chunks, and an interrupted download resumes from its verified chunks
when you run `receive` again into the same directory, even if either side was
restarted (a restarted sender prints a new code; use that). Partial state lives
in private `.tailbeam-v2-*.part` and `.state` files beside the destination. If
the source changes, the partial state is discarded. A resume keeps every chunk
of the partial file that still matches its hash, including chunks written just
before the receiver was killed.

The sender hashes the file before offering it. For files of 256 MiB or more it
caches the result in the user cache directory, keyed by inode, size, mtime and
ctime, so restarting a send of the same unchanged file (for example to let a
receiver resume) starts at once instead of re-reading it. `send --no-cache`
disables this.

The receiver fetches over `--streams` parallel connections (default 2, up to
8). Each stream also verifies (and decrypts) its own chunks, which spreads that
work over several cores. Two streams were fastest in live tests between a
low-power Intel N100 VM and a busy Celeron N3160 host: more streams compete
with `tailscaled` for CPU. Try 4 between faster machines or over long,
lossy paths.

`--plaintext` must be given on both sides; a mismatch fails with a message
naming the other side's mode, never a silent fallback. With `--plaintext`, a new
receiver also accepts offers from v1 senders, and `send --plaintext --v1` serves
receivers older than v2 (v1 restarts from byte zero).

Before downloading, `receive` shows the sender (name and stable ID), the quoted
file name, and the size, and asks `Accept? [y/N]`; anything but `y`/`yes`
declines, with a nonzero exit and no download or acknowledgement. `--yes` skips
the prompt. Without a terminal on stdin and without `--yes`, it refuses to run.
Free space for the bytes still missing is checked first (Linux), and the
partial file is preallocated so a full disk fails early.

File names must not start with `.`, and must be valid UTF-8 made only of
printable characters: control, C1, Unicode format (bidi overrides, zero-width),
and other non-printing characters are rejected, by sender and receiver alike.
NFC normalization is not required (it would need `golang.org/x/text`).

## How it works

**Encrypted mode (default).**
- **The code:** the sender generates 128 random bits. The offer's URL path uses
  an ID derived one-way from the code, and a Noise `NNpsk0` handshake
  ([flynn/noise](https://github.com/flynn/noise)) authenticates the receiver by
  the code.
- **Binding:** the handshake is bound to both stable node IDs and the offer ID.
- **What travels encrypted:** the file name, size and a per-session file key
  arrive only inside the handshake; the manifest and every chunk are sealed
  with XChaCha20-Poly1305.
- **Burning:** after 3 handshakes without a valid confirmation the offer is
  burned and `send` exits; start a new send.
- **Effect:** another process on the receiving machine, or anything answering
  for the sender's IP, gets nothing without the code.
- **Details:** see [docs/e2e-encryption.md](docs/e2e-encryption.md).

Everything below applies in both modes.

The sender listens on its own Tailscale address, TCP port 8784 by default. It
hashes the file and pins the intended destination's **stable node ID** from
the official Go LocalAPI client's `Status` response. Every incoming request must
pass LocalAPI `WhoIs(IP:PORT)` verification for that exact node and its owned address before
metadata or content is returned. An address routed through a subnet router is
not accepted as an address owned by that node.

The receiver resolves names using the daemon's peer list, avoiding public DNS.
It pins the sender's node ID and verifies the actual remote TCP endpoint through
the local daemon before sending any HTTP request. Proxies and HTTP redirects are
disabled. Ambiguous short names are rejected; use the full MagicDNS name,
Tailscale IP, or stable node ID to disambiguate.

Every protocol request also requires a `Sec-X-Tailscale-No-Browsers: tailbeam`
header, following Setec's browser-blocking pattern. Browser JavaScript cannot set
this forbidden `Sec-*` header. Requests with `Origin` or `Sec-Fetch-Site` are also
rejected. This prevents a malicious page in an authorized host's browser from
using that host's node identity to access the transfer, including after DNS
rebinding. The header is public protocol framing, not a credential.

Bare `receive` probes up to 256 online peers, with at most eight concurrent
requests, and repeats until an offer is found or the timeout expires. It accepts
only one offer; multiple offers require specifying the sender. `receive HOST`
pins that sender once and also works when it was initially offline. Bare receive
intentionally accepts an offer from any visible peer that has addressed this
node; specify a sender when you need to limit who can send you a file.

Downloads go to a private temporary file (mode 0600 on Unix). The receiver checks
the exact byte count and SHA-256 hash, syncs the file, and atomically creates the
final filename without replacing an existing file or symlink. It then acknowledges
the transfer. If acknowledgement fails, the verified file stays saved and the
error gives its path. The output filesystem must support hard links; unsupported
filesystems fail safely. No shell commands or downloaded files are executed.

The HTTP protocol is carried **inside Tailscale's WireGuard-encrypted network**,
with the end-to-end layer above inside it unless `--plaintext` is used. There
is no TLS layer. Tailscale may use its existing DERP relays when
a direct path is unavailable; they cannot decrypt the file. This removes the
need for an application coordinator but still depends on Tailscale's existing
control plane and transport infrastructure.

## Tailscale policy

Traffic flows **from the receiving host to the sending host**. Your tailnet's
ACLs or grants must allow TCP 8784 in that direction. A grant might look like:

```json
{
  "grants": [
    {
      "src": ["alice@example.com"],
      "dst": ["tag:file-sender"],
      "ip": ["tcp:8784"]
    }
  ]
}
```

Merge an appropriate rule into your existing policy using your real identities
and tags. Assigning tags requires a suitable `tagOwners` rule. Other existing
rules may also allow traffic; Tailscale rules are additive. Tailbeam's exact-node
check applies even when network policy allows more peers. Taildrop's built-in
file-sharing configuration is not required.

## Security boundary

Network authorization is to a **host**, including tagged hosts, rather than an
individual OS login. In the default encrypted mode a process on the destination
host also needs the transfer code, so other local users get nothing unless the
code leaks to them (for example through a command line; prefer the prompt or
`TAILBEAM_CODE`). They can still burn the offer with failed attempts. With
`--plaintext`, any process on the destination host able to connect as that
Tailscale node can retrieve its offer.

The local daemon, Tailscale control plane, administrators, both endpoint machines,
and the user-selected output directory are trusted. A compromised destination
can retain and redistribute its downloaded file. With `--plaintext`, the
checksum only detects corruption or source changes; it is not independent
authentication of an untrusted sender. In encrypted mode only a holder of the
code can produce the file, which proves possession of the code, not a person.
See [SECURITY.md](SECURITY.md) for protocol details and limits.

[The Setec integration review](docs/setec-review.md) compares the identity,
authorization, browser defenses, transport, and operational model with Tailscale's
reference secrets service and records the changes made as a result.

## Why not Tailcat or Taildrop?

[Tailcat](https://github.com/tailscale/tailcat) supplies encrypted transport
without the Tailscale control plane. Its default address contains a secret
capability; it also supports client node-key allowlists. Those keys do not
automatically map to your existing tailnet's users, device identities, or policy.
It could support a separate mode with out-of-band key exchange, but it does not
validate the daemon identity model used here. Tailbeam therefore uses the existing
tailnet directly, and its tests do not substitute Tailcat for identity checks.

[Taildrop](https://tailscale.com/kb/1106/taildrop) is worth using if its built-in
workflow and supported recipients fit your needs. Tailbeam adds an explicit,
temporary offer to one selected peer, a pull command, and receiver-side sender
pinning without a persistent application daemon.

## Development and validation

```sh
go test -race ./...
go vet ./...
go build -buildvcs=false -o bin/tailbeam ./cmd/tailbeam
```

Tests cover binary and empty-file transfers over real loopback HTTP connections
in both modes, the Noise test vector, wrong codes and burning, node-ID and offer
binding, tampered, reordered and truncated chunks, mode mismatches, resume across
restarts, authorization rejection, daemon identity wire formats, ambiguous names, checksum
and length failures, file limits, path traversal, symlinks, concurrent destination
creation, source changes, and acknowledgement failure. Tailscale identities are
mocked in tests; these are not live WireGuard or cross-host tailnet tests.

For a live smoke test, build on two Tailscale hosts, allow receiver-to-sender TCP
8784, transfer a file, and compare `sha256sum` on both sides. Try `receive` from a
third host: it should get no offer metadata or file bytes, even if policy permits
the connection. On the destination, try a wrong code three times: the sender
should report the offer burned. Repeat with the daemon stopped and an existing destination file;
both operations should fail safely. Test one transfer per sender/port; use a
different `--port` for concurrent offers. There is no directory/archive
handling, compression, parallel streaming, or background queue in this version.

## Releases

Release builds use [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) for
linux, darwin and windows on amd64 and arm64. To build everything locally without
publishing anything:

```sh
go install github.com/goreleaser/goreleaser/v2@latest
goreleaser check
goreleaser release --snapshot --clean
```

Archives and `checksums.txt` are written to `dist/` (git-ignored). Pushing a `v*`
tag runs `.github/workflows/release.yml`, which creates a draft GitHub release.
Binaries are not yet code-signed or notarized.

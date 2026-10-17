# Using tailbeam

## Requirements

- **Both hosts:** the tailbeam binary installed, logged into the same tailnet,
  able to see each other, and using Tailscale's normal OS network interface.
  Linux with `tailscaled` in TUN mode is the primary target. macOS and Windows
  builds compile, but live transfers there have not been validated.
- **Not supported:** userspace-only networking, Funnel, Serve proxies and
  public HTTP endpoints.
- **Policy:** the tailnet must allow TCP 8784 from the receiver to the sender
  (see [Tailscale policy](#tailscale-policy)).

## Sending and receiving

```sh
# On the sending host:
tailbeam send ./report.pdf desktop
#   Transfer code: mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx
#   On that host run: tailbeam receive nLAPTOPCNTRL:mfrg-gzdf-…

# On desktop, in the directory where the file should go:
tailbeam receive laptop                     # enter the code at the hidden prompt
TAILBEAM_CODE=mfrg-… tailbeam receive laptop
tailbeam receive laptop:mfrg-gzdf-…         # works, but warns: argv is visible to local users
TAILBEAM_CODE=mfrg-… tailbeam receive       # code only: discovers the sender
```

- **Running time:** start `send` first. Both commands keep running until the
  receiver acknowledges the saved file.
- **Host names:** hosts can be MagicDNS names, Tailscale IPs or stable node IDs.
  Ambiguous short names are rejected.
- **Confirmation:** before downloading, `receive` shows the sender, file name
  and size and asks `Accept? [y/N]`. `--yes` skips the prompt. Without a
  terminal, `--yes` is required.
- **Codes:** a code has seven dash-separated groups and includes a checksum, so
  typos fail before any network use. Write IPv6 senders as `[ADDR]:CODE`; ports
  belong in `--port`, never after the colon.
- **Flag order:** flags go before positional arguments.

## Flags

| Flag | Applies to | Default | Meaning |
| --- | --- | --- | --- |
| `--port` | both | 8784 | TCP port on the sender |
| `--timeout` | both | 1h | How long to wait for the peer. It never cuts off an active transfer |
| `--deadline` | both | none | Absolute cap on the whole command |
| `--socket` | both | platform default | Path to the `tailscaled` socket |
| `--plaintext` | both | off | Rely on WireGuard only, with no code; both sides must use it |
| `--v1` | send | off | With `--plaintext`: serve protocol v1 for receivers older than v2 |
| `--no-cache` | send | off | Re-hash a large file even if its manifest is cached |
| `--dir` | receive | `.` | Existing output directory |
| `--max-bytes` | receive | 1 GiB | Largest file accepted |
| `--idle-timeout` | receive | 5m | Abort a download that receives nothing for this long |
| `--streams` | receive | 2 | Parallel range requests, 1 to 8 |
| `--yes` | receive | off | Accept without the confirmation prompt |

`tailbeam version` prints the version.

## Resume

An interrupted download resumes when you run `receive` again into the same
directory, even if either side was restarted. A restarted sender prints a new
code; use that one.

Partial data lives in private `.tailbeam-v2-*.part` and `.state` files beside the
destination. On a rerun, every chunk of the partial file that still matches its
hash is kept. If the source file changed, the partial data is discarded.

For files of 256 MiB or more, the sender caches its chunk hashes in the user
cache directory, so a restarted send of the same unchanged file starts at once.
Keep the source unchanged until the transfer completes.

## Performance

Two streams were fastest in live tests between a low-power Intel N100 VM and a
busy Celeron N3160 host. More streams competed with `tailscaled` for CPU.
Between faster machines, or over long and lossy paths, try `--streams 4`.
Measurements are in [protocol-v2.md](protocol-v2.md).

## Plaintext mode and compatibility

`--plaintext` must be given on both sides. A mismatch fails with a message
naming the other side's mode; it never falls back silently. In plaintext mode a
receiver also accepts offers from v1 senders, and `send --plaintext --v1` serves
receivers older than v2. v1 has no resume.

## File names and output

- **Allowed names:** valid UTF-8 and printable only. Names starting with `.`,
  control and C1 characters, Unicode format characters (bidi overrides,
  zero-width) and Windows device names are rejected by both sender and receiver.
- **Overwriting:** the receiver never replaces an existing file or symlink. A
  verified file is published atomically with a hard link, so the output
  filesystem must support hard links.
- **Disk space:** on Linux, free space is checked and the file preallocated
  before downloading.

## Tailscale policy

Connections go **from the receiving host to the sending host**, so your
tailnet's ACLs or grants must allow TCP 8784 in that direction:

```json
{
  "grants": [
    {"src": ["alice@example.com"], "dst": ["tag:file-sender"], "ip": ["tcp:8784"]}
  ]
}
```

Tailscale rules are additive. Tailbeam's exact-node check applies even when
policy allows more peers. Taildrop's file-sharing settings are not needed.
Optional app-capability grants that limit who may send or receive are designed
in [app-capabilities.md](app-capabilities.md), but are not yet enforced by the CLI.

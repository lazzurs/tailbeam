# Protocol v2: chunked, resumable transfers

Protocol v2 makes very large transfers practical. The sender splits the file
into fixed-size chunks and hashes each one; the receiver verifies every chunk
as it arrives, records verified chunks on disk, and resumes from them after
any failure, including a restart of either process. Identity, authorization,
and browser defenses are unchanged from v1 and apply to every v2 endpoint.

Implementation: `internal/transfer/v2.go` (sender) and
`internal/transfer/v2_receive.go` (receiver).

The endpoints below are the **plaintext** form, served only with `--plaintext`.
By default the same chunking, manifest, root and resume state are carried by
the end-to-end encrypted endpoints under `/e2e/{offer}/` (`hello`, `confirm`,
`manifest`, `chunks?first=&last=`, `ack`), described in
[e2e-encryption.md](e2e-encryption.md). There, chunks are requested by index,
and each comes back as one sealed message, instead of by byte range. Both modes
share the receiver's resume files.

## Offer

`GET /v2/offer` returns, after the v1 gates (browser guard, then exact-node
`WhoIs` check):

```json
{"version":2,"id":"<64 hex>","name":"disk.img","size":107374182400,
 "chunk_size":8388608,"hash":"sha256","root":"<64 hex>"}
```

| Field | Meaning | Receiver check |
| --- | --- | --- |
| `version` | `2` | exactly 2 |
| `id` | random 256-bit offer token, new per sender process | 32 bytes of hex |
| `name` | base file name | v1 `validName` |
| `size` | bytes | `0 <= size <= --max-bytes` |
| `chunk_size` | bytes per chunk; the last chunk may be shorter | power of two, 64 KiB to 64 MiB |
| `hash` | chunk hash algorithm | exactly `sha256` |
| `root` | hash binding the manifest (below) | 32 bytes of hex |

Chunk count is `ceil(size / chunk_size)` and must not exceed 2^22. The
sender uses 8 MiB chunks and doubles the size until the count is at most 2^20,
so a 1 TiB file has 131,072 chunks and a 4 MiB manifest. The largest file v2
accepts is 2^22 × 64 MiB = 256 TiB.

## Manifest and root

`GET /v2/manifest/{id}` returns `count × 32` bytes: the SHA-256 of each chunk
in order, with an exact `Content-Length`.

```
root = SHA-256("tailbeam/v2 root\0" || uint64be(size) || uint64be(chunk_size) || manifest)
```

Binding `size` and `chunk_size` prevents a manifest from being reinterpreted
under other chunk boundaries. The receiver rejects a manifest whose length is
not exactly `count × 32` or whose root differs from the offer.

The sender hashes chunks in parallel (up to `min(GOMAXPROCS, 8)` workers,
cancellable) before it listens, and rejects the file if its size or
modification time changed while hashing. The root is deterministic: the same
file produces the same root after a sender restart.

### Why SHA-256 and not BLAKE3

Chunk-level parallelism already removes v1's single-core hashing bottleneck:
SHA-256 with SHA-NI runs at about 0.9 GB/s per core on a low-power Intel N100,
so 4 to 8 workers keep pace with fast disks and the network. Staying with the
standard library avoids a new dependency in a security tool and keeps Go's
FIPS-capable crypto. The `hash` field allows `blake3` to be added later
without changing the protocol.

## File reads and Range

`GET /v2/file/{id}` returns the whole file (200) or, with exactly one range
`Range: bytes=first-[last]`, that range (206, `Content-Range: bytes first-last/size`).
`last` past the end is clamped. Suffix ranges (`bytes=-n`), multiple ranges,
whitespace, signs, `first >= size`, and any range on an empty file return 416.

The receiver requests each contiguous run of missing chunks as one range and
requires the exact `Content-Range` and `Content-Length` it asked for.

Unlike v1, reads are not serialized behind the offer lock: up to 8 manifest or
file requests may run at once (more get 429), and only `ack` takes the lock.
Each write extends a one-minute write deadline, so a stalled peer releases its
slot instead of blocking retries until TCP gives up.

`POST /v2/ack/{id}` completes the offer (204); every later request gets 410.

## Receiver state and resume

For sender stable ID `S` and file name `N`, with
`k = hex(SHA-256(S || 0x00 || N)[:16])`, the receiver keeps two files in the
output directory, both mode 0600:

* `.tailbeam-v2-<k>.part`: the file, preallocated as a sparse file of `size` bytes.
* `.tailbeam-v2-<k>.state`: JSON `{version, sender, name, size, chunk_size, root, done}`,
  where `done` is a bitmap of verified chunks (at most 512 KiB).

The key uses the sender's identity and file name, not the offer ID or root, so a
rerun finds the previous attempt even after the sender restarts or the source
changes. The state is reused only if every field matches the new offer. If
anything differs (for example a new root because the source changed), both files
are removed and the download starts over. Symlinks at either path are removed,
never followed, and the partial file is created with `O_EXCL`.

For each chunk, the receiver writes the bytes into the partial file at the
chunk's offset while hashing them, compares the hash with the manifest, and
only then sets the chunk's bit. Every 64 MiB or 2 seconds, and on any error,
it syncs the partial file **before** writing the state (temp file, sync,
rename), so a recorded bit never refers to unsynced data. A lost state update
only causes chunks to be fetched again.

Failures: a broken connection, a short body, or no bytes for `--idle-timeout` (default 5 minutes from the CLI, one minute for the library default) ends the
current range request. The receiver checkpoints and retries from the next
missing chunk, after 1 second if the attempt made progress. Attempts without
progress wait 2 and then 4 seconds; the third consecutive one stops the download. A chunk that keeps failing its hash (for
example a source modified in place) ends the download with an error naming
it. Cancellation leaves the partial files in place; `receive` again with the
same sender and output directory resumes.

## Publication

When all bits are set, the receiver re-hashes the entire partial file in
parallel and compares every chunk with the manifest. This guards against a
corrupted or edited partial file or state, and against disk faults. Failed
chunks are cleared and fetched again, once. Then, as in v1: `fsync`, then
`link(part, dest)` (atomic, never replaces), remove the state and partial
names, `fsync` the directory (not on Windows), then `POST /v2/ack/{id}`.

## Security analysis

* **Unchanged:** every v2 request passes the v1 browser guard and exact-node
  `WhoIs` check before any metadata, manifest or byte is returned. The client
  dials only the pinned address and verifies the sender on every TCP connection.
* **What chunk hashes protect:** source changes during or between transfers,
  disk faults on either side, resume bookkeeping errors, and a wrong or
  stale partial file. WireGuard already authenticates packets in transit.
* **What they do not protect:** the manifest and root come from the sender over
  the same channel, so they prove consistency with the sender's claim, not the
  sender's honesty. This is the same as v1's whole-file hash.
* **Hostile offers:** chunk size and count are bounded, so an authenticated
  but hostile sender can make the receiver hold at most a 128 MiB manifest and
  a 512 KiB bitmap, and write at most `--max-bytes`. `size` is checked
  against `--max-bytes` before anything is allocated.
* **Local files:** resume files are private (0600, permission-checked on
  reuse, regular files only) and live in the output directory, which the model
  already requires to be trusted. Two concurrent receives of the same name
  from the same sender into one directory are unsupported. Final verification
  prevents a corrupt publish, but the attempts may interfere.
* **Downgrade:** in plaintext mode the receiver falls back to v1 only when
  `/v2/offer` returns 404, and v1 is equally authenticated, so a downgrade
  loses resume but not authenticity. Encrypted and plaintext modes never fall
  back to each other: a sender answers unknown paths with `X-Tailbeam-Mode`,
  and a receiver in the other mode stops with an error.

## Compatibility

* Default (encrypted) senders and receivers interoperate only with each other.
* With `--plaintext`, a new receiver tries `/v2/offer` first and falls back to
  `/v1/offer` on 404, so it works with old senders.
* `send --plaintext` serves v2 only. For a receiver older than v2, run
  `tailbeam send --plaintext --v1`.

## Deferred

* zstd compression per chunk, negotiated through `Accept-Encoding`.
* Parallel range streams. The sender already allows 8 concurrent reads, and the
  receiver writes by offset, so this is a receiver-only change.
* Delta transfer against an existing receiver file (`--base`), likely with
  content-defined chunking.
* Streaming mode for unknown sizes (stdin, on-the-fly archives) and directories.

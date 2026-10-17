# End-to-end encrypted mode (default)

Every transfer is end-to-end encrypted unless both sides pass `--plaintext`.
The sender prints a one-time **transfer code** (128 random bits). The receiver
proves it holds the code in a **Noise `NNpsk0`** handshake
([`github.com/flynn/noise`](https://pkg.go.dev/github.com/flynn/noise) v1.1.0).
The sender then delivers the offer and a fresh file key inside that handshake.
The manifest and every chunk travel sealed with **XChaCha20-Poly1305**. The URL
names the offer by an ID derived one-way from the code, so nothing about the
offer is served in plaintext.

Node authentication is unchanged and still mandatory on every request: browser
guard, `WhoIs` with stable-ID pinning, write deadlines, idle timeout, free-space
preflight and read-slot limits. The code is an additional factor, never a
replacement.

## Decisions

| Question | Decision |
| --- | --- |
| Default mode | Encrypted. `--plaintext` (both sides) restores protocol v2, with v1 fallback and `send --plaintext --v1`. There is never a silent fallback in either direction. |
| Where the offer ID comes from | Derived from the code: `HKDF(code, "tailbeam-e2e-v1 offer-id")`. No plaintext offer endpoint exists, and the code stays 28 characters. |
| Code lifetime | One code per transfer. No per-person keys, keygen or contacts. |
| Handshake | `flynn/noise` `Noise_NNpsk0_25519_ChaChaPoly_SHA256`, not a hand-assembled construction. |
| Data encryption | Our own small layer: XChaCha20-Poly1305 from `golang.org/x/crypto`, random nonces, chunk index bound in the associated data. |

## Threat model

| Threat | `--plaintext` | Default (encrypted) |
| --- | --- | --- |
| Another user or process on the recipient node fetches the offer | Gets the file and metadata (authorization is per node) | Gets nothing without the code: no name, size, manifest or bytes. It can still **burn** the offer (3 bad handshakes) or race to use a leaked code |
| Routing or netfilter subversion, or a CGNAT overlap, lets a host answer for a 100.x IP | `WhoIs` trusts the IP, so an impostor can serve or fetch | An impostor without the code cannot complete the handshake. The receiver writes nothing; the sender reveals nothing |
| The coordination plane injects a node or key | A rogue node can pass `WhoIs` | A rogue node lacks the code |
| Recorded traffic is decrypted later | WireGuard forward secrecy | Ephemeral X25519 gives forward secrecy, and the code is mixed in too |
| A malicious sender serves a different file | The hash travels on the same channel, so it only detects corruption | Only a code holder can complete the handshake and produce valid sealed chunks. That proves "holds the code", not a person's identity |

**What it does not protect against:**
- Compromised endpoints (root or malware on either machine, or the person forwarding the file).
- A leaky channel for carrying the code: pasted into a chat, it is as private as that chat.
- Traffic metadata: size and timing.
- Denial of service by anything that can reach the port, including burning the offer.
- Local users on the **receiving** machine reading the decrypted file in the output directory. Partial files are 0600, but choose the directory accordingly.

## Why these choices

**No PAKE.** A PAKE (SPAKE2, CPace) exists so a *short* code survives an active
attacker; Magic Wormhole needs that because people type codes and a public
rendezvous server sits in the middle. Tailbeam has no rendezvous server, and the
sender prints a command to paste, so the code can be 128 bits. Offline guessing
is then infeasible, and a PSK handshake is enough. The Go PAKE libraries are
also not fit to depend on:
- [`gospake2`](https://pkg.go.dev/salsa.debian.org/vasudev/gospake2): untagged, from 2021, and its README says it is unaudited.
- [`bytemare/cpace`](https://pkg.go.dev/github.com/bytemare/cpace): its README says "Don't, yet".
- [`filippo.io/cpace`](https://pkg.go.dev/filippo.io/cpace): experimental, from 2021.

If voice-readable codes are ever wanted, that is a separate mode with a burn
after 1 failure, and it needs a reviewed PAKE.

**flynn/noise for the handshake.** It is the widely used Go Noise
implementation: v1.1.0, BSD-3, and it ships the Noise test vectors.
`NNpsk0` is plain configuration: `HandshakeNN` with `PresharedKey` set and
`PresharedKeyPlacement: 0`. The `Prologue` field binds the node IDs and offer
ID. Choosing a specified pattern means the subtle part, key schedule and
transcript, is not ours. `TestNoiseVector` replays the library's
`Noise_NNpsk0_25519_ChaChaPoly_SHA256` vector through our configuration.

**Limits of using flynn/noise, and how we handle them:**
- **Noise transport messages cap at 64 KiB and use in-order counter nonces.**
  That does not fit 8 to 64 MiB chunks fetched out of order, retried or resumed
  in a later session. So Noise carries only the handshake and a one-message
  confirmation. Data uses our own AEAD layer, `internal/e2e/seal.go`, about 100 lines.
- **`ChannelBinding()` returns the handshake hash, which is public.** It is
  never used as a key. `UnsafeKey()` is not used either. Instead, the sender
  generates a random 32-byte **file key** per session and sends it inside the
  encrypted handshake message 2 (keys from ephemeral DH plus the PSK). All data
  keys are expanded from it with HKDF.
- **With `NN` the sender does not know whether the receiver finished.** A third
  request carries an encrypted confirmation under the receiver-to-sender
  transport key. The sender serves manifest and chunks only to confirmed sessions.
- **No formal audit of flynn/noise is published,** and the release cadence is
  slow; the spec is frozen. The whole design should get an external review
  before relying on it for high-stakes data.

## Wire protocol

All paths are under `/e2e/{offer}/`, where `{offer}` is the 64-hex-character
code-derived offer ID. Every request passes the browser guard and `WhoIs`
pinning first; failures get a generic 403 with no hints.

```
offer = HKDF-SHA256(code, info "tailbeam-e2e-v1 offer-id", 32 bytes)   public
psk   = HKDF-SHA256(code, info "tailbeam-e2e-v1 psk", 32 bytes)        secret
prologue = lp("tailbeam-e2e-v1") ‖ lp(sender stable ID) ‖ lp(receiver stable ID) ‖ lp(offer)
           (lp = 4-byte big-endian length prefix; each side takes IDs from its own daemon)

R → S  POST hello           body: Noise msg1 (psk, e)                    48 bytes
S → R  200                  body: Noise msg2 (e, ee) + encrypted payload:
                            {sid, file_key, name, size, chunk_size, hash, root}
R → S  POST confirm         body: sid(16) ‖ Encrypt_cs1(ad = sid, "tailbeam-e2e-v1 confirm")
S → R  204
R → S  GET manifest?sid=    → nonce(24) ‖ XChaCha20-Poly1305(k_manifest, ad_manifest, chunk hashes)
R → S  GET chunks?sid=&first=i&last=j
                            → for each chunk k in i..j: nonce(24) ‖ ciphertext(len_k + 16)
R → S  POST ack?sid=        body: HMAC-SHA256(k_ack, ad_ack)
S → R  204; the offer is consumed and the sender exits
```

Data keys come from the per-session file key:

```
k_manifest = HKDF(file_key, "tailbeam-e2e-v1 manifest")
k_chunk    = HKDF(file_key, "tailbeam-e2e-v1 chunk")
k_ack      = HKDF(file_key, "tailbeam-e2e-v1 ack")
ad_chunk   = "tailbeam-e2e-v1 chunk" ‖ lp(offer) ‖ lp(root) ‖ index(8) ‖ length(8) ‖ last(8)
ad_manifest= "tailbeam-e2e-v1 manifest" ‖ lp(offer) ‖ lp(root)
ad_ack     = "tailbeam-e2e-v1 ack" ‖ lp(offer) ‖ lp(root)
```

- **Wrong code or binding.** A wrong code, sender ID, receiver ID or offer ID
  changes the PSK or prologue, so the sender cannot read msg1. It answers 403
  and sends nothing about the offer.
- **Nonces.** Each sealed chunk takes a fresh random 24-byte nonce, so
  re-serving a chunk (retry, resume, parallel fetch, changed source) never
  reuses one. Chunks cannot be reordered, truncated, cut short or moved to
  another offer: the associated data carries the index, length, last flag,
  offer and root.
- **Hash check.** The receiver also checks each decrypted chunk against the
  manifest hash before recording it, as in plaintext v2.

**Attempt limit and burning:**
- The sender counts each handshake that does not end in a valid confirmation
  as a failure:
  - msg1 fails to authenticate;
  - the confirmation is wrong;
  - a handshake is left unconfirmed for over a minute;
  - the oldest pending handshake is evicted beyond 8.
- After **3** failures the offer is **burned**: every request gets 410 and
  `send` exits with "offer burned after 3 failed transfer-code attempts". A
  receiver that sees 410 stops instead of polling.
- A well-formed code for another offer derives another offer ID, gets a plain
  404 and does not count.

**Mode mismatch.** After the gates, a sender answers unknown paths with
`X-Tailbeam-Mode: e2e` or `plaintext`:
- An encrypted receiver that reaches a plaintext sender stops with "the sender
  offers a plaintext transfer; rerun receive with --plaintext if that is
  acceptable".
- A plaintext receiver that reaches an encrypted sender stops with "run
  receive without --plaintext and use its transfer code".
- Neither side ever serves or accepts the other mode's data.

**Resume.**
- Keys are per session, and nothing secret is stored.
- The receiver keeps verified *plaintext* chunks in its private `.part` and
  `.state` files, exactly as in v2: same names, keyed by sender stable ID and
  file name, and validated against the root.
- A rerun (new handshake, same code) fetches only missing chunks.
- A restarted sender prints a new code. The same file gives the same root, so
  the receiver resumes with the new code.

**Memory.** The sender seals one whole chunk per in-flight request: up to 8
concurrent reads at chunk size (8 MiB by default, up to 64 MiB for files over
8 TiB), plus the sealed copy. The receiver holds one sealed and one plaintext
chunk buffer per stream (`--streams`, default 2).

**Cost.** XChaCha20-Poly1305 on one core, per 8 MiB chunk:

| CPU | Seal | Open |
| --- | --- | --- |
| Intel N100 (VM) | 537 MB/s (2.0 s/GiB) | 777 MB/s (1.4 s/GiB) |
| Celeron N3160 (busy host) | 84 MB/s (12.8 s/GiB) | 99 MB/s (10.8 s/GiB) |

Each receive stream opens its own chunks, so streams spread this over cores.
Two choices were measured and not adopted:

- **Sealing in smaller segments, or pipelining read and seal with the write,
  so a stream never idles during crypto.** Overlapping the next chunk's read
  and seal with the current write made no difference live (49.8 vs 48.9 MB/s,
  N3160 to N100, 2 streams) or on the N3160's loopback (36 MB/s both), because
  both ends were CPU-bound, not idle. Parallel streams already overlap the
  work. The wire format stays one AEAD message per chunk.
- **AES-256-GCM.** It is faster where AES-NI exists (2.0 GB/s on the N100, 177
  MB/s on the N3160), but it has a 96-bit nonce and would be a crypto change.
  Removing the receiver's SHA-256, a larger per-byte cost, made no measurable
  live difference either: the busy host's `tailscaled` was the limit.

## CLI

```
$ tailbeam send secret.pdf desktop
Offering "secret.pdf" (1048576 bytes, end-to-end encrypted, resumable) to "desktop.tail1234.ts.net." [nDESKTOPCNTRL] only.
Transfer code: mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx
On that host run: tailbeam receive nLAPTOPCNTRL:mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx
  (or run tailbeam receive nLAPTOPCNTRL and enter the code at the prompt)
```

**Receiver code sources, in order:**
1. **The argument:** `HOST:CODE`, `[IPv6]:CODE`, or a bare `CODE`. A bare code
   probes all online peers at the code-derived path.
2. **`TAILBEAM_CODE`.**
3. **A no-echo prompt.** It uses `golang.org/x/term` and allows 3 tries.
   Without a terminal it errors.

A code on the command line prints a warning: on Linux any local user can read
another process's argv. `/proc/<pid>/environ` is owner-only, and the prompt
leaves no trace.

**Code format.** 16 random bytes encode as 26 base32 characters plus a
2-character checksum, lowercase, in seven dash-separated groups of four.
Parsing ignores case, dashes and spaces. The checksum catches typos before any
network use, so a typo never spends one of the 3 attempts. In `HOST:CODE`:
- An unbracketed IPv6 address is never split.
- A numeric suffix (`laptop:8784`) is rejected with "ports use --port".

`--v1` requires `--plaintext`. A code given with `--plaintext` is an error.

## Code

- `internal/e2e/code.go`: the code, its checksum, offer-ID and PSK derivation, and `SplitTarget`.
- `internal/e2e/noise.go`: the `NNpsk0` configuration, prologue, `Hello`, `Finish`, `Confirmation`, `Respond` and `Confirm`.
- `internal/e2e/seal.go`: the file key, `DeriveKeys`, `Seal`/`OpenChunk`, `Seal`/`OpenManifest` and `AckTag`.
- `internal/transfer/e2e.go`: `SenderE2E` (endpoints, attempt counting, burning) and `ServeE2E`.
- `internal/transfer/e2e_receive.go`: `FetchE2EOffer` (handshake and confirm), plus the sealed manifest and chunk source used by the shared chunked downloader.
- `cmd/tailbeam`: the `--plaintext` flag, code sources, the hidden prompt and the argv warning.

## Not done / open

- An external review of the design and of `seal.go`.
- Live cross-host testing (all tests use loopback with mocked identities).
- Recipient-generated codes, per-person keys, and short voice-readable codes
  are deliberately out of scope.

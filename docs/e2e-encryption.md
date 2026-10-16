# Optional end-to-end layer (`--e2e`): investigation and design

Status: design + prototype (`internal/e2e`), not wired into the CLI. Written
2026-10-16 against commit `3a82ae1`, assuming the v2 chunked protocol (manifest,
`Range` resume, persisted `.part` state) lands as designed in parallel.

**Recommendation.** Do not use a PAKE by default. Tailbeam's code is always
printed by one tool and pasted into another, so it does not need to be short.
Use a **128-bit random transfer code**, and authenticate a fresh **ephemeral
X25519 exchange** with it. Bind both Tailscale stable node IDs and the offer
ID into the transcript, then encrypt the offer, the manifest and every chunk
with per-chunk XChaCha20-Poly1305. Everything comes from the Go standard
library plus `golang.org/x/crypto`, with no new modules. A short, voice-readable
PAKE code (SPAKE2) is a possible later add-on, once a maintained Go
implementation exists.

## 1. Threat model: what the layer adds

The base protocol authenticates **nodes**: WireGuard plus `WhoIs` pinning of
stable IDs. The e2e layer adds a second factor: **knowledge of a one-time
secret** that the human carries out of band. The `WhoIs` checks stay
mandatory; e2e is in addition, never instead.

| Threat | Base protocol | With `--e2e` |
| --- | --- | --- |
| Another user or process on the recipient node fetches the offer | Gets file and metadata (node-level authz) | Gets ciphertext only. It can still burn the offer (DoS), and can learn the code if it is passed in argv (see §4) |
| Routing / netfilter subversion, CGNAT overlap: a host answers for a 100.x IP (review finding 2) | `WhoIs` trusts the IP, so an impostor can serve or fetch | An impostor without the code cannot complete the handshake. The receiver rejects before writing anything; the sender reveals nothing |
| Coordination plane injects a node or node key (no [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)) | Rogue node can pass `WhoIs` | Rogue node lacks the code. This is independent of the control plane |
| DERP relays | Already WireGuard-encrypted | No change |
| Sender authenticity of hash/manifest | Same channel as the data; only detects corruption | Manifest and chunks are MAC'd under a code-derived key, so only a code holder can produce them |
| Filename and size leak to the recipient node before acceptance | Plaintext `/offer` | Offer is encrypted; only the code holder sees the name. The size leaks roughly through ciphertext length |
| Recorded traffic decrypted later | WireGuard forward secrecy | Ephemeral DH gives forward secrecy. The 128-bit code is also mixed in, so a future quantum attacker needs the code as well |

**What it does not add:** protection from a compromised sender or receiver
endpoint (root, malware, the human forwarding the file). It is only as secret
as the channel used to carry the code: pasted into Slack, it is as private as
Slack. It hides no traffic metadata (size, timing). It does not defend against
DoS by anything allowed to reach the port. It cannot authenticate a *person*
beyond "whoever holds the code".

## 2. Options considered

| Option | Security in our setting | Code length / entropy | Offline guessing | Go dependency and maturity | Resume |
| --- | --- | --- | --- | --- | --- |
| **SPAKE2** (Magic Wormhole; [RFC 9382](https://datatracker.ietf.org/doc/rfc9382/)) | Good: short code, one online guess per attempt | ~16–30 bits (e.g. `7-guitar-ocean`) | Resistant (the point of a PAKE) | [`salsa.debian.org/vasudev/gospake2`](https://pkg.go.dev/salsa.debian.org/vasudev/gospake2): pseudo-version from May 2021, untagged, README says *"has not been formally audited"*, corrupt-message handling is a TODO. It is what [wormhole-william uses](https://github.com/psanford/wormhole-william/blob/master/go.mod). Not suitable as a security dependency | Per-session handshake, chunk layer below; fine |
| **CPace** (balanced PAKE) | As SPAKE2 | Short | Resistant | [`bytemare/cpace`](https://pkg.go.dev/github.com/bytemare/cpace): "PROOF OF CONCEPT … Deployment: Don't, yet." [`filippo.io/cpace`](https://pkg.go.dev/filippo.io/cpace): 2021 "experimental", based on draft-01. No production option | Fine |
| OPAQUE (augmented PAKE) | Built for client/server password *storage*; no stored verifier exists here | n/a | n/a | Wrong tool | n/a |
| **High-entropy code, no PAKE** (HKDF of code only) | Strong, simple | 128 bits, 28 base32 chars | Infeasible | stdlib only | Fine, but no forward secrecy: recorded traffic plus a leaked code decrypts it |
| **High-entropy code + ephemeral X25519** (recommended; same shape as Noise `NNpsk0` or TLS 1.3 `psk_dhe_ke`) | Strong; forward secrecy; code needed even by a quantum attacker | 128 bits | Infeasible | stdlib `crypto/ecdh`, `crypto/hkdf`, `crypto/hmac` + `x/crypto/chacha20poly1305` (already in go.sum) | Fresh handshake per session; plaintext chunks persist |
| Noise via [`flynn/noise`](https://pkg.go.dev/github.com/flynn/noise) (`NNpsk0`, or `KK` with keys bound to node IDs) | Equivalent to the above, with a formally specified pattern | 128 bits | Infeasible with a high-entropy PSK; short PSKs are offline-guessable from one active run | v1.1.0 (Feb 2024), BSD-3, 183 importers. PSK patterns need a custom `HandshakePattern`; no named `NNpsk0` | Use the handshake only, then `ChannelBinding()`-derived chunk keys |
| **age** recipient-first ([`filippo.io/age`](https://pkg.go.dev/filippo.io/age)) | Strong; the receiver's private key never leaves its process | Receiver public key (~62 chars) | n/a (public key) | v1.3.2 (Aug 2026), BSD-3, 432 importers, X25519 / scrypt / ML-KEM hybrid | Awkward: the file key and STREAM are per encryption; `DecryptReaderAt` needs the full ciphertext. Better to reuse the idea, not the format |
| TLS 1.3 PSK / Tailscale certs (contrast) | Certs authenticate *nodes* again, so they add little over WhoIs; PSK would be ideal | n/a | n/a | Go `crypto/tls` has no external PSK ([golang/go#6379](https://github.com/golang/go/issues/6379), open since 2013) | n/a |

**Why not a PAKE here.** A PAKE exists so a *low-entropy* secret survives an
active attacker. Magic Wormhole needs this because humans type the code and a
public rendezvous server sits in the middle. Tailbeam has no rendezvous server,
and the sender prints a full command line to copy. With a 128-bit code, an
active attacker learns nothing guessable, so the PAKE's only benefit is a
shorter code, at the cost of an unaudited dependency or hand-rolled
curve-point arithmetic. The deciding fact: the protocol does need a PAKE as
soon as codes are short. In a PSK handshake, an active impostor who receives a
confirmation MAC can test candidate codes offline. The prototype's own
`Reply.Confirm` allows exactly that, which is harmless only at 128 bits.

**Channel binding.** The transcript hash covers a length-prefixed
`"tailbeam-e2e-v1"`, the sender stable ID, receiver stable ID, offer ID and both
ephemeral keys. Stable IDs come from each side's *own* daemon (`Status` /
`WhoIs`), never from the peer. A code is therefore useless against another
node pair or another offer. The manifest root is not known before the
handshake (it travels encrypted), so it is bound later: it sits in every
chunk's AAD and in the ack MAC.

## 3. Recommended design

### Handshake (2 round trips, before any metadata)

```
R → S  POST /v2/e2e/hello     {eR}                     (WhoIs + browser gates as today)
S → R  200                    {eS, confirmS}
R      verify confirmS → sender knows code and agrees on both IDs and offer ID
R → S  POST /v2/e2e/confirm   {sid, confirmR}
S → R  200                    {sealed offer}            (only now does the name leave the sender)
```

The receiver learns the offer ID (a non-secret per-offer token that binds the
session) from a minimal plaintext `GET /v2/offer` → `{version:2, e2e:true, id}`
that carries no name or size. Alternatively the sender prints it as part of
the code string. The former keeps the code short.

### Key schedule (`internal/e2e/handshake.go`)

```
th   = SHA-256( lp("tailbeam-e2e-v1") ‖ lp(senderID) ‖ lp(receiverID) ‖ lp(offerID) ‖ lp(eR) ‖ lp(eS) )
prk  = HKDF-Extract(salt = th, ikm = X25519(e, e') ‖ code)
kcS  = HKDF-Expand(prk, "tailbeam-e2e-v1 confirm sender", 32)     confirmS = HMAC(kcS, th)
kcR  = HKDF-Expand(prk, "tailbeam-e2e-v1 confirm receiver", 32)   confirmR = HMAC(kcR, th)
kmeta= HKDF-Expand(prk, "tailbeam-e2e-v1 metadata", 32)
kdata= HKDF-Expand(prk, "tailbeam-e2e-v1 chunk data", 32)
kack = HKDF-Expand(prk, "tailbeam-e2e-v1 ack", 32)
sid  = HKDF-Expand(prk, "tailbeam-e2e-v1 session id", 16)
```

`sid` is derived, not issued, so only a code holder can name a session. Every
later request carries `Tailbeam-Session: <sid>`. Low-order X25519 points are
rejected by `crypto/ecdh`.

### What is encrypted

| Item | Key | AAD |
| --- | --- | --- |
| Offer `{name, size, chunk_size, hash, root}` | kmeta | `"offer" ‖ th` |
| Manifest (chunk hashes) | kmeta | `"manifest" ‖ th` |
| Chunk *i* | kdata | `"chunk" ‖ th ‖ root ‖ i ‖ len ‖ last` |
| Ack | `HMAC(kack, "ack" ‖ root)` in the body of `POST /v2/e2e/ack/{sid}` | n/a |

**AEAD.** Use XChaCha20-Poly1305 with a **random 192-bit nonce per seal**. The
24-byte nonce plus 16-byte tag cost 40 bytes per 8 MiB chunk. Counter nonces
(chunk index) would also work, but they are catastrophic if a chunk is ever
re-sealed with different plaintext, for example after a mid-session source
change. Random nonces make retries, parallel fetches and re-serving safe by
construction. The sender still checks each chunk against the manifest hash
before sealing, and the receiver checks the decrypted plaintext against the
manifest before marking it done. Requests are by chunk index
(`GET /v2/e2e/chunk/{sid}/{i}` → `nonce ‖ ciphertext`) rather than byte
ranges, so each response is one AEAD message.

### Resume

- **Keys are per session.** Every reconnect, process restart or resume runs a
  new handshake. Nothing secret is persisted.
- **The receiver persists plaintext** verified chunks in the 0600 `.part` file,
  exactly as in v2. A resumed session only fetches missing indices, so per-chunk
  AEAD with in-AAD indices composes directly with out-of-order and partial
  fetches.
- **Sender restart:** the same file gives the same manifest root. With the
  default random code, a restarted sender prints a **new code**, which the human
  passes again. The receiver decrypts the new offer, sees the same `(sender ID,
  name, size, root)`, and resumes its `.part`. An optional `--code-file` could
  keep a code across restarts, at the cost of storing the secret on disk.
  Not recommended by default.
- **Stale `.part` naming:** v2 keys `.part` by root, which in a shared directory
  lets local users confirm guesses of a file's content. Use
  `HMAC(root, "tailbeam part name")`, or rely on a private output directory.
  This is minor.

### Failure handling and limits

- A failed `confirmR`, or a bad `sid`, counts as a failed attempt. After **3**
  the offer is **burned**: the sender exits non-zero and says so, and the human
  must restart with a new code. At 128 bits this exists to surface attacks, not
  to stop guessing. At most 4 unconfirmed sessions outstanding; each expires in
  30 s.
- **Single use:** the code works for any number of sessions (resume) until a
  valid ack or the burn, and is then dead.
- **Receiver:** a bad `confirmS` aborts without a retry loop and without writing
  anything, and reports "sender did not prove the code (wrong code, or someone
  else is answering for this host)".
- In `--e2e` mode the sender **must not** serve v1 or plaintext v2 endpoints, so
  there is no downgrade. The receiver, given a code, refuses any non-e2e offer.

## 4. UX and CLI

```
$ tailbeam send --e2e secret.pdf desktop
Offering an end-to-end encrypted file to desktop.tail1234.ts.net [nXXXXCNTRL].
On that host run:
  tailbeam receive laptop:mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx
```

**Code format.** 16 random bytes encode as 26 base32 characters, plus a
2-character checksum, lowercase, in seven groups of 4 (34 characters with
dashes). The checksum catches typos locally, so a typo never spends one of the
three attempts. Parsing ignores case, dashes and spaces. Base32 avoids
0/O and 1/l ambiguity. A wordlist would need ~10 EFF words for 128 bits, which
is worse to copy and only useful for voice. That case is the PAKE add-on.

**`HOST:CODE` parsing** (`SplitTarget`):

- MagicDNS names, short names and stable node IDs contain no `:`, so they split
  at the colon.
- An unbracketed IPv6 address (`fd7a:115c:a1e0::1`) has several colons. It is
  never split; a code needs brackets: `[fd7a:115c:a1e0::1]:CODE`.
- The suffix must be a well-formed code (length, alphabet, checksum).
  `laptop:8784` fails with "ports use `--port`" instead of being silently read
  as a host.
- **argv exposure.** On Linux, `/proc/<pid>/cmdline` is world-readable, so
  `receive host:CODE` reveals the code to every local user, the very threat this
  mode targets. So:
  - with a code on the command line, the receiver warns on shared hosts;
  - `tailbeam receive laptop` with `--e2e` prompts `Transfer code:` with echo
    off when stdin is a TTY;
  - `TAILBEAM_CODE` is accepted from the environment (`/proc/<pid>/environ` is
    owner-only);
  - the printed hint stays the one-liner, since that is the copy-paste UX the
    user asked for.

**Flag.** `--e2e` on send generates the code. On receive, a code in the
argument or prompt implies e2e. `--e2e` without a code prompts.

**Recipient-first mode (later).** Here the receiver holds the secret:
`tailbeam receive --e2e` prints a code, and the human passes it to
`tailbeam send --code CODE FILE HOST`. The handshake is unchanged, only who
generates the code differs. This fits when the receiving person wants control,
for example on a shared recipient host where they don't trust the sender's
display path. A persistent variant, an age-style long-term X25519 identity in
`~/.config/tailbeam/` that senders pin by alias (Noise `NK`/`KK`), gives "only
this person, every time" without passing codes. It is the natural next step if
transfers between the same people repeat. It is out of scope for v1 of this
mode.

**Short codes (later).** If voice-readable codes are wanted, swap the handshake
for SPAKE2 (RFC 9382) over `filippo.io/edwards25519` (already an indirect
dependency). Keep everything from the key schedule's `prk` onward, and enforce
burn-after-1 failure with ~20-bit codes. This needs an independent review of
the hand-written group operations, because no maintained Go SPAKE2/CPace
exists today.

## 5. Prototype

`internal/e2e/` (about 300 lines, tests included; stdlib + `x/crypto`, which
`go mod tidy` promotes from indirect to direct):

- `code.go`: `NewCode`, `String`, `ParseCode` (checksum) and `SplitTarget`
  (`HOST[:CODE]`, IPv6 brackets).
- `handshake.go`: `NewHello`, `Respond`, `Finish`, `VerifyReceiver` and
  `AckTag`, with the key schedule above.
- `seal.go`: `SealChunk` / `OpenChunk` and `SealMeta` / `OpenMeta`.
- Tests cover:
  - code round trip and typo rejection, and target parsing (MagicDNS, IPv4,
    bare and bracketed IPv6, `host:port` rejection);
  - handshake success with matching session IDs;
  - rejection of a wrong code, swapped sender ID, swapped receiver ID or another
    offer ID;
  - chunk tamper, reorder (index), truncation (size), last-flag and root
    substitution;
  - cross-session replay, offer/manifest label confusion, nonce uniqueness on
    re-seal, and low-order point rejection.

Not done: HTTP endpoints, attempt counters, CLI flags, prompts. Those land
after the v2 chunked branch merges, because they sit on its manifest and chunk
fetch paths.

## Open questions

1. Should the offer ID come from a plaintext `GET /v2/offer`, or be embedded in
   the code (longer code, but zero plaintext endpoints in e2e mode)?
2. Should `--e2e` become the default once stable? It costs one extra round trip
   and a code to carry.
3. Is a persistent recipient identity (age/Noise-style) wanted? It changes the
   UX from "pass a code each time" to "pin a key once".
4. The construction is standard (ephemeral DH plus PSK through HKDF, mirroring
   TLS 1.3 `psk_dhe_ke`), but it is hand-assembled. Should it be swapped for
   `flynn/noise` `NNpsk0`, a formally specified pattern, at the cost of one
   dependency? Either way it needs an external review before release.

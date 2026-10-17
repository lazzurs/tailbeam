# How tailbeam works

Tailbeam is a receiver-pull HTTP protocol over the tailnet. The local
`tailscaled` is the only identity authority. By default a one-time transfer code
adds end-to-end encryption on top. Wire details are in
[protocol-v2.md](protocol-v2.md) (chunking and resume) and
[e2e-encryption.md](e2e-encryption.md) (the encrypted mode).

## Identity and authorization

- **Sender:** it listens only on its own Tailscale address (TCP 8784 by
  default) and pins the destination's **stable node ID** from the LocalAPI
  `Status` response. Every request must pass LocalAPI `WhoIs(IP:PORT)` for that
  exact node, and the source IP must be an address the node owns. A
  subnet-routed address is not accepted.
- **Receiver:** it resolves names from the daemon's peer list, never public DNS,
  and pins the sender's node ID. It verifies the remote end of each TCP
  connection through its own daemon before sending any HTTP. Proxies and
  redirects are disabled.
- **Browser guard:** every request needs the header
  `Sec-X-Tailscale-No-Browsers: tailbeam`, which browser JavaScript cannot set.
  Requests with `Origin` or `Sec-Fetch-Site` are rejected. This blocks a
  malicious page on an authorized host, including after DNS rebinding. The
  header is framing, not a credential.
- **Discovery:** a bare `receive` probes up to 256 online peers, 8 at a time,
  until it finds an offer or times out. It accepts only one offer.

## Encrypted mode (default)

- **Code and offer ID:** the sender generates a 128-bit code. The offer's URL
  uses an ID derived one-way from the code, so a wrong code finds nothing (404)
  and cannot burn the offer.
- **Handshake:** a Noise `NNpsk0` handshake
  ([flynn/noise](https://github.com/flynn/noise)) authenticates the receiver by
  the code. It is bound to both stable node IDs and the offer ID.
- **Data:** the file name, size and a per-session file key arrive only inside
  the handshake. The manifest and every chunk are sealed with
  XChaCha20-Poly1305.
- **Burning:** a handshake that fails or is never confirmed counts as a failure.
  After 3, the offer is burned and `send` exits.
- **Effect:** other processes on the receiving machine, and anything answering
  for the sender's IP, get nothing without the code.

## Publishing the file

Downloads go to a private (0600) partial file. Each chunk is checked against
the manifest's SHA-256 before it is recorded. A complete file is synced and
hard-linked into place, never replacing an existing file or symlink. The
receiver then syncs the directory and acknowledges. If the acknowledgement
fails, the file stays saved and the error gives its path. Nothing downloaded is
ever executed.

## Transport

HTTP runs inside Tailscale's WireGuard tunnel, with the encrypted layer inside
it unless `--plaintext` is used. There is no TLS. DERP relays may carry traffic
when no direct path exists; they cannot decrypt it.

## Security boundary

- **Plaintext mode:** network authorization is per **host**, not per OS user.
  Any process on the destination that can connect as that node can fetch the
  offer.
- **Encrypted mode:** a process also needs the code. Local users can still burn
  the offer, or use the code if it leaks to them, for example through a command
  line.
- **Trusted:** the local daemon, the Tailscale control plane, administrators,
  both endpoints and the output directory.
- **Sender authenticity:** in plaintext mode the checksum only detects
  corruption. In encrypted mode, only a holder of the code can produce the file.
  That proves possession of the code, not a person's identity.

See [SECURITY.md](../SECURITY.md) for the full model, and
[setec-review.md](setec-review.md) for a comparison with Tailscale's Setec.

## Why not Tailcat or Taildrop?

- **[Tailcat](https://github.com/tailscale/tailcat)** gives encrypted transport
  without the Tailscale control plane, using secret addresses or node-key
  allowlists. Those don't map to your tailnet's users, devices or policy.
- **[Taildrop](https://tailscale.com/kb/1106/taildrop)** is a good fit if its
  push-to-inbox workflow suits you. Tailbeam adds:
  - an explicit, temporary offer to one chosen peer;
  - a pull command;
  - sender pinning on the receiver;
  - end-to-end encryption;
  - resume verified chunk by chunk.

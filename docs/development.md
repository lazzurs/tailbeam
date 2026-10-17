# Development and releases

## Build and test

Go 1.27.1 or newer is required by the pinned Tailscale SDK.

```sh
go vet ./...
go test -race ./...
go build -o bin/tailbeam ./cmd/tailbeam
```

The tests use real loopback HTTP connections with mocked Tailscale identities.
They cover:
- **Transfers:** binary and empty files in both modes, mode mismatches, and
  resume across restarts.
- **Encryption:** the Noise test vector, wrong codes and burning, node-ID and
  offer binding, and tampered, reordered or truncated chunks.
- **Identity:** authorization rejection, daemon identity wire formats and
  ambiguous names.
- **Files:** checksum and length failures, size limits, path traversal,
  symlinks, concurrent destination creation, source changes and
  acknowledgement failure.

They do not exercise live WireGuard or a real tailnet.

## Live smoke test

1. Install the binary on two hosts and allow TCP 8784 from receiver to sender.
2. Transfer a file and compare `sha256sum` on both sides.
3. Run `receive` from a third host with the correct code. It should get a 403
   and no metadata or bytes.
4. Try a wrong code. It should get a 404, and the offer should still work with
   the right code.
5. Kill the receiver mid-transfer and rerun it. The transfer should resume.
6. Repeat with the daemon stopped and with an existing destination file. Both
   should fail safely.

Run one transfer per sender and port; use different `--port` values for
concurrent offers.

## Releases

Releases use [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`). It
builds for Linux, macOS and Windows on amd64 and arm64, plus a universal macOS
binary. Binaries report their version through `tailbeam version`.

To build locally without publishing:

```sh
go install github.com/goreleaser/goreleaser/v2@latest
goreleaser check
goreleaser release --snapshot --clean   # output in dist/
```

To publish, push a semantic-version tag such as `v0.1.0`. That runs
`.github/workflows/release.yml`, which creates the GitHub release with archives
and `checksums.txt`. Binaries are not yet code-signed or notarized.

# Tailbeam

Send a single file to one specific host on your tailnet. There is no server,
account or extra key: Tailscale identifies both ends. Transfers are end-to-end
encrypted by default, verified chunk by chunk, and resume after interruptions.

```sh
# On the sending host:
tailbeam send ./report.pdf desktop
#   Transfer code: mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx

# On desktop, in the directory where the file should go:
tailbeam receive laptop        # enter the code at the hidden prompt
```

Only `desktop` can fetch the offer, and only with the code. The receiver shows
the name and size and asks before downloading.

## Install

Download a binary for Linux, macOS or Windows from
[Releases](https://github.com/linuskendall/tailbeam/releases), or build it with
Go 1.27.1 or newer:

```sh
go install github.com/linuskendall/tailbeam/cmd/tailbeam@latest
```

Both hosts need tailbeam and a running Tailscale. Your tailnet policy must allow
TCP 8784 from the receiver to the sender.

## Documentation

- [Usage](docs/usage.md): commands, flags, resume, plaintext mode and tailnet policy.
- [How it works](docs/how-it-works.md): identity checks, encryption and the
  security boundary.
- [Protocol v2](docs/protocol-v2.md) and [end-to-end encryption](docs/e2e-encryption.md):
  the wire formats.
- [Security model](SECURITY.md), [Setec comparison](docs/setec-review.md) and
  [app-capability grants](docs/app-capabilities.md).
- [Development and releases](docs/development.md).

Tailbeam is new and has not been independently audited.

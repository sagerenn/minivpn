# Repository Guidelines

## Project Structure & Module Organization
Minivpn is a Go module at `github.com/ooni/minivpn`. The CLI lives in `cmd/minivpn/`, exportable helpers in `pkg/` (`config`, `tunnel`, `tracex`), and protocol internals in `internal/` (controlchannel, datachannel, tlssession). Obfuscation helpers sit in `obfs4/`, docs/tooling live in `extras/`, `examples/`, and `scripts/`, test harnesses reside in `tests/integration` and `tests/qa`, and provider configs stay local in `data/<provider>/`.

## Build, Test, and Development Commands
- `make build`, `make build-race`, and `make build-rel` emit Linux, race-enabled, and cross-platform binaries.
- `make bootstrap PROVIDER=name` prepares `data/<provider>/config` for smoke tests.
- `make test`, `make test-short`, `make test-unit`, and `make test-integration` cover the Go suite (unit coverage lands in `coverage/unit`, integration needs Docker).
- `make test-combined-coverage` enforces the 70% gate, `make test-ping` double-checks tunnel liveness, and `make lint` chains `gofmt`, `go vet`, `gosec`, and `revive`.

## Coding Style & Naming Conventions
Go sources must remain `gofmt -s` clean. Exported APIs use `CamelCase`, internal helpers use lowerCamelCase, and filenames describe their contents (`control_channel.go`). Keep public APIs in `pkg/`, CLI glue in `cmd/`, and experimental helpers in `extras/`. Run `make lint` before committing so vet, security, and style checks all pass together.

## Testing Guidelines
Place unit tests next to the code and follow the `TestComponentBehavior` pattern. Use `make test-short` for fast feedback, `make test-unit` when you need coverage artifacts, and `make test-integration` (Docker required) for end-to-end validation.

## Commit & Pull Request Guidelines
Commits follow `type: concise summary (#issue)` (e.g., `bug: propagate TLS errors (#73)`), so choose a meaningful type and keep subjects under 72 characters. Pull requests should link the tracked issue, summarize risk, list configuration or data changes, and record the commands you ran (`make lint`, `make test-combined-coverage`, etc.). Attach logs when tunneling, TLS, or obfs4 paths change.

## Security & Configuration Tips
Never commit generated configs, private keys, or `data/tests/` contents; keep obfs4 bridge material outside the tree and use `make netns-shell` to isolate manual sessions. To bypass local DNS filtering of the VPN endpoint, pass `--remote-dns ip[:port]` so the CLI resolves the remote host via that resolver before dialing.

## Userspace Mode
Run `minivpn --userspace` to replace the kernel TUN plumbing with the new gVisor stack and move packets entirely in userspace. Add `--userspace-socks 127.0.0.1:1080` to launch a SOCKS5 proxy backed by that stack so local tooling can route traffic through the tunnel without touching `/dev/net/tun`.

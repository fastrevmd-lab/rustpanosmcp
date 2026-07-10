# Phase 4 acceptance

Date: 2026-07-09

Phase 4 exits with a v0.1 release candidate: reproducible single-binary archive,
digest-pinned distroless container, hardened systemd service, explicit PAN-OS
compatibility claims, expanded parser fuzzing, published measurements, and a
complete operator/security runbook.

## Packaging and reproducibility

- `Dockerfile` pins the Rust 1.88 Debian 12 builder and distroless `cc-debian12`
  non-root multi-architecture indexes by SHA-256 digest. The final image runs as
  UID/GID 65532 and has vector-form entrypoint, no shell, and no package manager.
- CI builds the image, asserts its configured user, and runs `--version` with a
  read-only root, all capabilities dropped, and no-new-privileges.
- The systemd unit has empty capability sets, strict/read-only filesystem
  protection, one 0700 state directory, private temporary/devices namespaces,
  kernel/process/syscall restrictions, and resource caps.
- `scripts/verify-reproducible-build.sh` built twice in isolated target
  directories and confirmed byte-identical archives. Release consumers must
  verify the checksum generated beside the artifact from the tagged commit;
  embedding that self-referential checksum in the source tree is deliberately
  avoided.

The source host lacked permission to its Docker daemon, so the authoritative
container construction/smoke evidence is the Phase 4 PR's release-candidate CI
job. Local static systemd/Dockerfile policy validation passed.

## Compatibility and fuzzing

Normal CI parses representative system-info responses for PAN-OS 10.2, 11.1,
11.2, and 12.1. This is parser compatibility only. PAN-OS 12.1.5 has real
strict-HTTPS read, full MCP, and reversible guarded-mutation evidence; other
families remain unclaimed until `scripts/test-panos-matrix.sh` is run against
them.

All five libFuzzer targets completed bounded 10-second runs under nightly Rust
and cargo-fuzz 0.13.2 with 5-second per-input and 1 GiB RSS limits, with no
crash, timeout, or artifact:

- bearer header plus stored token-digest parsing;
- PAN-OS response XML;
- candidate XML element validation;
- read/write XPath validation;
- bounded token-store JSON/schema/reference validation.

The bearer/digest run executed 4,281,337 inputs and the token-store run executed
2,275,874 inputs. Every fuzz binary also compiles under the Rust 1.88 MSRV.

## Release measurements

Measurements used an optimized release profile with thin LTO, one codegen unit,
abort-on-panic, and stripped symbols.

| Measurement | Result |
|---|---:|
| 1,024-token worst-case miss, 10,000 iterations | 58.992 µs/lookup |
| In-memory full MCP `list_devices`, 1,000 iterations | p50 15.701 µs; p95 16.791 µs |
| Warm pooled mock HTTPS facts, 200 iterations | p50 40.172 µs; p95 46.682 µs |
| Rust full MCP to PAN-OS 12.1.5, 50 iterations | mean 425.246 ms; p50 410.217 ms; p95 507.546 ms |
| Python `pan-mcp` direct tool to the same device, 50 iterations | mean 435.348 ms; p50 390.830 ms; p95 520.634 ms |

The real-device harness alternated order and used the identical system-info XML
command/network path. Rust included stdio MCP dispatch; Python deliberately
excluded FastMCP dispatch, favoring Python. Rust p95 was 1.026x faster, but the
roughly 350-500 ms PAN-OS management-plane latency dominated both. The result
supports device-bound performance parity and extremely low Rust overhead; it
does not support a claim of dramatic same-device latency improvement.

## Reproducible gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo doc --workspace --no-deps --locked
cargo +1.88.0 check --workspace --all-targets --locked
cargo +1.88.0 check --manifest-path fuzz/Cargo.toml --bins --locked
cargo audit --deny warnings
cargo audit --file fuzz/Cargo.lock --no-fetch --deny warnings
cargo deny check licenses bans sources
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check licenses bans sources
scripts/verify-packaging.sh
scripts/verify-reproducible-build.sh
```

The PR is accepted only when its build/lint/test, MSRV, supply-chain, and
release-candidate packaging jobs are all green.

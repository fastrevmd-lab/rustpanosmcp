# rust-panosmcp

Async Rust Model Context Protocol server for Palo Alto Networks PAN-OS
firewalls. The repository now contains the Phase 1 secure, read-only client.

The project goal is a small, fast, production-oriented server with the same
security posture as `rust-junosmcp`: bearer-token authentication, per-token
device and tool scopes, TLS, strict remote-bind refusal rules, bounded input
and output, auditable change operations, and efficient connection reuse.

The architecture and delivery plan are in [PLAN.md](PLAN.md). Security
boundaries and release-blocking controls are tracked in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Status

Phase 1 implements validated inventory and secret providers, strict HTTPS with
system roots/custom CA/exact leaf pinning, pooled async PAN-OS XML API calls,
typed errors, timeouts, cancellation, output caps, and a per-device semaphore.
The stdio MCP server exposes four read-only tools: `list_devices`,
`gather_device_facts`, `execute_panos_op`, and `get_panos_config`.

The full HTTPS mock, MCP end-to-end, and explicitly configured `panosvm` lab
firewall acceptance suites pass. Phase 1 is complete; the reproducible evidence
is recorded in [docs/PHASE1_ACCEPTANCE.md](docs/PHASE1_ACCEPTANCE.md).

Bearer-protected Streamable HTTP is Phase 2. Phase 1 uses local stdio and must
not be placed behind an unauthenticated network bridge.

## Workspace

```text
rust-panosmcp/          # MCP binary and stdio adapter
rust-panosmcp-auth/     # bearer and secret-handling foundations
rust-panosmcp-core/     # inventory, PAN-OS client, validation, tool logic
config/                 # secret-free inventory examples
docs/                   # operator guidance and phase notes
fuzz/                   # isolated cargo-fuzz workspace
```

## Run Phase 1

Start from [config/devices.example.json](config/devices.example.json), keep the
real inventory out of Git, and provide the referenced environment secret:

```bash
export PANOS_LAB_API_KEY='runtime-secret'
cargo run --locked --release -- --device-mapping /absolute/path/devices.json
```

See [docs/PHASE1_OPERATIONS.md](docs/PHASE1_OPERATIONS.md) for the schema, TLS
trust choices, file-permission rules, tool surface, and explicit lab test.

## Validate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

## Project stance

This is an independent community project and does not claim affiliation with
or endorsement by Palo Alto Networks. Product names and trademarks are used
only to identify the systems with which the software interoperates.

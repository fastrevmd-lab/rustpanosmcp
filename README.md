# rust-panosmcp

Async Rust Model Context Protocol server for Palo Alto Networks PAN-OS
firewalls. The repository now contains the Phase 2 bearer-protected, read-only
remote server.

The project goal is a small, fast, production-oriented server with the same
security posture as `rust-junosmcp`: bearer-token authentication, per-token
device and tool scopes, TLS, strict remote-bind refusal rules, bounded input
and output, auditable change operations, and efficient connection reuse.

The architecture and delivery plan are in [PLAN.md](PLAN.md). Security
boundaries and release-blocking controls are tracked in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Status

Phase 1 implemented validated inventory and secret providers, strict HTTPS with
system roots/custom CA/exact leaf pinning, pooled async PAN-OS XML API calls,
typed errors, timeouts, cancellation, output caps, and a per-device semaphore.
Phase 2 adds digest-only bearer tokens, exact device/tool scopes, atomic
inventory/token reload, TLS Streamable HTTP, Host/Origin validation, bounded
request bodies, IP/token rate limits, and audit-safe request tracing. Both
transports expose four read-only tools: `list_devices`,
`gather_device_facts`, `execute_panos_op`, and `get_panos_config`.

The full HTTPS mock, MCP end-to-end, and explicitly configured `panosvm` lab
firewall acceptance suites pass. Phase 1 is complete; the reproducible evidence
is recorded in [docs/PHASE1_ACCEPTANCE.md](docs/PHASE1_ACCEPTANCE.md).

Phase 2 acceptance evidence is recorded in
[docs/PHASE2_ACCEPTANCE.md](docs/PHASE2_ACCEPTANCE.md). Configuration mutation
is intentionally absent until the guarded Phase 3 lifecycle is complete.

## Workspace

```text
rust-panosmcp/          # MCP binary and stdio adapter
rust-panosmcp-auth/     # bearer and secret-handling foundations
rust-panosmcp-core/     # inventory, PAN-OS client, validation, tool logic
config/                 # secret-free inventory examples
docs/                   # operator guidance and phase notes
fuzz/                   # isolated cargo-fuzz workspace
```

## Run

Start from [config/devices.example.json](config/devices.example.json), keep the
real inventory out of Git, and provide the referenced environment secret:

```bash
export PANOS_LAB_API_KEY='runtime-secret'
cargo run --locked --release -- --device-mapping /absolute/path/devices.json
```

For a remote listener, first mint a least-privilege token and then start native
TLS Streamable HTTP:

```bash
cargo run --locked --release -- \
  --device-mapping /etc/rust-panosmcp/devices.json \
  token add \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --name read-only-client \
  --devices lab-fw-01 \
  --tools list_devices,gather_device_facts,execute_panos_op,get_panos_config

cargo run --locked --release -- \
  --device-mapping /etc/rust-panosmcp/devices.json \
  --transport streamable-http \
  --host 0.0.0.0 --port 30031 \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --tls-cert /etc/rust-panosmcp/server.crt \
  --tls-key /etc/rust-panosmcp/server.key \
  --allowed-host mcp.example.test \
  --allowed-origin https://client.example.test
```

Capture the first command's stdout securely: that is the only display of the
new bearer secret. See [docs/PHASE2_OPERATIONS.md](docs/PHASE2_OPERATIONS.md)
for token rotation, reload, refusal rules, reverse-proxy deployment, and all
security defaults. Phase 1 inventory and firewall TLS details remain in
[docs/PHASE1_OPERATIONS.md](docs/PHASE1_OPERATIONS.md).

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

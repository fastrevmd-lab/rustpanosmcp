# rust-panosmcp

Async Rust Model Context Protocol server for Palo Alto Networks PAN-OS
firewalls. The repository contains the v0.2.2 dependency-maintenance release:
a bearer-protected server with a guarded PAN-OS candidate configuration
lifecycle and hardened release packaging.

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
Phase 2 added digest-only bearer tokens, exact device/tool scopes, atomic
inventory/token reload, TLS Streamable HTTP, Host/Origin validation, bounded
request bodies, IP/token rate limits, and audit-safe request tracing. Both
transports expose four read-only tools: `list_devices`,
`gather_device_facts`, `execute_panos_op`, and `get_panos_config`.

Phase 3 adds opt-in candidate fingerprints, narrow XPath policy, PAN-OS config
locks, per-device serialization, stage/diff/full validation, admin-scoped
partial commit/revert, job reconciliation, and structured mutation audit. Write
tools require explicit token scopes; `*` remains read-only.

Phase 4 adds a digest-pinned non-root distroless image, hardened systemd unit,
read-only deployment guidance, PAN-OS release-family matrix, five parser fuzz
targets, byte-reproducible archives, security/runbook documentation, and
published Rust/Python measurements.

v0.2 adds persistent multi-action change sets, token-specific XPath/action
grants and expiry, canonical-endpoint serialization, and independent approval
bound to the exact owner/device/fingerprint/action digest. Approved sets apply
under one PAN-OS config lock and automatically admin-revert if a later action
fails. They then use the existing diff, full-validation, commit, or discard
lifecycle. See [docs/V0.2_CHANGE_SETS.md](docs/V0.2_CHANGE_SETS.md).

v0.2.1 makes PAN-OS configuration-lock release a confirmed state transition:
commit/discard records clear `config_lock_held` only after the device accepts
unlock, while a failed unlock is persisted as `indeterminate` for explicit
reconciliation. It also records the default-trusted TLS and lab rollout
evidence in [docs/V0.2.1_ACCEPTANCE.md](docs/V0.2.1_ACCEPTANCE.md).

v0.2.2 updates the maintained Rust dependency graph and GitHub Actions while
preserving the v0.2.1 PAN-OS tool, authorization, inventory, and mutation-state
interfaces. The published release and guarded lab rollout evidence is in
[docs/V0.2.2_ACCEPTANCE.md](docs/V0.2.2_ACCEPTANCE.md). Multi-vsys, HA, and
Panorama work remains deferred.

The full HTTPS mock, MCP end-to-end, and explicitly configured `panosvm` lab
firewall acceptance suites pass. Phase 1 is complete; the reproducible evidence
is recorded in [docs/PHASE1_ACCEPTANCE.md](docs/PHASE1_ACCEPTANCE.md).

Phase 2 acceptance evidence is recorded in
[docs/PHASE2_ACCEPTANCE.md](docs/PHASE2_ACCEPTANCE.md). Configuration mutation
acceptance is in [docs/PHASE3_ACCEPTANCE.md](docs/PHASE3_ACCEPTANCE.md), with
operator requirements in [docs/PHASE3_OPERATIONS.md](docs/PHASE3_OPERATIONS.md).
Phase 4 release evidence is in
[docs/PHASE4_ACCEPTANCE.md](docs/PHASE4_ACCEPTANCE.md). Production deployment,
rotation, backup/recovery, and upgrades are covered by
[docs/OPERATIONS.md](docs/OPERATIONS.md); see also
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md),
[docs/BENCHMARKS.md](docs/BENCHMARKS.md), and [SECURITY.md](SECURITY.md).

## Workspace

```text
rust-panosmcp/          # MCP binary and stdio adapter
rust-panosmcp-auth/     # bearer and secret-handling foundations
rust-panosmcp-core/     # inventory, PAN-OS client, validation, tool logic
config/                 # secret-free inventory examples
docs/                   # operator guidance and phase notes
fuzz/                   # isolated cargo-fuzz workspace
packaging/              # distroless/container and systemd assets
scripts/                # release, matrix, fuzz, and benchmark gates
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
  --state-file /var/lib/rust-panosmcp/mutation-state.json \
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
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
scripts/verify-packaging.sh
```

Create a deterministic release archive with `scripts/build-release.sh`, or
compile it twice and require byte identity with
`scripts/verify-reproducible-build.sh`. Container/systemd installation is
documented in the operator runbook.

## Project stance

This is an independent community project and does not claim affiliation with
or endorsement by Palo Alto Networks. Product names and trademarks are used
only to identify the systems with which the software interoperates.

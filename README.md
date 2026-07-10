# rust-panosmcp

Async Rust Model Context Protocol server for Palo Alto Networks PAN-OS
firewalls. The repository is currently at the Phase 0 foundation milestone.

The project goal is a small, fast, production-oriented server with the same
security posture as `rust-junosmcp`: bearer-token authentication, per-token
device and tool scopes, TLS, strict remote-bind refusal rules, bounded input
and output, auditable change operations, and efficient connection reuse.

The architecture and delivery plan are in [PLAN.md](PLAN.md). Security
boundaries and release-blocking controls are tracked in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Status

Phase 0 provides a compileable three-crate Cargo workspace, a no-tool stdio MCP
server, bounded bearer/XML parser foundations, secret redaction, mock fixtures,
fuzz targets, and CI supply-chain gates. It does not yet connect to a firewall,
listen over HTTP, or implement bearer-token verification.

## Workspace

```text
rust-panosmcp/          # MCP binary and transport adapter
rust-panosmcp-auth/     # bearer and secret-handling foundations
rust-panosmcp-core/     # PAN-OS-independent parsing and future tool logic
fuzz/                   # isolated cargo-fuzz workspace
```

## Validate Phase 0

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

## Project stance

This will be an independent community project and will not claim affiliation
with or endorsement by Palo Alto Networks. Product names and trademarks will
be used only to identify the systems with which the software interoperates.

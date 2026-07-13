<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rust-panosmcp</h1>

<p align="center"><strong>Async Rust Model Context Protocol server for Palo Alto Networks PAN-OS firewalls</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project and does not claim affiliation with or endorsement by Palo Alto Networks. Product names and trademarks are used only to identify the systems with which the software interoperates.

The repository contains the v0.2.2 dependency-maintenance release: a bearer-protected server with a guarded PAN-OS candidate configuration lifecycle and hardened release packaging.

The project goal is a small, fast, production-oriented server with the same
security posture as `rust-junosmcp`: bearer-token authentication, per-token
device and tool scopes, TLS, strict remote-bind refusal rules, bounded input
and output, auditable change operations, and efficient connection reuse.

The architecture and delivery plan are in [PLAN.md](PLAN.md). Security
boundaries and release-blocking controls are tracked in
[THREAT_MODEL.md](THREAT_MODEL.md).

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

## Quick start

### Installation

Choose one of three install paths:

#### Release tarball (Linux x86_64)

Download the latest release from [GitHub releases](https://github.com/fastrevmd-lab/rustpanosmcp/releases). Assets follow the pattern `rust-panosmcp-v0.2.2-x86_64-unknown-linux-gnu.tar.gz` with a corresponding `.sha256` file.

```bash
# Download and verify
curl -LO https://github.com/fastrevmd-lab/rustpanosmcp/releases/download/v0.2.2/rust-panosmcp-v0.2.2-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/fastrevmd-lab/rustpanosmcp/releases/download/v0.2.2/rust-panosmcp-v0.2.2-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c rust-panosmcp-v0.2.2-x86_64-unknown-linux-gnu.tar.gz.sha256

# Extract
tar xzf rust-panosmcp-v0.2.2-x86_64-unknown-linux-gnu.tar.gz
cd rust-panosmcp-v0.2.2-x86_64-unknown-linux-gnu

# Install the binary and systemd assets
sudo install -m 0755 rust-panosmcp /usr/local/bin/rust-panosmcp
sudo install -m 0644 packaging/systemd/rust-panosmcp.sysusers /usr/lib/sysusers.d/rust-panosmcp.conf
sudo install -m 0644 packaging/systemd/rust-panosmcp.tmpfiles /usr/lib/tmpfiles.d/rust-panosmcp.conf
sudo install -m 0644 packaging/systemd/rust-panosmcp.service /etc/systemd/system/rust-panosmcp.service

# Create the service user and directories, then start
sudo systemd-sysusers
sudo systemd-tmpfiles --create
sudo systemctl daemon-reload
sudo systemctl enable --now rust-panosmcp
```

This creates a dedicated `rust-panosmcp` system user and provisions `/etc/rust-panosmcp` (config, root-owned) and `/var/lib/rust-panosmcp` (state). Place `devices.json` and `tokens.json` under `/etc/rust-panosmcp` before starting; see [packaging/systemd/](packaging/systemd/) for unit details.

#### Docker / GHCR

Prebuilt images are published to `ghcr.io/fastrevmd-lab/rust-panosmcp` on every release tag. See [.github/workflows/release-image.yml](.github/workflows/release-image.yml) for the build pipeline.

```bash
# Pull the image
docker pull ghcr.io/fastrevmd-lab/rust-panosmcp:latest

# Run with mounted config (see compose.example.yaml)
docker run --rm -i \
  -v "$PWD/devices.json:/etc/rust-panosmcp/devices.json:ro" \
  -v "$PWD/tokens.json:/etc/rust-panosmcp/tokens.json:ro" \
  ghcr.io/fastrevmd-lab/rust-panosmcp:latest
```

A `compose.example.yaml` is included in the repository.

#### Build from source

Requires Rust 1.88 or newer (MSRV).

```bash
git clone https://github.com/fastrevmd-lab/rustpanosmcp.git
cd rustpanosmcp
cargo build --release --locked
./target/release/rust-panosmcp --version
```

### Run (stdio)

Start from [config/devices.example.json](config/devices.example.json), keep the
real inventory out of Git, and provide the referenced environment secret:

```bash
export PANOS_LAB_API_KEY='runtime-secret'
cargo run --locked --release -- --device-mapping /absolute/path/devices.json
```

### Run (streamable-http with auth)

First mint a least-privilege token, then start the TLS Streamable HTTP transport:

```bash
cargo run --locked --release -- \
  --device-mapping /etc/rust-panosmcp/devices.json \
  token add \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --name read-only-client \
  --devices fw-example \
  --tools list_devices,gather_device_facts,execute_panos_op,get_panos_config

cargo run --locked --release -- \
  --device-mapping /etc/rust-panosmcp/devices.json \
  --transport streamable-http \
  --host 0.0.0.0 --port 30031 \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --tls-cert /etc/rust-panosmcp/server.crt \
  --tls-key /etc/rust-panosmcp/server.key \
  --allowed-host mcp.example.net \
  --allowed-origin https://client.example.net
```

Capture the first command's stdout securely: that is the only display of the
new bearer secret. See [docs/PHASE2_OPERATIONS.md](docs/PHASE2_OPERATIONS.md)
for token rotation, reload, refusal rules, reverse-proxy deployment, and all
security defaults. Phase 1 inventory and firewall TLS details remain in
[docs/PHASE1_OPERATIONS.md](docs/PHASE1_OPERATIONS.md).

> Next: [Learn the reader, writer, and reviewer MCP role
> workflow](docs/MCP_ROLE_WORKFLOW.md).

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

## MCP tools reference

The server exposes 15 MCP tools, grouped by operation type:

### Read-only tools

- **`list_devices`** — List authorized PAN-OS devices and safe metadata; never returns API keys.
- **`gather_device_facts`** — Gather hostname, model, serial, version, management IP, and uptime from an authorized device.
- **`execute_panos_op`** — Execute a read-only PAN-OS XML command rooted at `<show>` on an authorized device, with output caps.
- **`get_panos_config`** — Read running or candidate PAN-OS configuration at a validated `/config` XPath on an authorized device.

### Candidate lifecycle tools (mutation)

- **`get_candidate_fingerprint`** — Return a SHA-256 fingerprint over all operator-authorized candidate subtrees.
- **`stage_panos_config`** — Stage one policy-bounded PAN-OS candidate set/delete using an expected fingerprint.
- **`diff_panos_candidate`** — Return a bounded PAN-OS change summary for the exact staged candidate fingerprint.
- **`validate_panos_candidate`** — Validate a staged candidate and make only the same fingerprint eligible for commit.
- **`commit_panos_candidate`** — Commit only a successfully validated operation using an exact candidate fingerprint.
- **`discard_panos_candidate`** — Discard a staged operation through an admin-scoped partial candidate revert.
- **`get_panos_operation`** — Return safe status for an owned PAN-OS candidate lifecycle operation.

### Change-set tools (v0.2+)

- **`create_panos_change_set`** — Plan and persist 1-64 ordered PAN-OS candidate actions under inventory and token XPath/action scopes.
- **`approve_panos_change_set`** — Approve an unexpired exact change-set digest; self-approval is refused.
- **`get_panos_change_set`** — Return the exact actions, digest, approval, expiry, and operation state for review or recovery.
- **`apply_panos_change_set`** — Apply an independently approved exact change set under one endpoint/config lock, reverting partial failure.

Write tools require explicit token scopes; wildcard `*` grants remain read-only.

## Configuration

Three example files in [config/](config/) demonstrate the configuration surface:

- **[`devices.example.json`](config/devices.example.json)** — Device inventory with authentication, TLS validation modes (system roots, custom CA, or exact leaf pin), per-device concurrency limits, and optional admin override for candidate operations.
- **[`tokens.example.json`](config/tokens.example.json)** — Bearer-token store shape: digest-only storage, per-token device and tool allowlists, optional mutation grants (XPath roots, allowed actions), and expiry timestamps.
- **[`devices.mutation.example.json`](config/devices.mutation.example.json)** — Inventory variant demonstrating mutation-root configuration and admin-scoped candidate workflow fields.

Inventory files never hold inline credentials: each device's `api_key` is a reference — `{"type": "env", "name": "VAR_NAME"}` for an environment variable or `{"type": "file", "path": "/protected/path"}` for a mode-restricted secret file.

## Security

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) for complete coverage. Key points:

- **Authentication required for HTTP** — bearer tokens with SHA-256 digest-only storage; no plaintext secrets persist.
- **Loopback-only defaults** — off-loopback HTTP requires TLS or explicit `--allow-insecure-bind`; off-loopback TLS requires `--allowed-host`.
- **TLS verification always on** — system roots, custom CA bundle, or exact leaf pin; no trust-on-first-use or disabled verification.
- **Bounded I/O** — output caps (512 KiB default, 5 MiB max), request body limits (1 MiB default), timeouts on all PAN-OS calls.
- **Audited mutations** — candidate operations serialize per device, record principal and fingerprint, require explicit commit after validation, and persist lock/job state for recovery.

## CLI reference

```text
Secure, async MCP server for PAN-OS firewalls

Usage: rust-panosmcp [OPTIONS] [COMMAND]

Commands:
  token  Manage the digest-only bearer-token store
  state  Perform offline recovery on the private mutation-state file
  help   Print this message or the help of the given subcommand(s)

Options:
  -f, --device-mapping <DEVICE_MAPPING>
          Validated JSON device inventory [default: devices.json]
  -t, --transport <TRANSPORT>
          MCP transport [default: stdio] [possible values: stdio, streamable-http]
  -H, --host <HOST>
          Numeric bind address for Streamable HTTP [default: 127.0.0.1]
  -p, --port <PORT>
          TCP port for Streamable HTTP [default: 30031]
      --tokens-file <TOKENS_FILE>
          Absolute digest-only bearer-token file path
      --state-file <STATE_FILE>
          Absolute private JSON file for persistent change-set and operation state
      --tls-cert <TLS_CERT>
          Absolute PEM certificate path; requires `--tls-key`
      --tls-key <TLS_KEY>
          Absolute PEM private-key path; requires `--tls-cert`
      --allow-no-auth
          Disable bearer auth for a loopback-only development listener
      --allow-insecure-bind
          Permit a non-loopback plaintext listener behind a trusted TLS proxy
      --allowed-host <ALLOWED_HOST>
          Additional accepted HTTP Host authority. Repeat for multiple values
      --allowed-origin <ALLOWED_ORIGIN>
          Accepted browser Origin URL. Repeat for multiple values
      --ip-rate-per-minute <IP_RATE_PER_MINUTE>
          Per-source-IP requests allowed per rolling minute window [default: 120]
      --token-rate-per-minute <TOKEN_RATE_PER_MINUTE>
          Per-authenticated-token requests allowed per rolling minute window [default: 240]
      --request-body-limit <REQUEST_BODY_LIMIT>
          Maximum Streamable HTTP request body in bytes [default: 1048576]
  -h, --help
          Print help
  -V, --version
          Print version

Token subcommands:
  add     Mint a token, store only its digest, and print the secret once
  list    List token names and scopes without secrets or digests
  revoke  Revoke a named token
  rotate  Replace a token secret while preserving its scopes

State subcommands:
  resolve  Mark an indeterminate operation terminal after manual PAN-OS reconciliation
```

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

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="28" alt="">
  </picture><br>
  <sub><code>a mechub project</code> · deterministic decides · the model explains · a human approves<br>
  <a href="https://github.com/fastrevmd-lab">github.com/fastrevmd-lab</a></sub>
</p>

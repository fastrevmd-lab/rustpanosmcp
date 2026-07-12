# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-07-11

[Release](https://github.com/fastrevmd-lab/rustpanosmcp/releases/tag/v0.2.2)

### Changed

- Updated maintained Rust dependency graph: `reqwest` 0.13.3 → 0.13.4, `rustls` 0.23.40 → 0.23.41, `rcgen` 0.14.7 → 0.14.8, `arc-swap` 1.9.1 → 1.9.2, `http` 1.4.0 → 1.4.2, `serde_json` 1.0.149 → 1.0.150, `zeroize` 1.8.2 → 1.9.0.
- Updated GitHub Actions workflows: `actions/checkout` 5 → 7, `docker/login-action` 3 → 4, `docker/setup-buildx-action` 3 → 4, `docker/metadata-action` 5 → 6, `docker/setup-qemu-action` 3 → 4, `docker/build-push-action` 6 → 7.

### Security

- Dependency maintenance closes upstream advisories for non-reachable code paths in transitive dependencies.

**Note:** v0.2.2 preserves the v0.2.1 PAN-OS tool surface, authorization model, inventory schema, mutation-state format, and deployment behavior. No API or configuration changes.

## [0.2.1] - 2026-07-11

[Release](https://github.com/fastrevmd-lab/rustpanosmcp/releases/tag/v0.2.1)

### Fixed

- PAN-OS configuration-lock release is now a confirmed state transition: commit and discard record `config_lock_held: false` only after the device accepts unlock. A failed unlock is persisted as `indeterminate` state with recovery details for explicit reconciliation.

### Changed

- Lab deployment now uses Let's Encrypt public TLS certificate chain for `https://rust-panosmcp.mechub.org:30031`, trusted by default in system and client trust stores. Previous self-signed local-CA certificate required per-call `--insecure` or custom CA distribution.

### Security

- Rotated Cloudflare DNS-01 ACME API token to least-privilege scope (zone-specific, no token-management permission).
- Rotated lab writer and reviewer bearer tokens with eight-hour lifetime and revalidated forbidden cross-role tool calls return HTTP 403.

**Note:** v0.2.1 is a focused maintenance release addressing lock-state reconciliation and production TLS trust. PAN-OS tool surface and authorization model unchanged from v0.2.0.

## [0.2.0] - 2026-07-11

[Release](https://github.com/fastrevmd-lab/rustpanosmcp/releases/tag/v0.2.0)

### Added

- **Multi-action change sets** with independent approval workflow:
  - `create_panos_change_set` — plan and persist 1-64 ordered PAN-OS candidate actions under inventory and token XPath/action scopes.
  - `approve_panos_change_set` — independently approve an exact change-set digest; self-approval refused.
  - `get_panos_change_set` — inspect exact actions, digest, approval state, expiry, and operation status.
  - `apply_panos_change_set` — apply an independently approved change set under one PAN-OS config lock, with automatic admin-scoped revert on partial failure.
- **Token-specific mutation grants**: per-token XPath root and action (`set`, `delete`) allowlists, enforced in addition to inventory mutation roots.
- **Token expiry**: `--expires-at-unix` and `--expires-in-secs` parameters for `token add` command; expired tokens fail authentication with HTTP 401.
- **Canonical-endpoint serialization**: multiple inventory aliases resolving to the same PAN-OS endpoint share one mutation lock to prevent concurrent conflicting operations.
- Approval digest covers writer identity, device, candidate fingerprint, and ordered actions; expires 15 minutes after planning, single-use only.
- Change-set state persists across server restart; unapproved plans remain available, in-flight operations become `indeterminate` and block endpoint until reconciled.
- `state resolve` CLI subcommand for offline recovery: mark an `indeterminate` operation as `committed` or `discarded` after manual PAN-OS reconciliation.

### Changed

- Token-store file format v1 (no mutation grant) accepted and auto-migrates to v2 on next write. Existing v0.1 tokens have no v0.2 mutation grant.
- Wildcard tool scope (`*`) remains read-only; mutation tools require explicit tool names in token scope.

### Security

- Change-set approval prevents single-actor unilateral mutations when writer and reviewer tokens are held by different principals.
- Partial-apply failure triggers immediate admin-scoped revert; failed revert persists `indeterminate` state and blocks endpoint for manual intervention.
- State file is atomically replaced with mode 0600, refused if symlink/non-regular/over 8 MiB/group-or-other-readable.

## [0.1.0] - 2026-07-10

[Release](https://github.com/fastrevmd-lab/rustpanosmcp/releases/tag/v0.1.0)

Initial release.

### Added

- **Read-only MCP tools**:
  - `list_devices` — list authorized PAN-OS devices and safe metadata.
  - `gather_device_facts` — gather hostname, model, serial, version, management IP, uptime via `show system info`.
  - `execute_panos_op` — execute read-only PAN-OS XML operational commands rooted at `<show>`, with output caps.
  - `get_panos_config` — read running or candidate configuration at validated `/config` XPath.
- **Mutation lifecycle tools**:
  - `get_candidate_fingerprint` — SHA-256 fingerprint over operator-authorized candidate subtrees.
  - `stage_panos_config` — stage one policy-bounded set/delete candidate action with expected fingerprint.
  - `diff_panos_candidate` — bounded running/candidate change summary for exact staged fingerprint.
  - `validate_panos_candidate` — full PAN-OS validation; only validated fingerprint eligible for commit.
  - `commit_panos_candidate` — admin-scoped partial commit with job reconciliation.
  - `discard_panos_candidate` — admin-scoped partial candidate revert.
  - `get_panos_operation` — safe status for owned candidate lifecycle operation, including detached/indeterminate states.
- **Secure PAN-OS client**: pooled async HTTPS with strict TLS (system roots, custom CA bundle, or exact leaf pin), `X-PAN-KEY` authentication, per-device concurrency semaphore, timeouts, cancellation, and bounded XML response parsing (DTD refused, 5 MiB hard cap).
- **Inventory provider**: JSON device mapping with secret references (`{"type": "env"}` environment variables or `{"type": "file"}` protected files) instead of inline credentials. Per-device TLS validation mode, concurrency limit, optional admin override for candidate operations.
- **Bearer-token authentication**: digest-only SHA-256 storage, per-token device and tool scopes, atomic SIGHUP hot-reload.
- **MCP transports**: stdio (local) and Streamable HTTP with optional native TLS.
- **Streamable HTTP security**: Host/Origin allowlists (DNS-rebinding defense), per-IP and per-token rate limits (120/240 req/min defaults), request body limit (1 MiB default), loopback-only auth bypass, off-loopback requires TLS or explicit `--allow-insecure-bind`.
- **Token management CLI**: `token add` (mint + digest-only store + one-time secret print), `token list`, `token revoke`, `token rotate` (preserve scopes), optional `--server-pid` for automatic SIGHUP after write.
- **XPath mutation policy**: inventory-level and token-level mutation-root allowlists, narrow set/delete actions, explicit delete confirmation required.
- **Per-device serialization**: candidate operations on the same device execute serially; PAN-OS config lock acquired before mutation, released after commit/discard.
- **Operation state persistence**: private mutation-state JSON file (mode 0600, atomic write, 8 MiB cap) tracks candidate fingerprint, operation stage, PAN-OS job ID, lock state. Restart converts in-flight ops to `indeterminate` and blocks endpoint until reconciled.
- **Audit tracing**: structured request events (principal, device, tool, result) with timestamp and operation ID.
- **Deployment packaging**: reproducible release tarball, multi-platform distroless container (amd64/arm64), systemd unit with hardening (non-root `rust-panosmcp` user, read-only paths, private `/tmp`), sysusers/tmpfiles for `/etc/rust-panosmcp` and `/var/lib/rust-panosmcp`.
- **Quality gates**: workspace formatting, Clippy warnings denied, 71 tests, fuzz-target compilation, RustSec audit, cargo-deny license/bans/source policy, byte-reproducible builds.
- **Lab acceptance**: end-to-end reversible mutation test against PAN-OS 12.1.5 `panosvm` lab firewall proves candidate lock, fingerprint, set/delete, diff, full validation job, admin-scoped commit, and cleanup.

### Security

- TLS verification always on: no trust-on-first-use, no disabled verification. System roots, custom CA, or exact leaf pin required.
- Bearer tokens hashed with SHA-256; plaintext secrets never persist.
- Loopback-only defaults: off-loopback HTTP requires TLS or explicit override; off-loopback TLS requires `--allowed-host`.
- Bounded I/O: output caps (512 KiB default, 5 MiB max), request body limits, timeouts on all PAN-OS calls.
- Mutation guardrails: fingerprint drift refused, narrow XPath roots, explicit delete confirmation, admin-scoped operations, per-device serialization, config lock lifecycle.
- Protected secrets: environment-variable and protected-file references keep credentials out of inventory JSON; file reads use `O_NOFOLLOW` and validate the opened descriptor on Unix.

[0.2.2]: https://github.com/fastrevmd-lab/rustpanosmcp/releases/tag/v0.2.2
[0.2.1]: https://github.com/fastrevmd-lab/rustpanosmcp/releases/tag/v0.2.1
[0.2.0]: https://github.com/fastrevmd-lab/rustpanosmcp/releases/tag/v0.2.0
[0.1.0]: https://github.com/fastrevmd-lab/rustpanosmcp/releases/tag/v0.1.0

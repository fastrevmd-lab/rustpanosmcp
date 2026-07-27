# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Blocklist guardrails for read-only tools.** `execute_panos_op` and
  `get_panos_config` now evaluate an optional per-inventory blocklist through
  the shared `mecmcp-policy` engine, giving PAN-OS the same deny-pattern
  guardrails Junos has had. Previously any `<show>` command was accepted from a
  caller holding a valid token.

  **Additive: a deployment with no blocklist configured behaves exactly as
  before.** That is asserted directly rather than inferred — see
  `unconfigured_blocklist_leaves_execute_panos_op_unchanged` and its
  `get_panos_config` counterpart.

  The engine is **fail-open**: a command matching no rule is allowed. That is
  the correct model for an operator blocklist, but it is the opposite of what
  the mutation path does, so it is worth stating plainly.

- **Mutations are unchanged and stay fail-closed.** `validate_write_xpath`
  continues to require an XPath to sit under an operator-configured root.
  Prefix allowlist and glob blocklist are different authorization models, and
  moving mutations onto the blocklist would have silently widened what a
  mutation token can reach.


### Changed

- **Inventory loading moved to the shared `mecmcp-inventory` crate.** The
  `{"version":1,"devices":[…]}` envelope parses exactly as before — the trait
  was built around both servers' existing schemas rather than converging them.
  Two behaviours stay this server's own: an empty `devices` array is still
  rejected, and `api_key: {"type":"env",…}` still resolves name-only so
  `token add` works without runtime credentials.

- **CLI, signal handling, graceful shutdown, and the token subcommands now come
  from the shared `mecmcp-runtime` crate.** No user-visible change: every flag
  keeps its spelling and defaults, `state resolve` remains PAN-OS-only, and
  `mutation-state.json` is untouched in both format and location handling.

- **TLS loading moved to `mecmcp-transport`.** This repo's `src/tls.rs` was the
  original hardened loader — `O_NOFOLLOW`, size caps, a mode check and an owner
  check, `Zeroizing` on the key bytes — and it was lifted into the shared crate
  during Phase 3a so `rustjunosmcp` could adopt it too. The local copy is now
  deleted and this server calls the shared one: the same code, same behaviour.
  Its two unit tests went with it; the shared crate carries those plus a
  symlink-refusal test, and `mcp_https.rs` still covers the wiring end to end
  here.

## [0.4.0] - 2026-07-25

### Added

- **Structured audit logging via the shared [`mecmcp-audit`](https://github.com/fastrevmd-lab/mecmcp) crate** (`audit-v0.1.5`). One event per tool call with caller attribution, target devices, outcome, and execution duration. Previously the server contained only an `AUDIT_TARGET` constant with no active logging.
- **Change-set lifecycle auditing.** `create_panos_change_set`, `approve_panos_change_set`, and `apply_panos_change_set` each emit an audit event. The approval event carries both the **change-set id and the fingerprint digest**, providing independent evidence that a second principal reviewed the exact digest later applied. Previously `mutation-state.json` — a file the server itself rewrites — was the only record of approval.
- **New CLI flags for audit configuration:**
  - `--audit-format` — choose `json` (default, machine-parseable) or `pretty` (human-readable).
  - `--audit-log-file` — write audit events to a file path.
  - `--audit-journald` — emit audit events to systemd journal.
  - `--audit-redact` — HMAC-pseudonymise declared fields (device names, caller identity) so the log can be shipped to a SIEM without leaking operational identifiers.
  - `--audit-hmac-key-file` — path to the HMAC key for redaction; required when `--audit-redact` is enabled.
- Structured `Attribution` (Human/Agent, `on_behalf_of`, `change_ref`) carried through the audit path and included in every logged event.

### Changed

- **Rate limiting now uses a token-bucket algorithm instead of a fixed sliding window**, via the shared [`mecmcp-transport`](https://github.com/fastrevmd-lab/mecmcp) crate (`transport-v0.1.6`). The CLI flags `--ip-rate-per-minute` and `--token-rate-per-minute` are unchanged, but the enforcement is stricter: the old fixed-window implementation admitted up to 2× the nominal rate across a window boundary (a client bursting exactly at the edge of a 60-second window could send the full per-minute quota twice). The token bucket does not allow this — sustained requests are bounded to exactly the configured rate, and clients that previously survived a boundary burst will now receive HTTP 429. This matches `rust-junosmcp`'s behavior as of its v0.8.0 release.

## [0.3.0] - 2026-07-25

> **Operators: check your token-file permissions before upgrading.** The server
> now refuses to start if `tokens.json` is group- or world-readable. Run
> `chmod 600` on it first; see *Upgrade notes* below.

### Changed

- **Authentication now comes from the shared [`mecmcp-auth`](https://github.com/fastrevmd-lab/mecmcp) crate** (`auth-v0.1.4`), replacing this repo's own `token.rs`, `store.rs`, and `file.rs`. `rust-panosmcp-auth` is now a thin vendor layer holding the PAN-OS write grant (`MutationGrant`) and the tool registry. Roughly 1,200 lines of duplicated authentication code were removed. Token scopes, the change-set lifecycle, and the MCP tool surface are unchanged.
- A **new** `tokens.json` is written with envelope `version` 1 rather than 2. Both are accepted on read, and prior releases accept either, so this is compatible in both directions.

### Fixed

- **The on-disk envelope `version` is preserved on write.** Between adopting the shared crate and this release, a `tokens.json` written by the server lost its `version` field entirely, which prior releases require — meaning a rollback could not read the file the newer binary had written. The version a file is read with is now the version it is written back with.
- `token add`, `rotate`, and `revoke` again validate that a token's scopes reference known devices and known tools, and reject duplicate token names. That validation was briefly lost when the lifecycle operations were reimplemented inline.

### Security

- **`tokens.json` must be mode 0600.** A group- or world-readable token file is refused and the server exits rather than starting with credentials exposed. The error names the file, its mode, both uids, and the `chmod 600` remedy.
- Secret zeroing now uses the `zeroize` crate, and the process uid lookup uses `rustix`, so the authentication crate contains no `unsafe`.

### Upgrade notes

```bash
# 1. Verify the token file is not group- or world-readable.
stat -c '%a %U:%G' /var/lib/rust-panosmcp/tokens.json   # expect 600
chmod 600 /var/lib/rust-panosmcp/tokens.json            # if it is not

# 2. Preserve change-set state across the upgrade — it holds approval records.
#    /var/lib/rust-panosmcp/mutation-state.json must not be deleted or reset.
```

No token needs to be reissued and no client needs a new credential.

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

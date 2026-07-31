# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.2] - 2026-07-31

### Changed

- Adopt mecmcp 0.3.8 (tag `v0.3.8`), which carries the whole of mecmcp#90.
- `tokens.json` and `devices.json` are now read through mecmcp's shared hardened
  loader. Both must be a regular file, mode 0600, owned by the service user.
  Inventory previously had **no** permission check at all — a `devices.json`
  left group- or world-readable used to load and now will not. Verified before
  release that 608's deployed files already comply.
- `OperationLimits` and `ChangeSetRecord` gained fields upstream. This server
  takes the shared defaults for the new limits and leaves `targets`/`preview`
  unset, which keeps the state file at version 1 — the same reasoning that
  already governs `policy_signature`, so a rollback to 0.7.1 can still read it.

### Notes

- On-disk state is unchanged in both directions. 608's live 26 KB
  `mutation-state.json` loads under 0.3.8 and round-trips back to version 1.
- Change-set digests are byte-identical: mecmcp keeps the single-target digest
  encoding untouched, so the ten applied change sets on 608 remain valid.

## [0.7.1] - 2026-07-29

### Fixed

- **XPath mutation roots are compared by meaning, not by quote style.**
  `[@name='x']` and `[@name="x"]` are the same XPath, but both mutation checks
  compared strings — and the two sources that feed them, `devices.json` and a
  token's mutation grant, are written by different people at different times.

  Where they disagreed, **every write was refused and no input could satisfy
  both**: single quotes passed the device policy and failed the token grant,
  double quotes did the reverse. A server in that state starts cleanly, serves
  reads, and cannot perform a single mutation. Found on a deployed server whose
  write path had never worked.

  Both checks now canonicalise through one shared helper, so they cannot drift
  apart again. A value containing an apostrophe is left untouched rather than
  mangled — XPath 1.0 has no escape for it — and anything that is not a
  complete, well-formed predicate passes through unchanged, so normalisation can
  never widen a root.

## [0.7.0] - 2026-07-29

### Added

- **`--lab-mode` for single-operator environments.** Change sets are approved on
  creation, so one engineer can plan and apply without a second principal.
  Previously lab mode was hardcoded off with no flag to enable it, so change
  sets were unusable in a one-person lab.

  No approver is invented. A waived change set reports `approver: null`
  alongside `approval_waiver: "lab-mode"`. The server warns at startup that
  two-person control is relaxed.

- **`--approval-timeout-secs`** — how long a change-set approval stays valid.
  Previously a compiled-in 15 minutes with no way to change it.

### Changed

- **The change-set CLI now matches every other mecmcp server** — `--lab-mode`,
  `--state-file`, `--approval-timeout-secs`, spelled and behaving identically.
  An operator who learns one server no longer has to relearn the next.

### Fixed

- **The approval TTL had two sources.** The coordinator used one value while
  `create_change_set` computed expiry from a separate constant, so setting the
  new flag would have applied it to the coordinator's expiry checks while change
  sets silently kept the compiled-in default. Both now read the coordinator.

## [0.6.0] - 2026-07-29

### Fixed

- **A successful commit no longer ends up in the manual-recovery queue.**
  PAN-OS releases the vsys configuration lock as part of committing, so the
  explicit release that followed failed with `Config is not currently locked`
  and the operation was marked `Indeterminate`. Because one unreconciled
  operation is allowed per device, **every** successful commit then blocked the
  next change set until someone resolved the record by hand. An already-released
  lock is now treated as success; a release that fails for any other reason
  still fails loudly, because that leaves the lock genuinely held.

- **Restart recovery no longer strands an operation.** The state file was
  repaired after the coordinator had already loaded it, so the API reported
  `indeterminate` while the file said `staged`, and the offline `state resolve`
  tool refused to act on either. The operation could be neither used nor
  resolved, with its candidate and lock still held on the device. The decision
  is now made while state is read, so memory and file always agree.

- **A staged operation whose candidate changed outside this server can be
  cleared.** Previously `discard` refused (the fingerprint guard, correctly) and
  `state resolve` refused (not `indeterminate`), leaving no exit and blocking
  every later change on that device. `state resolve` now accepts any
  non-terminal operation; already-settled records are still refused.

### Added

- **`token add` accepts provenance flags** — `--provider`, `--provider-tier`,
  `--on-behalf-of`, `--actor-type`. These were silently discarded, so tokens
  carried no principal identity into the audit trail.

### Changed

- Change-set and single-operation lifecycles now run on the shared
  `mecmcp-changeset` coordinator rather than a local implementation. No
  user-visible change to the tool surface or the state file.

All of the above was verified against the live PAN-OS 12.1.5 lab firewall,
including a full plan → approve → apply → validate → commit cycle ending in a
terminal `committed` record with no lock held.

## [0.5.0] - 2026-07-26

### Added

- **Session and concurrency caps, enforced by default.** New flags with the
  defaults shown:

  | Flag | Default |
  |---|---|
  | `--max-sessions` | 128 |
  | `--max-sessions-per-token` | 16 |
  | `--max-inflight-requests` | 64 |
  | `--max-inflight-requests-per-token` | 16 |
  | `--max-inflight-requests-per-target` | 4 |

  **These are active on upgrade, not opt-in.** This server previously had no
  session or concurrency limits at all, so a deployment that routinely holds
  more than 128 sessions, or issues more than 16 concurrent requests on one
  token, will begin receiving **HTTP 503** where it previously succeeded. Set a
  flag to `0` to disable that dimension if the defaults are too tight for your
  workload.

  The values match `rustjunosmcp`'s, so the two servers behave alike out of the
  box.

- **`/metrics`, behind `--enable-metrics`.** Exports `panosmcp_*` Prometheus
  series — active sessions, limit hits, tool duration, sessions reaped. Off by
  default.

  **The endpoint is unauthenticated.** Bind it somewhere your scrape target can
  reach and callers cannot, or leave it off.

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

- **Rate limiting now uses a token-bucket algorithm instead of a fixed sliding window**, via the shared [`mecmcp-transport`](https://github.com/fastrevmd-lab/mecmcp) crate (`transport-v0.1.6`). The CLI flags `--ip-rate-per-minute` and `--token-rate-per-minute` are unchanged, but the enforcement is stricter: the old fixed-window implementation admitted up to 2× the nominal rate across a window boundary (a client bursting exactly at the edge of a 60-second window could send the full per-minute quota twice). The token bucket does not allow this — sustained requests are bounded to exactly the configured rate, and clients that previously survived a boundary burst will now receive HTTP 429. This matches `rust-junosmcp`'s behavior as of its v0.8.0 release.

  *(Moved here from the 0.4.0 section, where it was filed by mistake. v0.4.0's tree still contains `FixedWindowLimiter`; the token bucket landed afterwards in #54. Anyone reading 0.4.0's notes would have believed boundary bursts were already bounded.)*

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

## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --locked` passes, with tests added or updated for this change
- [ ] `cargo audit` and `cargo deny check licenses bans sources` are clean, or any new advisory/license exception is called out below
- [ ] This PR touches a device-facing config or command path (a PAN-OS XML API call, candidate stage/diff/validate/commit/discard, or change-set create/approve/apply) — if checked, explain the blast radius and how it stays within existing token scopes/authorization below
- [ ] All fixtures, inventory examples, and device output in this PR are synthetic — no real hostnames, serials, credentials, bearer tokens, PAN-OS API keys, or configuration exports
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] If this touches a mutation or approval path: deterministic code decides, not a model output, and self-approval remains refused

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->

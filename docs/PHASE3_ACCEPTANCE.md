# Phase 3 acceptance

Date: 2026-07-09

Phase 3 implements a fingerprint-bound, serialized, auditable candidate
lifecycle with stage, diff, full validation, admin-scoped partial commit,
admin-scoped discard, detached commit reconciliation, and status polling.

## Automated gates

`rust-panosmcp-core/tests/mutation_lifecycle.rs` uses a deterministic HTTPS
PAN-OS mock and proves:

- stale candidate fingerprints are refused before mutation;
- narrow set and explicitly confirmed delete actions work;
- running/candidate change summary is bounded;
- commit is refused until full validation succeeds;
- the validation and commit jobs are polled to terminal success;
- caller cancellation returns a detached disposition while reconciliation
  continues to committed state;
- a terminal failed commit retains its operation and configuration lock so an
  explicit admin-scoped discard can recover the candidate;
- admin-scoped discard restores candidate to running;
- configuration locks are acquired and released; and
- a principal cannot bypass operation ownership or lifecycle state.

Inventory and XML unit tests cover opt-in write policy, broad-root refusal,
DTD/size/depth checks, exact delete confirmation, and wildcard-token refusal
for every Phase 3 tool.

## PAN-OS lab evidence

The ignored reversible test ran against the configured disposable `panosvm`:

```bash
PANOS_LAB_MUTATION_INVENTORY=/absolute/mutation-inventory.json \
PANOS_LAB_DEVICE=panosvm \
PANOS_LAB_ADDRESS_XPATH="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address" \
cargo test --locked -p rust-panosmcp-core --test lab_mutation \
  -- --ignored --nocapture
```

Observed result on 2026-07-09:

- hostname `panosvm`, PAN-OS `12.1.5`;
- narrow mutation-root fingerprint succeeded without raising the 5 MiB hard
  response cap;
- PAN-OS configuration lock acquisition succeeded;
- address probe set, change summary, full validation job, and admin-scoped
  partial commit succeeded;
- the running configuration contained the committed probe;
- explicitly confirmed delete, second full validation, and second admin-scoped
  partial commit succeeded;
- the running and candidate configurations no longer contain the probe; and
- the complete add/delete cleanup round trip passed in 323.42 seconds.

This confirms the exact API shapes used by the implementation on 12.1.5. It
does not prove behavior on other PAN-OS releases or isolation from another
client sharing the same admin identity; those are explicit deployment limits.

# Phase 1 acceptance

Phase 1 met its exit criteria on 2026-07-09.

## Requirement evidence

| Requirement | Implementation and verification evidence |
|---|---|
| Inventory, schema, and secret providers | `inventory` unit tests cover exact-name lookup, unknown fields/plaintext refusal, HTTPS origins, duplicates, concurrency bounds, environment secrets, and protected file secrets. Unix reads use `O_NOFOLLOW` and validate the opened descriptor. |
| Strict TLS, custom CA/pin, `X-PAN-KEY`, POST-only | The HTTPS integration suite proves custom-CA success, system-root refusal of self-signed TLS, exact leaf-pin success and mismatch refusal, no query string, sensitive header authentication, and form bodies without keys. |
| Typed XML and error mapping | Unit and HTTPS tests cover success/error envelopes, documented code mapping, malformed/deep/oversized XML, DTD refusal, HTTP status errors, facts, and asynchronous job states. |
| Reuse, deadlines, semaphore, cancellation | HTTPS tests prove one warm connection is reused, response and timeout bounds hold, cancellation interrupts a slow request, and server-observed concurrency never exceeds the per-device limit. |
| Four read-only MCP tools | MCP discovery exposes exactly `list_devices`, `gather_device_facts`, `execute_panos_op`, and `get_panos_config`. Mutation-root and unsafe XPath requests are refused before device I/O. |
| Mock end-to-end | `mcp_https` calls every tool through an in-memory MCP client and a pinned in-process HTTPS PAN-OS mock. |
| Explicit lab end-to-end | `lab_firewall` passed all four core tool operations against the explicitly configured `panosvm` lab firewall. `lab_mcp_firewall` then passed all four through the complete MCP-to-HTTPS path. Both suites are opt-in and read-only. |

## Quality gates

The accepted revision passed:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --locked`
- Rust 1.88 workspace and fuzz-target checks
- warning-denied rustdoc
- RustSec audits for the workspace and fuzz lockfiles
- cargo-deny license, ban, and source policy for both workspaces
- locked compilation of both fuzz targets

The real-firewall tests are deliberately ignored in ordinary CI because they
require a named private lab endpoint and external secret. Their commands are
documented in `PHASE1_OPERATIONS.md` and fail closed when configuration or
credentials are missing.

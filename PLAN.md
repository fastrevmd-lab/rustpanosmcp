# rust-panosmcp project plan

Status: Phase 0 implemented; Phases 1-4 planned, 2026-07-09

## 1. Outcome

Build a production-oriented MCP server in async Rust for managing PAN-OS
firewalls. It should preserve the qualities that make `rust-junosmcp` useful:

- low-latency repeated calls through connection reuse;
- bounded parallel work across devices;
- bearer-token authentication with least-privilege scopes;
- secure-by-default HTTP and device connections;
- guardrails around configuration changes;
- explicit timeouts, output limits, stable errors, and audit events;
- deployable as a single binary, container, or systemd service.

The existing Python `pan-mcp` demo is a tool-surface reference, not the
security or transport baseline. The Rust implementation will not inherit its
disabled certificate verification, trust-on-first-use SSH behavior, single
environment token, or synchronous request handling.

## 2. Initial scope

### v0.1: standalone firewalls, XML API first

Use the PAN-OS XML API over HTTPS for the first release. Using one protocol
keeps the attack surface small and lets a pooled async HTTP client serve both
operational and configuration workflows. PAN-OS supports operational commands,
candidate configuration actions, validation, and commits through the XML API.

Initial tools:

1. `list_devices`
2. `gather_device_facts`
3. `execute_panos_op` — XML operational command, guarded by policy
4. `get_panos_config` — running or candidate, optional XPath and output caps
5. `get_panos_config_diff` — candidate versus running, with a bounded result
6. `stage_panos_config` — typed XML API action plus XPath and element
7. `validate_panos_candidate`
8. `commit_panos_candidate` — explicit second step, job polling, audit event
9. `discard_panos_candidate`

The configuration tools deliberately separate staging, validation, commit,
and discard. A later convenience tool may compose those steps, but it must not
weaken authorization or audit boundaries.

### Deferred until after v0.1

- SSH/set-format input and interactive CLI automation;
- Panorama, templates, device groups, and commit-all;
- multi-vsys and HA-aware workflows;
- log/report retrieval, file import/export, upgrades, and content updates;
- dynamic inventory mutation;
- OAuth authorization-server discovery. Static high-entropy bearer tokens are
  the first supported remote-auth mechanism.

## 3. Proposed workspace

```text
rust-panosmcp/
├── Cargo.toml
├── rust-panosmcp/          # CLI, rmcp handler, stdio/HTTP/TLS transport
├── rust-panosmcp-auth/     # token mint/store/scope/middleware
├── rust-panosmcp-core/     # inventory, PAN-OS client, policy, tools
├── config/                 # safe templates without secrets
├── docs/                   # threat model, operations, API compatibility
├── packaging/              # systemd and container assets
├── scripts/                # packaging and integration-test helpers
└── tests/                  # end-to-end transport and mock-device tests
```

Keep transport adapters thin. Tool behavior belongs in `core`, so it can be
unit-tested without an MCP client or listening socket.

## 4. Core design

### MCP transport

- `rmcp` 2.x with stdio and Streamable HTTP at `/mcp`.
- `axum`/`tower` for middleware and `rustls` for native TLS.
- Local stdio remains available without bearer auth.
- Streamable HTTP requires a token store unless an explicit loopback-only
  `--allow-no-auth` escape hatch is selected.
- Non-loopback plain HTTP is refused unless the operator explicitly asserts a
  trusted TLS-terminating proxy with `--allow-insecure-bind`.
- Validate both `Host` and `Origin`; allowlists are explicit for remote use.

### PAN-OS client

- Async `reqwest` client with the rustls backend and one reusable client/pool
  per TLS policy.
- HTTPS and certificate verification are mandatory by default. A device can
  reference a private CA bundle or pinned certificate/SPKI. Any insecure TLS
  mode is lab-only, opt-in, loudly logged, and unavailable by accident.
- Send all API calls as POST form bodies. Put the device API key in the
  `X-PAN-KEY` header so it is not exposed in URLs, proxy logs, or error text.
- Parse the XML response status and numeric code into typed, stable errors.
- Poll asynchronous jobs with cancellation, exponential backoff plus jitter,
  and a caller-visible deadline.
- Use a per-device semaphore with a conservative default of four concurrent
  reads. Serialize candidate-changing and commit operations per device.
- Never retry a mutation unless the operation is proven idempotent or its job
  state can be reconciled.

### Inventory and secrets

- JSON inventory keyed by a stable device name. Calls resolve names only, not
  arbitrary caller-supplied URLs or IP addresses; this prevents the tool from
  becoming an SSRF primitive.
- Device fields: name, HTTPS endpoint, optional vsys, API-key source, TLS trust
  source, tags, timeouts, concurrency cap, and command/config policy.
- API keys are referenced from environment variables or root/service-user
  readable files. Plaintext keys in inventory are refused by default.
- Inventory and secret files receive ownership and permission checks. Secrets
  are redacted from `Debug`, tracing, errors, and serialized tool results.
- SIGHUP reload builds and validates a complete replacement before atomically
  swapping live inventory and token stores.

## 5. Security baseline

### MCP bearer tokens

Match or improve the `rust-junosmcp-auth` model:

- mint 32 random bytes and encode with unpadded base64url;
- print plaintext only at creation/rotation time;
- store only a versioned digest, verify in constant time, and zeroize temporary
  secret buffers where practical;
- scope every token to an allowlist of devices and tools;
- support add, revoke, rotate, list-metadata, and SIGHUP hot reload;
- use RFC 6750-style `401` responses with `WWW-Authenticate` and return `403`
  for authenticated but out-of-scope calls;
- never record bearer values in request logs.

Before implementation, benchmark token lookup at the intended token count.
For small stores, constant-time linear lookup avoids a token-existence timing
oracle. If the store must scale, index by a non-secret token identifier while
keeping secret verification constant-time.

### Request and tool guardrails

- Global request-body limit and per-field limits for XML, XPath, command, and
  template-like input.
- Output `max_bytes`/`max_lines` limits, truncation metadata, and hard response
  ceilings before serialization.
- Per-IP and per-token request rate limits for HTTP; per-device API concurrency
  limits protect the firewall management plane.
- Tool allowlists and device allowlists at the bearer layer.
- A separate command/action policy denies destructive operational commands and
  dangerous configuration roots by default. Most-specific allow/deny wins.
- XML parser configured with entity expansion and DTDs disabled, depth/size
  limits, and tests for entity-expansion and malformed-input denial of service.
- XPath input is treated as an authorization boundary: validate grammar, cap
  length/depth, and restrict write roots before sending it to a device.
- Candidate-changing calls carry token name, device, action, XPath fingerprint,
  result, job ID, and duration in structured audit logs. Payloads and keys do
  not enter logs.
- Cancellation and disconnect behavior is tested explicitly. A client
  disconnect is not assumed to cancel an in-flight commit.

### Configuration safety

- Read-only tools ship first and receive a separate read-only token example.
- Write tokens must opt into each of stage, validate, commit, and discard.
- Acquire/reconcile PAN-OS configuration locks where supported and report lock
  owner/conflicts clearly.
- Fetch and fingerprint candidate state before mutation; return enough state to
  detect intervening changes before commit.
- Validate before commit by default. Commit is a distinct call and requires an
  expected candidate fingerprint or operation ID from staging.
- Poll commit jobs to a terminal state and report warnings separately from
  errors. A transport timeout never becomes a false success.
- Document the shared-candidate risk: changes made by another administrator can
  be included unless partial-commit semantics and ownership are verified.

## 6. Performance targets

Performance means low overhead without overwhelming the PAN-OS management
plane.

- Reuse HTTPS connections and TLS sessions; do not create a client per tool
  call.
- Run different devices concurrently while bounding work per device.
- Avoid blocking code on Tokio workers; XML parsing above a measured threshold
  moves to `spawn_blocking`.
- Stream and cap large responses instead of building multiple unbounded copies.
- Cache immutable device metadata briefly, with explicit TTL and invalidation.
- Record request, queue, device, parsing, and total durations with tracing.
- Benchmark against the existing Python `pan-mcp` on the same firewall and
  network path.

Provisional v0.1 acceptance targets:

- MCP overhead under 10 ms p95 for mock-device read tools;
- warm sequential calls materially faster than the Python demo;
- parallel calls across devices scale until the configured global limit;
- no more than five API calls in flight per firewall, with four as the default;
- bounded memory under maximum accepted input/output and malformed XML tests.

The five-call ceiling is conservative because Palo Alto Networks recommends a
limit of five concurrent REST API calls to protect the shared management-plane
web server. The XML path will be load-tested, but it should not default to a
more aggressive posture without device evidence.

## 7. Delivery phases

### Phase 0 — skeleton and quality gates (implemented)

- Create the Cargo workspace and three crates.
- Pin a supported Rust MSRV and enable formatting, Clippy, unit tests,
  `cargo audit`, license checks, and dependency review.
- Add error taxonomy, tracing conventions, secret-redaction tests, fuzz targets,
  and mock PAN-OS HTTP fixtures.
- Write `THREAT_MODEL.md` before enabling a listening remote transport.

Exit: clean CI with a no-op MCP server and mock client test.

### Phase 1 — secure PAN-OS read client

- Inventory/schema validation and secret providers.
- Strict TLS, custom CA/pin support, `X-PAN-KEY`, POST-only request builder.
- Typed XML response parser and error-code mapping.
- Connection reuse, timeouts, per-device semaphore, cancellation.
- Implement `list_devices`, facts, op, and config read tools.

Exit: read-only end-to-end tests against a mock server and one explicitly
configured lab firewall.

### Phase 2 — bearer-protected remote MCP

- Port and generalize the proven token store, scope checks, CLI token commands,
  and atomic hot reload.
- Add Streamable HTTP, TLS, refusal matrix, Host/Origin validation, body limits,
  rate limits, and audit-safe HTTP tracing.
- Test missing, malformed, invalid, revoked, rotated, and out-of-scope tokens.

Exit: remote read-only deployment passes transport and auth integration tests.

### Phase 3 — guarded configuration lifecycle

- Candidate fingerprinting and per-device mutation lock.
- Stage, validate, diff, commit, discard, job polling, and cancellation audit.
- Confirm exact PAN-OS configuration-lock and partial-commit behavior on the lab
  version before claiming isolation from other administrators.
- Add destructive-operation policy and two-step commit workflow tests.

Exit: successful and failed changes are deterministic, scoped, fully audited,
and recoverable in a disposable lab.

### Phase 4 — packaging, hardening, and benchmarks

- Distroless container and hardened systemd service.
- Run as an unprivileged user with a read-only filesystem and narrowly writable
  state paths.
- Integration matrix for selected PAN-OS releases.
- Fuzz XML/XPath/token parsing, run dependency audit, and publish benchmarks.
- Write operator runbook, security policy, token rotation, backup/recovery, and
  upgrade instructions.

Exit: v0.1 release candidate with reproducible build and measured comparison
to Python `pan-mcp`.

## 8. Test strategy

- Unit: inventory validation, secret redaction, scopes, policies, XPath rules,
  response parsing, output caps, error codes, and job state machine.
- Property/fuzz: XML responses, hostile XML inputs, XPath validation, bearer
  parsing, token-store JSON, and truncation logic.
- Integration: mock HTTPS firewall with a private CA, delayed/truncated/broken
  responses, auth failure, rate limiting, reconnect, and job polling.
- MCP: stdio and Streamable HTTP initialize/list/call, TLS, Host/Origin checks,
  auth refusal matrix, hot rotation/revocation, cancellation, and disconnects.
- Real device: read-only tests by default; write tests require an explicit
  environment gate and a disposable candidate/lab firewall.
- Performance: cold/warm sequential, bounded parallel, multi-device fan-out,
  large response, slow job, and memory profile.

## 9. Decisions to confirm during implementation

These do not block the initial skeleton:

1. First real-device PAN-OS versions and whether Panorama must enter v0.1.
2. Whether API keys come primarily from environment variables, systemd
   credentials, or a secrets manager plugin.
3. Whether v0.1 needs set-format parity. The recommended answer is XML-only;
   SSH/set mode can follow after its host-key, credential, prompt, and session
   safety model is designed.
4. Whether to extract a shared vendor-neutral bearer-auth crate from
   `rust-junosmcp` or keep an independent copy with synchronized tests.
5. Packaging defaults: listen port, service account, state paths, and registry.

## 10. Primary references

- MCP Streamable HTTP transport and its Origin/auth/local-bind requirements:
  https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- PAN-OS API authentication and security (`X-PAN-KEY`, HTTPS, POST for
  sensitive calls, key rotation):
  https://docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security
- PAN-OS XML API request types and configuration actions:
  https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions
- PAN-OS commit API:
  https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/commit
- PAN-OS REST API concurrency guidance (used here as a conservative shared
  management-plane ceiling):
  https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/pan-os-rest-api

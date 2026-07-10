# Threat model

Status: Phase 0 baseline, 2026-07-09

This document defines the security boundaries and invariants for
`rust-panosmcp`. It is a design constraint, not a claim that the Phase 0
scaffold is ready for remote or device access.

## Scope

The server will accept MCP requests over local stdio or bearer-protected
Streamable HTTP and translate authorized tool calls into PAN-OS management API
requests. The protected systems are standalone firewalls in v0.1. Panorama,
multi-vsys, SSH automation, file transfer, upgrades, and OAuth authorization
servers are outside the first release scope.

## Assets

- MCP bearer credentials and their authorization scopes.
- PAN-OS API keys and private trust material.
- Firewall running and candidate configuration.
- Operational data, logs, topology, versions, and device identity.
- Availability of the MCP service and firewall management plane.
- Audit records that attribute security-relevant actions to a token and device.
- Integrity of the binary, dependency graph, configuration, and update path.

## Trust boundaries

```text
MCP client
   │  untrusted request fields; bearer credential on HTTP
   ▼
MCP transport boundary
   │  authentication, Host/Origin checks, size/rate limits
   ▼
rust-panosmcp process
   │  device/tool policy, XML/XPath validation, concurrency limits
   ▼
PAN-OS management network
   │  verified HTTPS, X-PAN-KEY, bounded async jobs
   ▼
Firewall management plane and shared candidate configuration

Local operator ── inventory/token/CA files ──► rust-panosmcp process
Supply chain  ── source/crates/CI/artifacts ─► deployed binary
```

Inputs remain untrusted after crossing a boundary. Successful MCP bearer
authentication does not make commands, XML, XPath, device names, or response
data safe.

## Security principals

- Local operator: installs the binary and controls configuration and secret
  files. This principal is trusted to administer devices but can still make
  dangerous mistakes.
- MCP token holder: may call only explicitly scoped tools against explicitly
  scoped devices. Different tokens are separate principals.
- PAN-OS API administrator: permissions are ultimately constrained by the
  role attached to the device API key.
- Other firewall administrators: trusted by PAN-OS but concurrent and not
  necessarily coordinated with this server. Their candidate changes are an
  important race and attribution risk.
- Remote attacker: can reach the MCP socket or influence an MCP client, but has
  no valid token.
- Malicious or compromised MCP client: possesses a valid limited token and
  attempts scope escalation, resource exhaustion, or policy bypass.
- Compromised or impersonated firewall: returns hostile XML, delays forever,
  or attempts to expose secrets through crafted response text.

## Non-negotiable invariants

1. Remote MCP requests are authenticated before tool execution.
2. Authentication and authorization failures never reveal whether another
   token, device, or secret exists beyond what the caller is permitted to know.
3. Tokens authorize both the exact tool and every target device before network
   I/O begins.
4. Caller input cannot select an arbitrary URL. Device endpoints come only
   from validated operator inventory.
5. PAN-OS credentials do not appear in URLs, logs, errors, MCP results, panic
   output, or `Debug` formatting.
6. Device HTTPS certificate verification is on by default. Insecure modes are
   explicit, lab-only, and impossible to enable through an MCP request.
7. Every untrusted byte stream has a size, time, depth, count, and concurrency
   bound appropriate to its type.
8. Candidate-changing operations are serialized per device and never retried
   blindly.
9. A disconnect or timeout does not turn an unknown commit outcome into
   success, failure, or cancellation. The job is reconciled or reported as
   indeterminate.
10. Audit records identify the principal, device, operation, outcome, and
    timing without recording secrets or full configuration payloads.

## Threats and required controls

| Threat | Consequence | Required controls | Phase |
|---|---|---|---|
| Stolen or guessed MCP token | Unauthorized firewall access | 256-bit random secrets, digest-only store, constant-time verification, rotation/revocation, TLS, rate limits | 2 |
| Bearer value leaked through diagnostics | Durable credential compromise | Redacted secret type, generic parser errors, header filtering, negative tests | 0/2 |
| Token scope bypass | Cross-device or destructive access | Central device/tool authorization, deny-by-default scope tests, tool-registry drift tripwire | 2 |
| DNS rebinding or browser-origin attack | Website reaches a local MCP server | Loopback default, strict `Origin` and `Host` allowlists, HTTP 403 on mismatch | 2 |
| Plaintext remote transport | Credential and payload interception | Native TLS or explicit trusted-proxy override; refuse unsafe binds | 2 |
| SSRF through device argument | Access to arbitrary internal services | Resolve stable inventory names only; validate endpoint scheme and address policy | 1 |
| PAN-OS key in URL or proxy logs | Device credential compromise | POST requests and `X-PAN-KEY`; sanitize request/error tracing | 1 |
| Firewall impersonation | Credential theft and false results | rustls verification, custom CA or pin support, no insecure default | 1 |
| XML entity expansion, deep nesting, or malformed XML | Memory/CPU denial of service or local data exposure | Response byte/depth caps, reject DTD, no external entities, fuzz parser | 0/1 |
| Oversized MCP arguments or responses | Process memory exhaustion | HTTP body caps, per-field limits, streaming response cap, output truncation metadata | 1/2 |
| API call flood | Firewall UI/API outage | Per-token/IP rate limits, global and per-device semaphores, conservative defaults | 1/2 |
| Destructive op-command injection | Reboot, reset, or service disruption | XML command policy, deny rules, typed tools for dangerous operations | 1/3 |
| XPath escapes authorized config root | Unauthorized configuration changes | Parse/normalize XPath, enforce allowed roots and action pairs, cap complexity | 3 |
| Candidate race with another administrator | Commit includes unrelated changes | Candidate fingerprint, configuration lock, expected operation ID, partial-commit validation | 3 |
| Mutation replay after network failure | Duplicate or unintended change | Idempotency analysis, job reconciliation, never auto-retry unknown mutations | 3 |
| Client disconnect during commit | Lost accountability or false cancellation | Detached/reconciled job state, explicit cancellation semantics, drop audit guard | 3 |
| Log injection or payload disclosure | Misleading audit trail or config leakage | Structured fields, newline-safe encoding, hashes/fingerprints instead of payloads | 2/3 |
| Weak local file permissions | Local secret theft or unauthorized policy change | Owner/mode checks, atomic replace, dedicated service user, read-only filesystem | 1/2/4 |
| Dependency or build compromise | Malicious binary | Locked dependencies, audit/deny checks, Dependabot, minimal features, reproducible release work | 0/4 |
| Insecure flag enabled accidentally | Silent security downgrade | Refusal matrix, mutually exclusive flags, startup warning, config tests | 2 |

## Phase 0 controls implemented

- Workspace forbids unsafe Rust in project crates and treats warnings as CI
  failures.
- `SecretString` redacts `Debug`/`Display`, avoids serialization and cloning,
  and zeroizes owned bytes on drop.
- Bearer-header parsing is bounded, allocation-free, and has errors that do not
  retain the supplied credential.
- PAN-OS XML structural validation caps bytes and depth and rejects DTDs.
- Bearer and XML parsers have cargo-fuzz targets.
- The dependency graph is locked and CI checks advisories, licenses, bans, and
  sources.
- The Phase 0 server has no tools, no listening HTTP socket, no inventory, and
  no device network access.

## Residual Phase 0 risk

The current code is a scaffold. It does not yet implement bearer token
verification, authorization scopes, Streamable HTTP, TLS, PAN-OS connections,
inventory validation, rate limiting, or audit persistence. Do not deploy this
revision as a remote service or describe it as a functional firewall manager.

The bounded XML helper currently performs structural envelope validation only.
Phase 1 must add semantic status/error parsing and response-content limits
before device data is exposed through MCP.

## Verification obligations

Each future security control needs at least one refusal-path test, not only a
happy-path test. Before a remote release, the suite must cover:

- missing, malformed, invalid, rotated, revoked, and out-of-scope tokens;
- Host and Origin allowlist failures;
- loopback/non-loopback/TLS CLI refusal combinations;
- invalid certificates and private-CA success;
- hostile XML, oversized response bodies, slow responses, and cancellation;
- per-device concurrency saturation and queue deadlines;
- stage/validate/commit races and indeterminate job outcomes;
- log capture proving bearer values and PAN-OS keys never appear.

Security findings should be reported privately to the repository owner until
a public security policy and coordinated disclosure address are established.

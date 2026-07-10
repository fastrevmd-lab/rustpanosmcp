# Phase 1 operations

Phase 1 is a local-stdio, read-only PAN-OS XML API server. Remote MCP and its
bearer-token boundary arrive in Phase 2; do not expose the stdio process through
an unauthenticated network wrapper.

## Inventory

Copy `config/devices.example.json` to a path excluded from version control and
set the referenced API-key environment variable. A key can instead come from
an absolute file path:

```json
"api_key": { "type": "file", "path": "/etc/rust-panosmcp/lab-fw.api-key" }
```

API-key files must be regular, non-symlink files owned by the service user or
root and inaccessible to group/other users. Inventory and CA files must not be
group- or world-writable. Reads use `O_NOFOLLOW` on Unix and remain attached to
the validated file descriptor to prevent a path-swap race.

Endpoints must be HTTPS origins with no credentials, path, query, or fragment.
MCP calls select an exact inventory name; they cannot supply an address or URL.

TLS trust modes are:

- `system`: platform roots plus normal hostname validation;
- `custom_ca`: only certificates from an absolute PEM bundle, with hostname
  validation;
- `leaf_sha256`: the exact SHA-256 digest of the DER leaf certificate. This
  deliberately pins one certificate identity and must be rotated when that
  certificate changes.

There is no certificate-verification disable switch.

## Run

```bash
export PANOS_LAB_API_KEY='replace-at-runtime'
cargo run --locked --release -- --device-mapping /etc/rust-panosmcp/devices.json
```

The process speaks MCP over stdin/stdout and writes tracing output to stderr.
PAN-OS calls use reusable direct HTTPS connections, HTTP POST forms, and a
sensitive `X-PAN-KEY` header. Environment proxy settings and redirects are
disabled so the device key cannot be forwarded to an intermediary.

Available tools:

- `list_devices`
- `gather_device_facts`
- `execute_panos_op` (one XML command rooted at `<show>`)
- `get_panos_config` (running or candidate, XPath rooted at `/config`)

Operational and configuration output has caller-selectable byte and line caps,
plus a five-MiB device-response ceiling. The default per-device concurrency is
four and the accepted maximum is five.

## Explicit lab acceptance

The ignored integration test performs only reads and exercises all four Phase
1 operations against one named firewall:

```bash
PANOS_LAB_INVENTORY=/etc/rust-panosmcp/devices.json \
PANOS_LAB_DEVICE=lab-fw-01 \
cargo test --locked -p rust-panosmcp-core --test lab_firewall \
  -- --ignored --nocapture
```

The inventory referenced by `PANOS_LAB_INVENTORY` controls the API-key secret
source and TLS trust. Use a PAN-OS administrative role limited to the required
read operations.

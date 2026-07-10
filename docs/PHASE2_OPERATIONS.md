# Phase 2 operations

Phase 2 supports local stdio and bearer-protected MCP Streamable HTTP. It is
read-only: no MCP tool stages, validates, commits, or discards PAN-OS candidate
configuration.

## Token store

Token files use schema version 1 and contain only versioned digests, audit
names, scopes, and creation timestamps. Start with no file or copy
`config/tokens.example.json` to an absolute path and set mode 0600. The file
must remain owned by root or the service account and inaccessible to group and
other users.

Mint a token whose exact scopes match one inventory device:

```bash
rust-panosmcp \
  --device-mapping /etc/rust-panosmcp/devices.json \
  token add \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --name automation-reader \
  --devices lab-fw-01 \
  --tools list_devices,gather_device_facts,get_panos_config
```

The plaintext secret is written once to stdout. Capture it directly into a
secret manager; it cannot be recovered from the store. Wildcard `*` is
supported for either scope but cannot be mixed with exact names. Exact scopes
are preferred.

List non-secret metadata, rotate, or revoke:

```bash
rust-panosmcp -f /etc/rust-panosmcp/devices.json token list \
  --tokens-file /etc/rust-panosmcp/tokens.json

rust-panosmcp -f /etc/rust-panosmcp/devices.json token rotate \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --name automation-reader --server-pid "$(cat /run/rust-panosmcp.pid)"

rust-panosmcp -f /etc/rust-panosmcp/devices.json token revoke \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --name automation-reader --server-pid "$(cat /run/rust-panosmcp.pid)"
```

Rotate prints the replacement secret once. `--server-pid` sends SIGHUP only
after a successful atomic store update. Alternatively send SIGHUP separately.
Reload constructs and validates the complete inventory, PAN-OS clients, and
token store before one atomic swap. Errors leave the previous runtime active.

## Native TLS listener

```bash
rust-panosmcp \
  --device-mapping /etc/rust-panosmcp/devices.json \
  --transport streamable-http \
  --host 0.0.0.0 --port 30031 \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --tls-cert /etc/rust-panosmcp/server.crt \
  --tls-key /etc/rust-panosmcp/server.key \
  --allowed-host mcp.example.test \
  --allowed-origin https://client.example.test
```

The MCP endpoint is `https://mcp.example.test:30031/mcp`. Send the token as
`Authorization: Bearer <secret>`. The private key must be an absolute,
non-symlink regular file owned by root or the service account with mode 0600.
TLS 1.2 and 1.3 are enabled; older protocol versions are not.

`--allowed-host` is the exact authority clients send and protects against DNS
rebinding. `--allowed-origin` is an exact browser origin including scheme and,
when non-default, port. Repeat either flag for multiple values. Non-browser
MCP clients normally omit Origin and are still constrained by Host and bearer
authentication.

The default request-body limit is 1 MiB. The defaults allow 120 requests per
source IP and 240 per token in each fixed one-minute window. Change these with
`--request-body-limit`, `--ip-rate-per-minute`, and
`--token-rate-per-minute`; invalid or excessive values are refused at startup.

## Trusted TLS proxy

For a reverse proxy that terminates TLS on the same trusted host/network,
retain bearer authentication and acknowledge plaintext binding explicitly:

```bash
rust-panosmcp \
  -f /etc/rust-panosmcp/devices.json \
  -t streamable-http -H 127.0.0.1 -p 30031 \
  --tokens-file /etc/rust-panosmcp/tokens.json
```

Loopback needs no downgrade flag. A non-loopback proxy hop additionally needs
`--allow-insecure-bind`, explicit `--allowed-host`, and explicit
`--allowed-origin`. That flag does not disable bearer authentication or PAN-OS
HTTPS verification. Protect the proxy hop against untrusted network access.

`--allow-no-auth` is development-only and is refused for every non-loopback
address. It cannot be combined with `--tokens-file`.

## Audit and refusal behavior

HTTP request events include method, path, source IP, token audit name, status,
and duration. They intentionally exclude Authorization, query strings, request
bodies, API keys, and device response payloads. Route logs to an access-
controlled durable sink appropriate to the deployment.

The server fails startup for missing remote authentication, incomplete TLS
pairs, relative token/TLS paths, DNS hostnames in the bind field, unsafe
off-loopback plaintext, missing off-loopback Host/Origin policy, zero or
excessive rates, and out-of-range body limits. Authentication failures are
generic HTTP 401 responses; authenticated scope failures are HTTP 403; rate
limits are HTTP 429 with Retry-After.

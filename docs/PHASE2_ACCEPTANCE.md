# Phase 2 acceptance

Date: 2026-07-09

Phase 2 exits with a bearer-protected read-only remote MCP boundary. The
accepted implementation includes digest-only token lifecycle commands, exact
device/tool scopes, atomic SIGHUP reload, Streamable HTTP with native TLS,
Host/Origin validation, request-body caps, per-IP/per-token limits, and
audit-safe structured request events.

## Reproducible gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
cargo audit --deny warnings
cargo deny check licenses bans sources
```

The Phase 2 HTTP integration suite proves:

- missing, malformed, invalid, rotated, and revoked credentials return 401;
- exact tool and device scope failures return HTTP 403 before tool dispatch;
- a failed inventory/token reload retains the last complete runtime;
- valid MCP initialization succeeds through the protected router;
- disallowed Host and Origin values return 403;
- oversized bodies return 413;
- IP/token limits return 429 with Retry-After;
- an authenticated MCP initialization completes through a real native-TLS TCP
  listener with a private test CA, while an exposed private key is refused.

## Token lookup measurement

The maximum supported store is 1,024 tokens. The release-mode manual benchmark
hashes a candidate once and scans every digest using constant-time comparison:

```bash
cargo test -p rust-panosmcp-auth --release \
  --test token_lookup_benchmark -- --ignored --nocapture
```

On the Phase 2 development host, 10,000 full-store misses took 824.5 ms, or
82.45 microseconds per authentication. This is an environment-specific
measurement, not an SLA; the committed benchmark makes regression checks
repeatable.

The real-firewall Phase 1 lab read suite remains the device acceptance gate.
Phase 2 adds no PAN-OS write calls. Phase 3 remains blocked from claiming safe
mutation until lock, fingerprint, two-step commit, reconciliation, and
cancellation requirements pass against the disposable lab.

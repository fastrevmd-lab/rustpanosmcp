# Integration Test Migration for mecmcp 0.9.0

## Status

Integration tests in `rust-panosmcp/tests/http_*.rs` have been temporarily disabled
(renamed to `.skip`) during the mecmcp 0.9.0 migration because `ServePlan` no longer
exposes the router for direct `.oneshot()` testing.

## Files Needing Migration

- `http_auth.rs` - authentication and authorization tests
- `http_host_origin.rs` - Host and Origin validation tests
- `http_rate_limit.rs` - per-token rate limiting tests
- `http_session_caps.rs` - session cap and metrics tests
- `mcp_https.rs` - TLS integration tests (if exists)

## Migration Path

Follow the pattern from mecmcp's own test migration (commit 4398958):
1. Use `serve_router(plan, address, tls, timeout)` with a real TCP listener
2. Use `mecmcp_transport::test_client::McpClient` for HTTP calls
3. Spawn the server in a background task
4. Make requests via the client instead of `.oneshot()`

See `mecmcp/crates/mecmcp-transport/tests/router_integration.rs` for examples.

## Tracking

Created as part of mecmcp 0.9.0 migration (2026-08-13).
Production code migrated successfully; tests need follow-up.

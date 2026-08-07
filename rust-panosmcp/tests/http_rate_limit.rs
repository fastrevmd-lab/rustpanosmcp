//! Per-token rate limiting integration tests.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use rust_panosmcp::{
    RuntimeState,
    http_transport::{HttpOptions, build_router},
};
use rust_panosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use std::fs;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rate-limit-test","version":"1"}}}"#;

struct Fixture {
    _directory: TempDir,
    runtime: RuntimeState,
    secret: String,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("temporary directory");
    let key_path = directory.path().join("panos-api-key");
    fs::write(&key_path, "not-a-live-key").expect("API key fixture");
    make_private(&key_path);
    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"lab-fw","endpoint":"https://fw.example.test","api_key":{{"type":"file","path":"{}"}}}}]}}"#,
            key_path.display()
        ),
    )
    .expect("inventory fixture");

    let token_path = directory.path().join("tokens.json");
    let known_devices = ["lab-fw".to_owned()];
    let known = KnownNames {
        devices: Some(&known_devices),
        tools: rust_panosmcp_auth::KNOWN_TOOLS,
    };
    let secret = TokenStoreFile::add(
        &token_path,
        "reader",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &known,
    )
    .expect("token add")
    .expose_secret()
    .to_owned();
    let runtime = RuntimeState::load(&inventory_path, Some(&token_path)).expect("runtime");
    Fixture {
        _directory: directory,
        runtime,
        secret,
    }
}

#[cfg(unix)]
fn make_private(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("setting file mode 0600");
}

#[cfg(not(unix))]
fn make_private(_path: &std::path::Path) {}

fn post(body: impl Into<Body>, authorization: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "http://localhost:30031")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, authorization)
        .body(body.into())
        .expect("request")
}

#[tokio::test]
async fn per_token_rate_limit_enforces_429() {
    let fixture = fixture();
    let options = HttpOptions {
        port: 30031,
        tls: false,
        allowed_hosts: Vec::new(),
        allowed_origins: Vec::new(),
        ip_rate_per_minute: 0,
        token_rate_per_minute: 2,
        request_body_limit: 1024 * 1024,
        max_inflight_requests: 64,
        max_inflight_requests_per_token: 16,
        max_inflight_requests_per_target: 4,
        max_sessions: 128,
        max_sessions_per_token: 16,
    };

    let (app, _shutdown) =
        build_router(fixture.runtime, options, false, CancellationToken::new()).expect("router");
    let auth = format!("Bearer {}", fixture.secret);

    // First request should succeed
    let response = app
        .clone()
        .oneshot(post(INITIALIZE, &auth))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // Second request should succeed (burst allows 2)
    let response = app
        .clone()
        .oneshot(post(INITIALIZE, &auth))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // Third request should be rate limited (429)
    let response = app
        .clone()
        .oneshot(post(INITIALIZE, &auth))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "third request must be rate limited after exhausting the per-token burst"
    );
    assert!(
        response.headers().get(header::RETRY_AFTER).is_some(),
        "429 response must include Retry-After header"
    );

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        json.get("error").and_then(|v| v.as_str()),
        Some("rate_limited"),
        "429 response must include rate_limited error"
    );
    assert_eq!(
        json.get("limit").and_then(|v| v.as_str()),
        Some("token_rate"),
        "429 response must indicate token_rate limit"
    );
}

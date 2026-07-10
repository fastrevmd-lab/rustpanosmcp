//! Phase 2 remote transport/authentication integration tests.

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use rmcp::{
    ServiceExt as _,
    model::CallToolRequestParams,
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use rust_panosmcp::{
    RuntimeState,
    http_transport::{HttpOptions, build_router, serve},
    tls,
};
use rust_panosmcp_auth::{ScopeSet, TokenStoreFile};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use tower::ServiceExt as _;

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"phase2-test","version":"1"}}}"#;

struct Fixture {
    _directory: TempDir,
    runtime: RuntimeState,
    token_path: PathBuf,
    secret: String,
}

fn fixture(devices: ScopeSet, tools: ScopeSet) -> Fixture {
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
    let secret = TokenStoreFile::add(
        &token_path,
        "reader",
        devices,
        tools,
        &["lab-fw".to_owned()],
    )
    .expect("token add")
    .expose_secret()
    .to_owned();
    let runtime = RuntimeState::load(&inventory_path, Some(&token_path)).expect("runtime");
    Fixture {
        _directory: directory,
        runtime,
        token_path,
        secret,
    }
}

fn options() -> HttpOptions {
    HttpOptions {
        port: 30031,
        tls: false,
        allowed_hosts: Vec::new(),
        allowed_origins: Vec::new(),
        ip_rate_per_minute: 1_000,
        token_rate_per_minute: 1_000,
        request_body_limit: 1024 * 1024,
    }
}

fn post(body: impl Into<Body>, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "http://localhost:30031")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder.body(body.into()).expect("request")
}

async fn status(
    runtime: &RuntimeState,
    options: HttpOptions,
    request: Request<Body>,
) -> StatusCode {
    build_router(runtime.clone(), options)
        .oneshot(request)
        .await
        .expect("infallible router")
        .status()
}

#[tokio::test]
async fn missing_malformed_and_invalid_tokens_are_rfc6750_unauthorized() {
    let fixture = fixture(ScopeSet::Wildcard, ScopeSet::Wildcard);
    for authorization in [
        None,
        Some("Basic abc"),
        Some("Bearer"),
        Some("Bearer wrong"),
    ] {
        assert_eq!(
            status(&fixture.runtime, options(), post(INITIALIZE, authorization)).await,
            StatusCode::UNAUTHORIZED
        );
    }

    let response = build_router(fixture.runtime.clone(), options())
        .oneshot(post(INITIALIZE, None))
        .await
        .expect("router");
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn valid_token_initializes_but_wrong_tool_or_device_is_http_forbidden() {
    let fixture = fixture(
        ScopeSet::Allowlist(vec!["lab-fw".to_owned()]),
        ScopeSet::Allowlist(vec!["get_panos_config".to_owned()]),
    );
    let bearer = format!("Bearer {}", fixture.secret);
    assert_eq!(
        status(&fixture.runtime, options(), post(INITIALIZE, Some(&bearer))).await,
        StatusCode::OK
    );

    let wrong_tool = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_panos_op","arguments":{"device":"lab-fw","command":"<show><system><info/></system></show>"}}}"#;
    assert_eq!(
        status(&fixture.runtime, options(), post(wrong_tool, Some(&bearer))).await,
        StatusCode::FORBIDDEN
    );
    let wrong_device = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_panos_config","arguments":{"device":"other-fw","xpath":"/config"}}}"#;
    assert_eq!(
        status(
            &fixture.runtime,
            options(),
            post(wrong_device, Some(&bearer))
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn rotation_revocation_and_failed_reload_are_atomic() {
    let fixture = fixture(ScopeSet::Wildcard, ScopeSet::Wildcard);
    let old_bearer = format!("Bearer {}", fixture.secret);
    let rotated = TokenStoreFile::rotate(&fixture.token_path, "reader", &["lab-fw".to_owned()])
        .expect("rotate")
        .expose_secret()
        .to_owned();
    fixture.runtime.reload().expect("reload rotation");
    assert_eq!(
        status(
            &fixture.runtime,
            options(),
            post(INITIALIZE, Some(&old_bearer))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    let new_bearer = format!("Bearer {rotated}");
    assert_eq!(
        status(
            &fixture.runtime,
            options(),
            post(INITIALIZE, Some(&new_bearer))
        )
        .await,
        StatusCode::OK
    );

    fs::write(&fixture.token_path, b"not-json").expect("corrupt replacement");
    assert!(fixture.runtime.reload().is_err());
    assert_eq!(
        status(
            &fixture.runtime,
            options(),
            post(INITIALIZE, Some(&new_bearer))
        )
        .await,
        StatusCode::OK,
        "failed reload must retain the last complete snapshot"
    );
}

#[tokio::test]
async fn revoked_token_is_rejected_after_reload() {
    let fixture = fixture(ScopeSet::Wildcard, ScopeSet::Wildcard);
    let bearer = format!("Bearer {}", fixture.secret);
    assert!(
        TokenStoreFile::revoke(&fixture.token_path, "reader", &["lab-fw".to_owned()])
            .expect("revoke")
    );
    fixture.runtime.reload().expect("reload revocation");
    assert_eq!(
        status(&fixture.runtime, options(), post(INITIALIZE, Some(&bearer))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn host_origin_body_and_rate_guards_reject_requests() {
    let fixture = fixture(ScopeSet::Wildcard, ScopeSet::Wildcard);
    let bearer = format!("Bearer {}", fixture.secret);

    let mut bad_host = post(INITIALIZE, Some(&bearer));
    bad_host
        .headers_mut()
        .insert(header::HOST, "evil.example".parse().expect("header"));
    assert_eq!(
        status(&fixture.runtime, options(), bad_host).await,
        StatusCode::FORBIDDEN
    );

    let mut bad_origin = post(INITIALIZE, Some(&bearer));
    bad_origin.headers_mut().insert(
        header::ORIGIN,
        "https://evil.example".parse().expect("header"),
    );
    assert_eq!(
        status(&fixture.runtime, options(), bad_origin).await,
        StatusCode::FORBIDDEN
    );

    let mut small = options();
    small.request_body_limit = 1024;
    assert_eq!(
        status(
            &fixture.runtime,
            small,
            post(vec![b'x'; 1025], Some(&bearer))
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let mut rate_limited = options();
    rate_limited.ip_rate_per_minute = 1;
    let router = build_router(fixture.runtime.clone(), rate_limited);
    assert_eq!(
        router
            .clone()
            .oneshot(post(INITIALIZE, Some(&bearer)))
            .await
            .expect("router")
            .status(),
        StatusCode::OK
    );
    let response = router
        .oneshot(post(INITIALIZE, Some(&bearer)))
        .await
        .expect("router");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(header::RETRY_AFTER));
}

fn make_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private mode");
    }
}

#[tokio::test]
async fn native_tls_listener_completes_authenticated_mcp_initialize() {
    let fixture = fixture(ScopeSet::Wildcard, ScopeSet::Wildcard);
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("self-signed certificate");
    let cert_path = fixture._directory.path().join("listener.pem");
    let key_path = fixture._directory.path().join("listener.key");
    let cert_pem = issued.cert.pem();
    fs::write(&cert_path, &cert_pem).expect("certificate");
    fs::write(&key_path, issued.signing_key.serialize_pem()).expect("private key");
    make_private(&key_path);
    let tls = tls::load(&cert_path, &key_path).expect("listener TLS");

    let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("ephemeral port");
    let address = probe.local_addr().expect("local address");
    drop(probe);
    let mut listener_options = options();
    listener_options.port = address.port();
    listener_options.tls = true;
    let runtime = fixture.runtime.clone();
    let server =
        tokio::spawn(async move { serve(runtime, address, listener_options, Some(tls)).await });

    let root = reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("root certificate");
    let client = reqwest::Client::builder()
        .add_root_certificate(root)
        .no_proxy()
        .build()
        .expect("HTTPS client");
    let endpoint = format!("https://localhost:{}/mcp", address.port());
    let bearer = format!("Bearer {}", fixture.secret);
    let mut response = None;
    for _ in 0..50 {
        match client
            .post(&endpoint)
            .header(header::AUTHORIZATION, &bearer)
            .header(
                header::ORIGIN,
                format!("https://localhost:{}", address.port()),
            )
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .body(INITIALIZE)
            .send()
            .await
        {
            Ok(result) => {
                response = Some(result);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
    let response = response.expect("TLS listener became reachable");
    assert_eq!(response.status(), StatusCode::OK);
    server.abort();
}

#[tokio::test]
async fn rmcp_client_observes_handler_level_device_scope_over_http() {
    let fixture = fixture(
        ScopeSet::Allowlist(Vec::new()),
        ScopeSet::Allowlist(vec!["list_devices".to_owned()]),
    );
    let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("ephemeral port");
    let address = probe.local_addr().expect("local address");
    drop(probe);
    let mut listener_options = options();
    listener_options.port = address.port();
    let runtime = fixture.runtime.clone();
    let server = tokio::spawn(async move { serve(runtime, address, listener_options, None).await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(format!("http://{address}/mcp"))
            .auth_header(fixture.secret.clone()),
    );
    let client = ().serve(transport).await.expect("remote MCP initialize");
    let result = client
        .call_tool(CallToolRequestParams::new("list_devices"))
        .await
        .expect("list devices");
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .expect("text result");
    let value: serde_json::Value = serde_json::from_str(&text.text).expect("JSON result");
    assert_eq!(value["devices"], serde_json::json!([]));
    client.cancel().await.expect("client shutdown");
    server.abort();
}

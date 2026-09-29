//! `/readyz` must flip to failing once PAN-OS rejects the configured API key.

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rust_panosmcp::{
    RuntimeState,
    http_transport::{HttpOptions, build_router},
};
use rust_panosmcp_core::{inventory::Environment, tools::GatherDeviceFactsInput};
use std::{fs, net::SocketAddr, path::PathBuf};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const API_KEY: &str = "readyz-test-api-key";

/// A single-purpose mock PAN-OS endpoint that always answers with an HTTP
/// 403 "Invalid Credential" rejection, regardless of what was requested --
/// the shape PAN-OS actually uses for a revoked, invalid, or expired API
/// key (an HTTP 200 wrapping an XML error code is not what a bad key
/// produces).
struct UnauthorizedMock {
    endpoint: String,
    cert_path: PathBuf,
    handle: axum_server::Handle<SocketAddr>,
    _directory: TempDir,
}

impl UnauthorizedMock {
    async fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().expect("temporary mock directory");
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mock certificate");
        let cert_path = directory.path().join("ca.pem");
        fs::write(&cert_path, cert.pem()).expect("write mock CA");
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            cert.pem().into_bytes(),
            signing_key.serialize_pem().into_bytes(),
        )
        .await
        .expect("mock TLS config");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind mock HTTPS");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("mock address");
        let app = axum::Router::new().route(
            "/api/",
            axum::routing::post(|| async {
                (
                    axum::http::StatusCode::FORBIDDEN,
                    r#"<response status="error" code="403"><msg><line>Invalid Credential</line></msg></response>"#,
                )
            }),
        );
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .expect("create mock HTTPS server")
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
                .expect("mock HTTPS server");
        });
        tokio::task::yield_now().await;
        Self {
            endpoint: format!("https://localhost:{}", address.port()),
            cert_path,
            handle,
            _directory: directory,
        }
    }
}

impl Drop for UnauthorizedMock {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "READYZ_TEST_KEY").then(|| API_KEY.to_owned())
    }
}

#[tokio::test]
async fn readyz_flips_to_failing_after_a_panos_auth_error() {
    let mock = UnauthorizedMock::start().await;
    let directory = tempfile::tempdir().expect("temporary directory");
    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"lab-fw","endpoint":"{}","api_key":{{"type":"env","name":"READYZ_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}}}}]}}"#,
            mock.endpoint,
            mock.cert_path.display()
        ),
    )
    .expect("inventory fixture");

    let inventory = rust_panosmcp_core::inventory::Inventory::load_with_environment(
        &inventory_path,
        &TestEnvironment,
    )
    .expect("load inventory");
    let service = rust_panosmcp_core::tools::PanosService::new(inventory).expect("PAN-OS service");
    let runtime = RuntimeState::from_parts(service, None);

    let options = HttpOptions {
        port: 30032,
        tls: false,
        allow_insecure_bind: false,
        allowed_hosts: Vec::new(),
        allowed_origins: Vec::new(),
        ip_rate_per_minute: 1_000,
        token_rate_per_minute: 1_000,
        request_body_limit: 1024 * 1024,
        max_inflight_requests: 64,
        max_inflight_requests_per_token: 16,
        max_inflight_requests_per_target: 4,
        max_sessions: 128,
        max_sessions_per_token: 16,
    };

    let shutdown = CancellationToken::new();
    let plan = build_router(runtime.clone(), options, false, shutdown.clone()).expect("router");
    let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;

    let client = reqwest::Client::new();
    let readyz = |served_address: SocketAddr| {
        let client = client.clone();
        async move {
            client
                .get(format!("http://{served_address}/readyz"))
                .send()
                .await
                .expect("readyz request")
        }
    };

    // No request has reached PAN-OS yet: readiness reflects proven failure,
    // not silence, so it must still report ready.
    let before = readyz(served.address).await;
    assert_eq!(before.status(), reqwest::StatusCode::OK);

    // Trigger one real request against the mock, which always answers an
    // HTTP 403 invalid-credential rejection -- this is what an expired or
    // revoked API key looks like for real.
    let service = runtime.snapshot().service.clone();
    let error = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: "lab-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect_err("mock always answers invalid credential");
    assert!(
        matches!(
            error,
            rust_panosmcp_core::PanosMcpError::HttpStatus { status: 403, .. }
        ),
        "unexpected error: {error:?}"
    );

    // One poll interval later, /readyz must report the auth failure.
    let after = readyz(served.address).await;
    assert_eq!(after.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body = after.text().await.expect("readyz body");
    assert!(body.contains("panos_auth"));

    shutdown.cancel();
    served.serving.await.expect("server").expect("serve");
}

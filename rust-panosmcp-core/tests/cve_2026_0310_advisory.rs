//! `gather_device_facts` must surface a visible CVE-2026-0310 version-floor
//! warning, not just a value a caller has to know to compare themselves.

use axum::{Router, routing::post};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::{GatherDeviceFactsInput, PanosService},
};
use std::{fs, net::TcpListener};
use tokio_util::sync::CancellationToken;

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_CVE_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

async fn system_info(sw_version: &'static str) -> impl axum::response::IntoResponse {
    format!(
        r#"<response status="success"><result><system><hostname>test-fw</hostname><model>PA-VM</model><sw-version>{sw_version}</sw-version><serial>000000000000</serial><ip-address>192.0.2.100</ip-address><uptime>1234567</uptime></system></result></response>"#
    )
}

/// Stand up a mock device that answers every operational command with the
/// given `sw-version`, and return a service pointed at it.
async fn fixture(sw_version: &'static str) -> PanosService {
    let directory = tempfile::tempdir().expect("tempdir");
    let issued = generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let cert_path = directory.path().join("ca.pem");
    fs::write(&cert_path, issued.cert.pem()).expect("certificate file");
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        issued.cert.pem().into_bytes(),
        issued.signing_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("server TLS");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let app = Router::new().route(
        "/api/",
        post(move || async move { system_info(sw_version).await }),
    );
    let handle = axum_server::Handle::new();
    let task_handle = handle.clone();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .expect("TLS server")
            .handle(task_handle)
            .serve(app.into_make_service())
            .await
            .expect("mock server");
    });
    tokio::task::yield_now().await;

    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"test-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_CVE_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("cve advisory test inventory");
    PanosService::new(inventory).expect("service")
}

#[tokio::test]
async fn below_fix_level_produces_a_visible_advisory() {
    let service = fixture("12.1.5").await;
    let output = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("gather_device_facts");

    assert_eq!(
        output.advisories.len(),
        1,
        "advisories: {:?}",
        output.advisories
    );
    let advisory = &output.advisories[0];
    assert!(advisory.contains("12.1.5"), "advisory: {advisory}");
    assert!(advisory.contains("12.1.10"), "advisory: {advisory}");
    assert!(advisory.contains("CVE-2026-0310"), "advisory: {advisory}");
}

#[tokio::test]
async fn at_fix_level_produces_no_advisory() {
    let service = fixture("12.1.10").await;
    let output = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("gather_device_facts");

    assert!(
        output.advisories.is_empty(),
        "advisories: {:?}",
        output.advisories
    );
}

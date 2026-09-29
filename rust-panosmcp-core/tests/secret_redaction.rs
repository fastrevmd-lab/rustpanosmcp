//! MEC-528 class 1: `get_panos_config` and `execute_panos_op` must not echo
//! back PAN-OS secret material (admin password hashes, certificate private
//! keys) verbatim, even when no xpath/command blocklist is configured.

use axum::{Router, extract::Form, routing::post};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::{ExecutePanosOpInput, GetPanosConfigInput, PanosService},
};
use std::{collections::BTreeMap, fs, net::TcpListener};
use tokio_util::sync::CancellationToken;

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_REDACTION_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

fn success(body: &str) -> String {
    format!(r#"<response status="success">{body}</response>"#)
}

async fn api(Form(form): Form<BTreeMap<String, String>>) -> String {
    let request_type = form.get("type").map(String::as_str);
    let command = form.get("cmd").map(String::as_str).unwrap_or_default();

    if request_type == Some("config") {
        // Simulates reading /config/mgt-config/users: PAN-OS returns the
        // admin's phash verbatim in the config XML.
        return success(concat!(
            "<result><entry name=\"admin\">",
            "<phash>$9$abcXYZ012.def/GHI$rest.of.the.hash.value</phash>",
            "</entry></result>"
        ));
    }
    if command.contains("<show><system><info>") {
        // Simulates `show config running`: PAN-OS returns the running config,
        // which can include a certificate's private key, as inline text.
        return success(concat!(
            "<result><certificate><private-key>",
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIBOgIBAAJBAK...redacted-body...==\n",
            "-----END RSA PRIVATE KEY-----",
            "</private-key></certificate></result>"
        ));
    }

    r#"<response status="error"><msg><line>unknown request</line></msg></response>"#.to_owned()
}

async fn fixture() -> PanosService {
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
    let app = Router::new().route("/api/", post(api));
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
            r#"{{"version":1,"policy":{{"mode":"allowlist","allow":["show system info"]}},"devices":[{{"name":"test-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_REDACTION_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("redaction test inventory");
    PanosService::new(inventory).expect("service")
}

#[tokio::test]
async fn get_panos_config_redacts_admin_password_hash() {
    let service = fixture().await;
    let output = service
        .get_panos_config(
            GetPanosConfigInput {
                device: "test-fw".to_owned(),
                source: rust_panosmcp_core::tools::ConfigSource::Running,
                xpath: Some("/config/mgt-config/users".to_owned()),
                max_bytes: None,
                max_lines: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("get_panos_config");

    assert!(
        !output.output.content.contains("$9$"),
        "admin password hash leaked in tool output: {}",
        output.output.content
    );
    assert!(
        output.output.content.contains("[REDACTED]"),
        "expected redaction marker in output: {}",
        output.output.content
    );
}

#[tokio::test]
async fn execute_panos_op_redacts_private_key_material() {
    let service = fixture().await;
    let output = service
        .execute_panos_op(
            ExecutePanosOpInput {
                device: "test-fw".to_owned(),
                command: "<show><system><info></info></system></show>".to_owned(),
                max_bytes: None,
                max_lines: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("execute_panos_op");

    assert!(
        !output.output.content.contains("BEGIN RSA PRIVATE KEY"),
        "private key material leaked in tool output: {}",
        output.output.content
    );
    assert!(
        output.output.content.contains("[REDACTED]"),
        "expected redaction marker in output: {}",
        output.output.content
    );
}

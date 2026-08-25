//! Structural audit coverage test: every tool in KNOWN_TOOLS must emit an audit event.
//!
//! This test ensures that adding a new tool to KNOWN_TOOLS without also adding audit
//! coverage causes a loud, named failure listing the missing tool.

mod common;

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use mecmcp_audit::testutil::CapturingWriter;
use rcgen::generate_simple_self_signed;
use rust_panosmcp_auth::{KNOWN_TOOLS, MutationAction, MutationGrant};
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    mutation::{
        ApproveChangeSetInput, CandidateFingerprintInput, ChangeSetAction, ChangeSetStatusInput,
        CreateChangeSetInput, OperationInput, OperationStatusInput, StageAction, StageConfigInput,
    },
    tools::{
        ConfigSource, ExecutePanosOpInput, GatherDeviceFactsInput, GetPanosConfigInput,
        PanosService,
    },
};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    net::TcpListener,
    sync::{Arc, Mutex},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

// Serialize audit-capturing tests to prevent buffer contamination.
// The tracing subscriber is now process-global via thread-local routing, but these
// tests are #[tokio::test] with default current_thread runtime, so each future stays
// on the thread that installed its thread-local capture. If switched to multi_thread,
// the lock prevents a task from migrating to another thread's capture.
static AUDIT_TEST_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_AUDIT_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

#[derive(Debug)]
struct MockState {
    candidate: String,
}

async fn api(
    State(state): State<Arc<Mutex<MockState>>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> String {
    let request_type = form.get("type").map(String::as_str);
    let action = form.get("action").map(String::as_str);
    let command = form.get("cmd").map(String::as_str).unwrap_or_default();

    if request_type == Some("config") && action == Some("get") {
        let candidate = state.lock().expect("state").candidate.clone();
        return success(&format!("<result>{candidate}</result>"));
    }
    if request_type == Some("config") && action == Some("set") {
        state.lock().expect("state").candidate =
            "<config><shared><address><entry name=\"test\"><ip-netmask>192.0.2.1</ip-netmask></entry></address></shared></config>".to_owned();
        return success("<result><msg>set complete</msg></result>");
    }
    if command.contains("<show><system><info>") {
        return success(
            r#"<result><system><hostname>test-fw</hostname><model>PA-VM</model><sw-version>11.0.0</sw-version><serial>000000000000</serial><ip-address>192.0.2.100</ip-address><uptime>1234567</uptime></system></result>"#,
        );
    }
    if command.contains("<show><session><info>") {
        return success("<result><num-max>8192</num-max></result>");
    }
    if command == "<show><config><list><change-summary/></list></config></show>" {
        return success(
            "<result><journal><entry><xpath>/config/shared/address</xpath></entry></journal></result>",
        );
    }
    if command == "<validate><full></full></validate>" {
        return success("<result><job>101</job></result>");
    }
    if command.contains("<show><jobs><id>101</id>") {
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress></job></result>",
        );
    }
    if command.contains("<show><jobs><id>102</id>") {
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress></job></result>",
        );
    }
    if request_type == Some("commit") && action == Some("partial") {
        return success("<result><job>102</job></result>");
    }
    if command.contains("<revert><config><partial>") {
        return success("<result><msg>reverted</msg></result>");
    }

    r#"<response status="error"><msg><line>unknown request</line></msg></response>"#.to_owned()
}

fn success(body: &str) -> String {
    format!(r#"<response status="success">{body}</response>"#)
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
    let state = Arc::new(Mutex::new(MockState {
        candidate: "<config><shared><address/></shared></config>".to_owned(),
    }));
    let app = Router::new()
        .route("/api/", post(api))
        .with_state(state.clone());
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
            r#"{{"version":1,"devices":[{{"name":"test-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_AUDIT_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}},"mutation":{{"admin":"mcp-admin","allowed_xpath_roots":["/config/shared/address"],"allow_delete":true,"require_config_lock":false}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("audit test inventory");
    PanosService::new(inventory).expect("service")
}

/// Extract the "tool" field from each audit event in the captured log bytes.
fn extract_tool_names(captured_bytes: &[u8]) -> HashSet<String> {
    String::from_utf8_lossy(captured_bytes)
        .lines()
        .filter_map(|line| {
            if line.contains("tool=") {
                // Extract tool=<name> from the log line
                line.split("tool=")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                    .map(|s| s.to_owned())
            } else {
                None
            }
        })
        .collect()
}

#[tokio::test]
async fn all_tools_emit_audit_events() {
    let _lock = AUDIT_TEST_LOCK.lock().await;

    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

    let service = fixture().await;
    let cancel = CancellationToken::new();

    // Exercise every tool once to trigger audit events
    let _ = service.list_devices(None);

    let _ = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .execute_panos_op(
            ExecutePanosOpInput {
                device: "test-fw".to_owned(),
                command: "<show><session><info></info></session></show>".to_owned(),
                max_bytes: None,
                max_lines: None,
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .get_panos_config(
            GetPanosConfigInput {
                device: "test-fw".to_owned(),
                xpath: Some("/config/shared/address".to_owned()),
                source: ConfigSource::Running,
                max_bytes: None,
                max_lines: None,
            },
            None,
            cancel.clone(),
        )
        .await;

    let fp = service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await
        .expect("fingerprint");

    let grant = MutationGrant {
        allowed_xpath_roots: vec!["/config/shared/address".to_owned()],
        actions: vec![MutationAction::Set, MutationAction::Delete],
    };

    let change_set = service
        .create_change_set(
            CreateChangeSetInput {
                device: "test-fw".to_owned(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
                actions: vec![ChangeSetAction {
                    action: StageAction::Set,
                    xpath: "/config/shared/address".to_owned(),
                    element: Some(
                        "<entry name=\"test\"><ip-netmask>192.0.2.1</ip-netmask></entry>"
                            .to_owned(),
                    ),
                    destructive_confirmation: None,
                }],
            },
            None,
            "owner",
            Some(&grant),
            cancel.clone(),
        )
        .await
        .expect("create_change_set");

    let _ = service
        .approve_change_set(
            ApproveChangeSetInput {
                device: "test-fw".to_owned(),
                change_set_id: change_set.change_set_id.clone(),
                expected_digest: change_set.digest.clone(),
            },
            None,
            "approver",
        )
        .await;

    let _ = service
        .change_set_status(
            ChangeSetStatusInput {
                device: "test-fw".to_owned(),
                change_set_id: change_set.change_set_id.clone(),
            },
            None,
        )
        .await;

    // Apply produces an operation_id for subsequent lifecycle calls
    let apply_out = service
        .apply_change_set(
            rust_panosmcp_core::mutation::ApplyChangeSetInput {
                device: "test-fw".to_owned(),
                change_set_id: change_set.change_set_id,
                expected_digest: change_set.digest,
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            None,
            "owner",
            Some(&grant),
            cancel.clone(),
        )
        .await
        .expect("apply");

    let _ = service
        .diff_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .validate_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .operation_status(
            OperationStatusInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
            },
            "owner",
            None,
        )
        .await;

    // Call stage_config (will fail due to mock, but will emit audit event)
    let _ = service
        .stage_config(
            StageConfigInput {
                device: "test-fw".to_owned(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some("<entry name=\"test\"/>".to_owned()),
                destructive_confirmation: None,
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    // Call commit_candidate (will fail, but will emit audit event)
    let _ = service
        .commit_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    // Call discard_candidate (will fail, but will emit audit event)
    let _ = service
        .discard_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    // Extract audit events
    let bytes = cap.0.lock().expect("lock audit capture").clone();
    let audited_tools = extract_tool_names(&bytes);

    // Compare with KNOWN_TOOLS
    let expected: HashSet<String> = KNOWN_TOOLS.iter().map(|s| s.to_string()).collect();
    let missing: Vec<_> = expected.difference(&audited_tools).collect();
    let extra: Vec<_> = audited_tools.difference(&expected).collect();

    assert!(
        missing.is_empty(),
        "Tools in KNOWN_TOOLS but not audited: {:?}",
        missing
    );
    assert!(
        extra.is_empty(),
        "Audited tools not in KNOWN_TOOLS: {:?}",
        extra
    );
}

#[tokio::test]
async fn no_double_emission() {
    let _lock = AUDIT_TEST_LOCK.lock().await;

    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

    let service = fixture().await;
    let cancel = CancellationToken::new();

    // Call one already-audited tool
    let _ = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel,
        )
        .await;

    let bytes = cap.0.lock().expect("lock audit capture").clone();
    let log = String::from_utf8_lossy(&bytes);
    let count = log
        .lines()
        .filter(|line| line.contains("tool=gather_device_facts"))
        .count();

    assert_eq!(
        count, 1,
        "gather_device_facts emitted {} audit events, expected exactly 1",
        count
    );
}

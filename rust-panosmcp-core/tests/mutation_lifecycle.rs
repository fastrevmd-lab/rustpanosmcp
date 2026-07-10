//! Guarded candidate lifecycle against a deterministic mock PAN-OS XML API.

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    mutation::{
        CandidateFingerprintInput, CommitDisposition, OperationInput, OperationStatusInput,
        StageAction, StageConfigInput,
    },
    tools::PanosService,
};
use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_MUTATION_TEST_KEY").then(|| "fixture-api-key".to_owned())
    }
}

#[derive(Debug)]
struct MockState {
    running: String,
    candidate: String,
    locks_added: usize,
    locks_removed: usize,
    commit_fails: bool,
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
            "<config><shared><address><entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry></address></shared></config>".to_owned();
        return success("<result><msg>set complete</msg></result>");
    }
    if request_type == Some("config") && action == Some("delete") {
        state.lock().expect("state").candidate =
            "<config><shared><address/></shared></config>".to_owned();
        return success("<result><msg>delete complete</msg></result>");
    }
    if command.contains("<config-lock><add>") {
        state.lock().expect("state").locks_added += 1;
        return success("<result><msg>lock added</msg></result>");
    }
    if command.contains("<config-lock><remove>") {
        state.lock().expect("state").locks_removed += 1;
        return success("<result><msg>lock removed</msg></result>");
    }
    if command == "<show><config><list><change-summary/></list></config></show>" {
        return success(
            "<result><journal><entry><xpath>/config/shared/address</xpath></entry></journal></result>",
        );
    }
    if command == "<validate><full></full></validate>" {
        return success("<result><job>101</job></result>");
    }
    if request_type == Some("commit") && action == Some("partial") {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        return success("<result><job>102</job></result>");
    }
    if command.contains("<show><jobs><id>101</id>") {
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress><details>validation passed</details></job></result>",
        );
    }
    if command.contains("<show><jobs><id>102</id>") {
        let mut state = state.lock().expect("state");
        if state.commit_fails {
            return success(
                "<result><job><status>FIN</status><result>FAIL</result><progress>100</progress><details>commit refused by mock</details></job></result>",
            );
        }
        state.running = state.candidate.clone();
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress><details>commit passed</details></job></result>",
        );
    }
    if command.contains("<revert><config><partial>") {
        let mut state = state.lock().expect("state");
        state.candidate = state.running.clone();
        return success("<result><msg>reverted</msg></result>");
    }
    r#"<response status="error" code="17"><msg><line>unsupported mock request</line></msg></response>"#.to_owned()
}

fn success(inner: &str) -> String {
    format!(r#"<response status="success" code="19">{inner}</response>"#)
}

struct Fixture {
    _directory: tempfile::TempDir,
    state: Arc<Mutex<MockState>>,
    server: axum_server::Handle<std::net::SocketAddr>,
    service: PanosService,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.shutdown();
    }
}

async fn fixture(commit_fails: bool) -> Fixture {
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
        running: "<config><shared><address/></shared></config>".to_owned(),
        candidate: "<config><shared><address/></shared></config>".to_owned(),
        locks_added: 0,
        locks_removed: 0,
        commit_fails,
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
            r#"{{"version":1,"devices":[{{"name":"mock-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_MUTATION_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}},"mutation":{{"admin":"mcp-admin","allowed_xpath_roots":["/config/shared/address"],"allow_delete":true,"require_config_lock":true}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("mutation inventory");
    Fixture {
        _directory: directory,
        state,
        server: handle,
        service: PanosService::new(inventory).expect("service"),
    }
}

#[tokio::test]
async fn stage_diff_validate_detached_commit_and_discard_are_guarded() {
    let fixture = fixture(false).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let mismatch = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: "sha256:stale".to_owned(),
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
            },
            "token-a",
            CancellationToken::new(),
        )
        .await;
    assert!(mismatch.is_err());

    let staged = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
            },
            "token-a",
            CancellationToken::new(),
        )
        .await
        .expect("stage");
    let operation = OperationInput {
        device: "mock-fw".to_owned(),
        operation_id: staged.operation_id.clone(),
        expected_candidate_fingerprint: staged.candidate_fingerprint.clone(),
    };
    assert!(
        fixture
            .service
            .commit_candidate(operation.clone(), "token-a", CancellationToken::new())
            .await
            .is_err(),
        "commit must refuse an unvalidated operation"
    );
    let diff = fixture
        .service
        .diff_candidate(operation.clone(), "token-a", CancellationToken::new())
        .await
        .expect("diff");
    assert!(diff.change_summary.contains("/config/shared/address"));
    let validated = fixture
        .service
        .validate_candidate(operation.clone(), "token-a", CancellationToken::new())
        .await
        .expect("validate");
    assert!(validated.succeeded);

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let commit = fixture
        .service
        .commit_candidate(operation, "token-a", cancelled)
        .await
        .expect("detached commit");
    assert_eq!(commit.disposition, CommitDisposition::Detached);
    let mut terminal = None;
    for _ in 0..100 {
        let status = fixture
            .service
            .operation_status(
                OperationStatusInput {
                    device: "mock-fw".to_owned(),
                    operation_id: staged.operation_id.clone(),
                },
                "token-a",
            )
            .await
            .expect("status");
        if status.state == "committed" {
            terminal = Some(status);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(terminal.expect("commit reconciled").job_id.is_some());

    let current = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let xpath = "/config/shared/address/entry[@name='phase3']".to_owned();
    let deletion = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: current.candidate_fingerprint,
                action: StageAction::Delete,
                xpath: xpath.clone(),
                element: None,
                destructive_confirmation: Some(format!("DELETE {xpath}")),
            },
            "token-a",
            CancellationToken::new(),
        )
        .await
        .expect("delete stage");
    fixture
        .service
        .discard_candidate(
            OperationInput {
                device: "mock-fw".to_owned(),
                operation_id: deletion.operation_id,
                expected_candidate_fingerprint: deletion.candidate_fingerprint,
            },
            "token-a",
            CancellationToken::new(),
        )
        .await
        .expect("discard");
    let state = fixture.state.lock().expect("state");
    assert_eq!(state.candidate, state.running);
    assert_eq!(state.locks_added, state.locks_removed);
}

#[tokio::test]
async fn failed_commit_remains_recoverable_by_discard() {
    let fixture = fixture(true).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let staged = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
            },
            "token-a",
            CancellationToken::new(),
        )
        .await
        .expect("stage");
    let operation = OperationInput {
        device: "mock-fw".to_owned(),
        operation_id: staged.operation_id.clone(),
        expected_candidate_fingerprint: staged.candidate_fingerprint.clone(),
    };
    assert!(
        fixture
            .service
            .validate_candidate(operation.clone(), "token-a", CancellationToken::new())
            .await
            .expect("validation")
            .succeeded
    );
    let commit = fixture
        .service
        .commit_candidate(operation.clone(), "token-a", CancellationToken::new())
        .await
        .expect("terminal failed commit");
    assert_eq!(commit.succeeded, Some(false));
    let status = fixture
        .service
        .operation_status(
            OperationStatusInput {
                device: "mock-fw".to_owned(),
                operation_id: staged.operation_id,
            },
            "token-a",
        )
        .await
        .expect("status");
    assert_eq!(status.state, "failed");
    fixture
        .service
        .discard_candidate(operation, "token-a", CancellationToken::new())
        .await
        .expect("failed commit discard");
    let state = fixture.state.lock().expect("state");
    assert_eq!(state.candidate, state.running);
    assert_eq!(state.locks_added, state.locks_removed);
}

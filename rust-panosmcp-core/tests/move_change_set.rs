//! Rule `move` under the guarded change-set lifecycle, against a deterministic
//! mock PAN-OS XML API that is aware of the requested XPath -- unlike the
//! shared mock in `mutation_lifecycle.rs`, which always answers with the
//! whole running/candidate document regardless of what was asked for. A
//! `move` action needs the mock to answer "what rules currently exist in this
//! container" so the live-existence check (MEC-535) has something real to
//! check against.

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_auth::{MutationAction, MutationGrant};
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    mutation::{
        CandidateFingerprintInput, ChangeSetAction, CreateChangeSetInput, MovePosition,
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

const RULES_XPATH: &str = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules";

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_MOVE_TEST_KEY").then(|| "fixture-api-key".to_owned())
    }
}

#[derive(Debug, Default)]
struct MockState {
    /// `<rules>` container body PAN-OS would answer for a `show`/`get` at
    /// `RULES_XPATH` -- the live rulebase a `move` action is checked against.
    rules: String,
    /// Requests PAN-OS actually received for `action=move`, each captured as
    /// its exact `(xpath, where, dst)` fields -- this is what proves the
    /// device command was built correctly, not just that *something* was
    /// sent.
    move_requests: Vec<(String, String, Option<String>)>,
    locks_added: usize,
    locks_removed: usize,
}

fn success(inner: &str) -> String {
    format!(r#"<response status="success" code="19">{inner}</response>"#)
}

async fn api(
    State(state): State<Arc<Mutex<MockState>>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> String {
    let request_type = form.get("type").map(String::as_str);
    let action = form.get("action").map(String::as_str);
    let xpath = form.get("xpath").map(String::as_str).unwrap_or_default();
    let command = form.get("cmd").map(String::as_str).unwrap_or_default();

    if request_type == Some("config") && (action == Some("show") || action == Some("get")) {
        if xpath == RULES_XPATH {
            let rules = state.lock().expect("state").rules.clone();
            return success(&format!("<result>{rules}</result>"));
        }
        // Every other read in this test is `candidate_fingerprint` hashing
        // the one configured mutation root, which *is* `RULES_XPATH` -- so
        // nothing else should be asked for.
        return r#"<response status="error" code="17"><msg><line>unexpected xpath in mock</line></msg></response>"#.to_owned();
    }
    if command == "<check><pending-changes></pending-changes></check>" {
        return success("<result>no</result>");
    }
    if request_type == Some("config") && action == Some("move") {
        let mut state = state.lock().expect("state");
        state.move_requests.push((
            xpath.to_owned(),
            form.get("where").cloned().unwrap_or_default(),
            form.get("dst").cloned(),
        ));
        return success("<result><msg>move complete</msg></result>");
    }
    if command.contains("<config-lock><add>") {
        state.lock().expect("state").locks_added += 1;
        return success("<result><msg>lock added</msg></result>");
    }
    if command.contains("<config-lock><remove>") {
        state.lock().expect("state").locks_removed += 1;
        return success("<result><msg>lock removed</msg></result>");
    }
    r#"<response status="error" code="17"><msg><line>unsupported mock request</line></msg></response>"#.to_owned()
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

async fn fixture() -> Fixture {
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

    // Two existing rules -- matches the real PAN-OS shape for a rule-base
    // container fetch (`response`/`result`/`rules`/`entry`), which is exactly
    // the depth `scan_config_entries` expects for a list container.
    let state = Arc::new(Mutex::new(MockState {
        rules: "<rules><entry name=\"rule1\"><action>allow</action></entry>\
                <entry name=\"rule2\"><action>deny</action></entry></rules>"
            .to_owned(),
        ..Default::default()
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
            r#"{{"version":1,"devices":[{{"name":"mock-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_MOVE_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}},"mutation":{{"admin":"mcp-admin","allowed_xpath_roots":["{}"],"allow_delete":true,"require_config_lock":true}}}}]}}"#,
            address.port(),
            cert_path.display(),
            RULES_XPATH,
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("mutation inventory");
    let state_path = directory.path().join("mutation-state.json");
    let service = PanosService::new_with_options(
        inventory,
        Some(&state_path),
        false,
        None,
        false,
        true,
        None,
    )
    .expect("service");
    Fixture {
        _directory: directory,
        state,
        server: handle,
        service,
    }
}

fn grant() -> MutationGrant {
    MutationGrant {
        allowed_xpath_roots: vec![RULES_XPATH.to_owned()],
        actions: vec![MutationAction::Move],
    }
}

fn rule_xpath(name: &str) -> String {
    format!("{RULES_XPATH}/entry[@name='{name}']")
}

#[tokio::test]
async fn stage_config_refuses_a_move_to_a_nonexistent_destination() {
    let fixture = fixture().await;
    let fingerprint = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");

    let error = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: fingerprint.candidate_fingerprint,
                action: StageAction::Move,
                xpath: rule_xpath("rule1"),
                element: None,
                destructive_confirmation: None,
                move_position: Some(MovePosition::After),
                move_destination: Some("does-not-exist".to_owned()),
            },
            "writer",
            Some(&grant()),
            None,
            CancellationToken::new(),
        )
        .await
        .expect_err("a nonexistent move destination must be refused");
    assert!(
        error.to_string().contains("does not exist"),
        "error should name the missing destination, got: {error}"
    );

    let state = fixture.state.lock().expect("state");
    assert!(
        state.move_requests.is_empty(),
        "PAN-OS must never see a move naming a destination this server could not confirm exists"
    );
    assert_eq!(
        state.locks_added, 0,
        "an invalid move must be refused before any device-side lock is taken"
    );
}

#[tokio::test]
async fn stage_config_refuses_to_move_a_nonexistent_rule() {
    let fixture = fixture().await;
    let fingerprint = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");

    let error = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: fingerprint.candidate_fingerprint,
                action: StageAction::Move,
                xpath: rule_xpath("ghost-rule"),
                element: None,
                destructive_confirmation: None,
                move_position: Some(MovePosition::Top),
                move_destination: None,
            },
            "writer",
            Some(&grant()),
            None,
            CancellationToken::new(),
        )
        .await
        .expect_err("moving a rule that does not exist must be refused");
    assert!(
        error.to_string().contains("does not exist"),
        "error should name the missing rule, got: {error}"
    );
    assert!(
        fixture
            .state
            .lock()
            .expect("state")
            .move_requests
            .is_empty()
    );
}

#[tokio::test]
async fn stage_config_moves_an_existing_rule_after_an_existing_sibling() {
    let fixture = fixture().await;
    let fingerprint = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");

    let staged = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: fingerprint.candidate_fingerprint,
                action: StageAction::Move,
                xpath: rule_xpath("rule1"),
                element: None,
                destructive_confirmation: None,
                move_position: Some(MovePosition::After),
                move_destination: Some("rule2".to_owned()),
            },
            "writer",
            Some(&grant()),
            None,
            CancellationToken::new(),
        )
        .await
        .expect("a move between two existing rules must succeed");
    assert!(!staged.operation_id.is_empty());

    let state = fixture.state.lock().expect("state");
    assert_eq!(
        state.move_requests,
        vec![(
            rule_xpath("rule1"),
            "after".to_owned(),
            Some("rule2".to_owned())
        )],
        "PAN-OS must receive exactly the move this action described: the moved \
         rule's own xpath, the requested position, and the named sibling"
    );
    assert_eq!(state.locks_added, 1);
}

#[tokio::test]
async fn create_change_set_refuses_a_move_whose_destination_does_not_exist() {
    let fixture = fixture().await;
    let fingerprint = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");

    let error = fixture
        .service
        .create_change_set(
            CreateChangeSetInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: fingerprint.candidate_fingerprint,
                actions: vec![ChangeSetAction {
                    action: StageAction::Move,
                    xpath: rule_xpath("rule1"),
                    element: None,
                    destructive_confirmation: None,
                    move_position: Some(MovePosition::Before),
                    move_destination: Some("does-not-exist".to_owned()),
                }],
            },
            None,
            "writer",
            Some(&grant()),
            CancellationToken::new(),
        )
        .await
        .expect_err("a plan naming a nonexistent move destination must be refused at plan time");
    assert!(error.to_string().contains("does not exist"));
    assert!(
        fixture
            .state
            .lock()
            .expect("state")
            .move_requests
            .is_empty()
    );
}

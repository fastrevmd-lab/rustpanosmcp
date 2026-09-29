//! End-to-end coverage for `list_panos_entries` and `get_panos_entry_digest`
//! (MEC-531): pagination and byte-truncation on a large rulebase, and
//! single-entry drift detection that never re-reads the config root.

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::{ConfigSource, GetPanosEntryDigestInput, ListPanosEntriesInput, PanosService},
};
use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio_util::sync::CancellationToken;

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_LIST_ENTRIES_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

#[derive(Debug, Default)]
struct MockState {
    /// Current XML for the one entry `get_panos_entry_digest` tests target.
    entry_action: Mutex<String>,
    /// Every xpath a `type=config` request asked for, in order.
    requested_xpaths: Mutex<Vec<String>>,
    request_count: AtomicUsize,
}

fn success(body: &str) -> String {
    format!(r#"<response status="success">{body}</response>"#)
}

fn rulebase(count: usize) -> String {
    let rules: String = (0..count)
        .map(|i| format!(r#"<entry name="rule-{i:04}"><action>allow</action></entry>"#))
        .collect();
    format!("<result><rules>{rules}</rules></result>")
}

async fn api(
    State(state): State<Arc<MockState>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> String {
    state.request_count.fetch_add(1, Ordering::SeqCst);
    let request_type = form.get("type").map(String::as_str);
    let action = form.get("action").map(String::as_str);
    let xpath = form.get("xpath").cloned().unwrap_or_default();

    if request_type == Some("config") && action == Some("get") {
        state
            .requested_xpaths
            .lock()
            .expect("xpaths")
            .push(xpath.clone());

        if xpath.ends_with(']') {
            // A single-entry XPath: return exactly that one entry.
            let action = state.entry_action.lock().expect("entry action").clone();
            return success(&format!(
                r#"<result><entry name="watched-rule"><action>{action}</action></entry></result>"#
            ));
        }
        if xpath.contains("rule-base/security/rules") {
            let count: usize = if xpath.contains("big") { 5_000 } else { 10 };
            return success(&rulebase(count));
        }
    }

    r#"<response status="error"><msg><line>unknown request</line></msg></response>"#.to_owned()
}

async fn fixture(max_response_bytes: Option<usize>) -> (PanosService, Arc<MockState>) {
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
    let state = Arc::new(MockState::default());
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

    let max_response_bytes_json = max_response_bytes
        .map(|value| format!(r#","max_response_bytes":{value}"#))
        .unwrap_or_default();
    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"test-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_LIST_ENTRIES_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}}{max_response_bytes_json}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("list entries test inventory");
    (PanosService::new(inventory).expect("service"), state)
}

#[tokio::test]
async fn pagination_returns_only_the_requested_window_as_structured_json() {
    let (service, _state) = fixture(None).await;
    let out = service
        .list_panos_entries(
            ListPanosEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Candidate,
                xpath: "/config/devices/entry/vsys/entry/rule-base/security/rules".to_owned(),
                offset: Some(3),
                limit: Some(4),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("list entries");

    assert_eq!(out.total_entries, 10);
    assert_eq!(out.returned, 4);
    assert_eq!(out.entries.len(), 4);
    assert_eq!(out.entries[0].name, "rule-0003");
    assert_eq!(out.entries[3].name, "rule-0006");
    // Structured per-entry digest, not an opaque blob.
    for entry in &out.entries {
        assert!(entry.digest.starts_with("sha256:"));
        assert!(entry.xml.contains(&entry.name));
    }
    // More rules exist past this page: "N of M shown".
    assert!(out.truncated);
}

#[tokio::test]
async fn a_rulebase_over_the_old_5mib_style_cap_is_truncated_and_marked_not_errored() {
    // A small device-level cap simulates the old 5 MiB ceiling: 5000 rules
    // guarantees this device's raw response is many times larger than it.
    let (service, _state) = fixture(Some(8192)).await;
    let out = service
        .list_panos_entries(
            ListPanosEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Candidate,
                xpath: "/config/devices/entry/vsys/entry/rule-base/security/rules-big".to_owned(),
                offset: Some(0),
                limit: Some(500),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("a byte-capped rulebase must return a truncated result, not an error");

    assert!(
        out.truncated,
        "response cut short of the full rulebase must be marked"
    );
    assert!(
        !out.entries.is_empty(),
        "entries that completed before the cut must still be returned"
    );
    assert!(
        out.total_entries < 5_000,
        "the scan must not claim to have seen entries past the byte cut"
    );
    for entry in &out.entries {
        assert!(entry.name.starts_with("rule-"));
    }
}

#[tokio::test]
async fn entry_digest_detects_drift_without_reading_the_config_root() {
    let (service, state) = fixture(None).await;
    *state.entry_action.lock().expect("entry action") = "allow".to_owned();

    let xpath =
        "/config/devices/entry/vsys/entry/rule-base/security/rules/entry[@name='watched-rule']"
            .to_owned();

    let before = service
        .get_panos_entry_digest(
            GetPanosEntryDigestInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Candidate,
                xpath: xpath.clone(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("digest before change");
    assert!(before.found);
    assert_eq!(before.name.as_deref(), Some("watched-rule"));

    *state.entry_action.lock().expect("entry action") = "deny".to_owned();
    let after = service
        .get_panos_entry_digest(
            GetPanosEntryDigestInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Candidate,
                xpath: xpath.clone(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("digest after change");

    assert_ne!(
        before.digest, after.digest,
        "changing the entry must change its digest"
    );

    // Exactly one request per call, each scoped to the entry's own xpath --
    // never the config root a full fingerprint would read.
    let requested = state.requested_xpaths.lock().expect("xpaths").clone();
    assert_eq!(requested, vec![xpath.clone(), xpath]);
    assert_eq!(state.request_count.load(Ordering::SeqCst), 2);
}

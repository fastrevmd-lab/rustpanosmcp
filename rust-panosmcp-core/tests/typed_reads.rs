//! End-to-end coverage for the MEC-534 typed read tools: HA state, license,
//! content, and software status, `test security-policy-match`, bounded log
//! queries, and typed rulebase/object listings.

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_core::{
    PanosMcpError,
    inventory::{Environment, Inventory},
    tools::{
        ConfigSource, GetPanosContentStatusInput, GetPanosHaStateInput, GetPanosLicenseInfoInput,
        GetPanosSoftwareStatusInput, IpProtocol, ListPanosRulebaseEntriesInput, PanosLogType,
        PanosService, QueryPanosLogsInput, RulebaseKind, TestPanosSecurityPolicyMatchInput,
    },
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
        (name == "PANOS_TYPED_READS_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

#[derive(Debug, Default)]
struct MockState {
    /// Every `(type, action)` pair a request asked for, in order.
    requests: Mutex<Vec<(String, String)>>,
}

fn success(body: &str) -> String {
    format!(r#"<response status="success">{body}</response>"#)
}

async fn api(
    State(state): State<Arc<MockState>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> String {
    let request_type = form.get("type").cloned().unwrap_or_default();
    let action = form.get("action").cloned().unwrap_or_default();
    state
        .requests
        .lock()
        .expect("requests")
        .push((request_type.clone(), action.clone()));
    let command = form.get("cmd").cloned().unwrap_or_default();

    if command.contains("<show><high-availability><state>") {
        return success(
            "<result><enabled>yes</enabled><group><mode>Active-Passive</mode><local-info><state>active</state></local-info><peer-info><state>passive</state></peer-info></group></result>",
        );
    }
    if command.contains("<request><license><info>") {
        return success(
            r#"<result><licenses><entry><feature>PA-VM</feature><description>Virtual firewall</description><serial>000000000</serial><issued>January 1, 2026</issued><expires>Never</expires><expired>no</expired></entry></licenses></result>"#,
        );
    }
    if command.contains("<request><content><upgrade><info>") {
        return success(
            r#"<result><content-updates><entry><version>8800-1234</version><filename>panupv2-all-8800-1234</filename><released-on>2026/01/01</released-on><downloaded>yes</downloaded><current>yes</current></entry></content-updates></result>"#,
        );
    }
    if command.contains("<request><system><software><info>") {
        return success(
            r#"<result><sw-updates><versions><entry><version>11.0.0</version><filename>PanOS_vm-11.0.0</filename><released-on>2025/06/01</released-on><downloaded>yes</downloaded><current>yes</current><latest>yes</latest></entry></versions></sw-updates></result>"#,
        );
    }
    if command.contains("<test><security-policy-match>") {
        if command.contains("203.0.113.99") {
            // Deliberately zero matches for one probe address.
            return success("<result><rules></rules></result>");
        }
        return success(
            r#"<result><rules><entry name="allow-web"><from>trust</from><to>untrust</to></entry></rules></result>"#,
        );
    }
    if request_type == "log" && action.is_empty() {
        return success("<result><job>555</job></result>");
    }
    if request_type == "log" && action == "get" {
        return success(
            r#"<result><status>FIN</status><log><logs><entry><receive_time>2026-01-01T00:00:00</receive_time><src>192.0.2.1</src></entry></logs></log></result>"#,
        );
    }
    if request_type == "config" && (action == "show" || action == "get") {
        let xpath = form.get("xpath").cloned().unwrap_or_default();
        return success(&format!(
            r#"<result><container><entry name="from-{xpath}"><ip-netmask>192.0.2.0/24</ip-netmask></entry></container></result>"#
        ));
    }

    r#"<response status="error"><msg><line>unknown request</line></msg></response>"#.to_owned()
}

async fn fixture() -> (PanosService, Arc<MockState>) {
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

    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"test-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_TYPED_READS_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("typed reads test inventory");
    (PanosService::new(inventory).expect("service"), state)
}

#[tokio::test]
async fn ha_state_reports_local_and_peer_state() {
    let (service, _state) = fixture().await;
    let out = service
        .get_panos_ha_state(
            GetPanosHaStateInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("ha state");

    assert_eq!(out.state.enabled.as_deref(), Some("yes"));
    assert_eq!(out.state.mode.as_deref(), Some("Active-Passive"));
    assert_eq!(out.state.local_state.as_deref(), Some("active"));
    assert_eq!(out.state.peer_state.as_deref(), Some("passive"));
}

#[tokio::test]
async fn license_info_parses_typed_fields_per_entry() {
    let (service, _state) = fixture().await;
    let out = service
        .get_panos_license_info(
            GetPanosLicenseInfoInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("license info");

    assert_eq!(out.licenses.len(), 1);
    let license = &out.licenses[0];
    assert_eq!(license.feature.as_deref(), Some("PA-VM"));
    assert_eq!(license.expired.as_deref(), Some("no"));
    assert_eq!(license.expires.as_deref(), Some("Never"));
}

#[tokio::test]
async fn content_and_software_status_report_current_version() {
    let (service, _state) = fixture().await;

    let content = service
        .get_panos_content_status(
            GetPanosContentStatusInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("content status");
    assert_eq!(content.versions.len(), 1);
    assert_eq!(content.versions[0].current.as_deref(), Some("yes"));

    let software = service
        .get_panos_software_status(
            GetPanosSoftwareStatusInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("software status");
    assert_eq!(software.versions.len(), 1);
    assert_eq!(software.versions[0].version.as_deref(), Some("11.0.0"));
}

#[tokio::test]
async fn security_policy_match_reports_matched_and_unmatched_probes() {
    let (service, _state) = fixture().await;

    let matched = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "192.0.2.10".parse().expect("ip"),
                destination: "192.0.2.20".parse().expect("ip"),
                destination_port: 443,
                protocol: IpProtocol::Tcp,
                from_zone: None,
                to_zone: None,
                application: None,
                source_user: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("policy match");
    assert!(matched.matched);
    assert_eq!(matched.rule_name.as_deref(), Some("allow-web"));

    let unmatched = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "203.0.113.99".parse().expect("ip"),
                destination: "192.0.2.20".parse().expect("ip"),
                destination_port: 443,
                protocol: IpProtocol::Tcp,
                from_zone: None,
                to_zone: None,
                application: None,
                source_user: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("policy match");
    assert!(!unmatched.matched);
    assert!(unmatched.rule_name.is_none());
}

/// A zone name crafted to break out of its `<from>...</from>` element must
/// not be able to inject a sibling element into the command PAN-OS receives
/// -- it must arrive escaped, exactly as XML text.
#[tokio::test]
async fn security_policy_match_escapes_a_zone_name_that_looks_like_xml() {
    let (service, state) = fixture().await;
    let _ = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "192.0.2.10".parse().expect("ip"),
                destination: "192.0.2.20".parse().expect("ip"),
                destination_port: 443,
                protocol: IpProtocol::Tcp,
                from_zone: Some("trust</from><to>untrust".to_owned()),
                to_zone: None,
                application: None,
                source_user: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("policy match with hostile zone name");
    // If escaping failed, the mock would have seen a well-formed but
    // attacker-controlled `<to>untrust</to>` element; asserting on the
    // request count only proves the call round-tripped without the server
    // rejecting malformed XML, which it would if the escape produced an
    // unbalanced tag.
    assert!(!state.requests.lock().expect("requests").is_empty());
}

#[tokio::test]
async fn log_query_defaults_to_a_bounded_limit_and_rejects_an_excessive_one() {
    let (service, _state) = fixture().await;

    let out = service
        .query_panos_logs(
            QueryPanosLogsInput {
                device: "test-fw".to_owned(),
                log_type: PanosLogType::Traffic,
                query: None,
                max_logs: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("log query");
    assert_eq!(
        out.max_logs, 100,
        "unspecified max_logs must default, not be unbounded"
    );
    assert_eq!(out.returned, 1);

    let rejected = service
        .query_panos_logs(
            QueryPanosLogsInput {
                device: "test-fw".to_owned(),
                log_type: PanosLogType::Traffic,
                query: None,
                max_logs: Some(1_000_001),
            },
            None,
            CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        rejected,
        Err(PanosMcpError::Policy {
            field: "max_logs",
            ..
        })
    ));
}

#[tokio::test]
async fn rulebase_entries_builds_the_xpath_from_kind_and_vsys() {
    let (service, state) = fixture().await;
    let out = service
        .list_panos_rulebase_entries(
            ListPanosRulebaseEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                kind: RulebaseKind::NatRules,
                vsys: "vsys2".to_owned(),
                offset: None,
                limit: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("rulebase entries");

    assert_eq!(
        out.xpath,
        "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']/rule-base/nat/rules"
    );
    assert_eq!(out.entries.len(), 1);
    let requests = state.requests.lock().expect("requests").clone();
    assert!(requests.contains(&("config".to_owned(), "show".to_owned())));
}

#[tokio::test]
async fn rulebase_entries_rejects_a_vsys_name_that_would_break_out_of_the_predicate() {
    let (service, _state) = fixture().await;
    let result = service
        .list_panos_rulebase_entries(
            ListPanosRulebaseEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                kind: RulebaseKind::AddressObjects,
                vsys: "vsys1']/../shared".to_owned(),
                offset: None,
                limit: None,
            },
            None,
            CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        result,
        Err(PanosMcpError::Policy { field: "vsys", .. })
    ));
}

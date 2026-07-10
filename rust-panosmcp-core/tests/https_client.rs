//! End-to-end coverage against an in-process HTTPS PAN-OS mock.

use axum::{
    Router,
    extract::{ConnectInfo, Form, OriginalUri, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::post,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rust_panosmcp_core::{
    PanosMcpError,
    client::PanosClient,
    inventory::{Environment, Inventory},
    xml::parse_device_facts,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const API_KEY: &str = "mock-pan-os-api-key";

#[derive(Debug, Clone)]
struct RequestRecord {
    api_key_ok: bool,
    uri_has_query: bool,
    form: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct MockState {
    records: Mutex<Vec<RequestRecord>>,
    peers: Mutex<BTreeSet<SocketAddr>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
    jobs: AtomicUsize,
}

struct ActiveGuard(Arc<MockState>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct MockHttps {
    endpoint: String,
    cert_path: PathBuf,
    leaf_digest: [u8; 32],
    state: Arc<MockState>,
    handle: axum_server::Handle<SocketAddr>,
    _directory: tempfile::TempDir,
}

impl MockHttps {
    async fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().expect("temporary mock directory");
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mock certificate");
        let cert_pem = cert.pem();
        let key_pem = signing_key.serialize_pem();
        let cert_path = directory.path().join("ca.pem");
        fs::write(&cert_path, &cert_pem).expect("write mock CA");
        let leaf_digest = Sha256::digest(cert.der().as_ref()).into();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            cert_pem.into_bytes(),
            key_pem.into_bytes(),
        )
        .await
        .expect("mock TLS config");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mock HTTPS");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("mock address");
        let state = Arc::new(MockState::default());
        let app = Router::new()
            .route("/api/", post(api))
            .with_state(state.clone());
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .expect("create mock HTTPS server")
                .handle(server_handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("mock HTTPS server");
        });
        tokio::task::yield_now().await;
        Self {
            endpoint: format!("https://localhost:{}", address.port()),
            cert_path,
            leaf_digest,
            state,
            handle,
            _directory: directory,
        }
    }

    fn client(&self, tls: &str, extra: &str) -> PanosClient {
        let inventory_path = self._directory.path().join(format!(
            "inventory-{}.json",
            self.state.records.lock().expect("records").len()
        ));
        let tls_json = match tls {
            "system" => r#"{"type":"system"}"#.to_owned(),
            "custom_ca" => format!(
                r#"{{"type":"custom_ca","path":"{}"}}"#,
                self.cert_path.display()
            ),
            "pin" => format!(
                r#"{{"type":"leaf_sha256","fingerprint":"{}"}}"#,
                digest_hex(self.leaf_digest)
            ),
            "bad_pin" => format!(
                r#"{{"type":"leaf_sha256","fingerprint":"{}"}}"#,
                "00".repeat(32)
            ),
            _ => panic!("unknown test TLS mode"),
        };
        fs::write(
            &inventory_path,
            format!(
                r#"{{"version":1,"devices":[{{"name":"mock-fw","endpoint":"{}","api_key":{{"type":"env","name":"PANOS_TEST_KEY"}},"tls":{}, {extra}}}]}}"#,
                self.endpoint, tls_json
            ),
        )
        .expect("write inventory");
        let inventory = Inventory::load_with_environment(inventory_path, &TestEnvironment)
            .expect("load mock inventory");
        PanosClient::new(inventory.device("mock-fw").expect("mock device"))
            .expect("build PAN-OS client")
    }
}

impl Drop for MockHttps {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_TEST_KEY").then(|| API_KEY.to_owned())
    }
}

async fn api(
    State(state): State<Arc<MockState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> impl IntoResponse {
    state.peers.lock().expect("peers").insert(peer);
    state.records.lock().expect("records").push(RequestRecord {
        api_key_ok: headers
            .get("X-PAN-KEY")
            .is_some_and(|value| value.as_bytes() == API_KEY.as_bytes()),
        uri_has_query: uri.query().is_some(),
        form: form.clone(),
    });
    let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
    state.max_active.fetch_max(active, Ordering::SeqCst);
    let _active = ActiveGuard(state.clone());

    let command = form.get("cmd").map(String::as_str).unwrap_or_default();
    if command.contains("<timeout") {
        tokio::time::sleep(Duration::from_millis(1_200)).await;
    }
    if command.contains("<slow") {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    if command.contains("<large") {
        return format!(
            "<response status=\"success\" code=\"19\"><result>{}</result></response>",
            "x".repeat(4096)
        );
    }
    if command.contains("<error") {
        return "<response status=\"error\" code=\"7\"><msg><line>Object is not present</line></msg></response>".to_owned();
    }
    if command.contains("<jobs>") {
        if state.jobs.fetch_add(1, Ordering::SeqCst) == 0 {
            return "<response status=\"success\" code=\"19\"><result><job><status>ACT</status><progress>25</progress></job></result></response>".to_owned();
        }
        return "<response status=\"success\" code=\"19\"><result><job><status>FIN</status><result>OK</result><progress>100</progress></job></result></response>".to_owned();
    }
    if form.get("type").map(String::as_str) == Some("config") {
        return "<response status=\"success\" code=\"19\"><result><config><devices/></config></result></response>".to_owned();
    }
    "<response status=\"success\" code=\"19\"><result><system><hostname>mock-fw</hostname><ip-address>192.0.2.10</ip-address><model>PA-VM</model><serial>012345</serial><sw-version>11.2.4</sw-version><uptime>1 day</uptime></system></result></response>".to_owned()
}

fn digest_hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_post_protocol(records: &[RequestRecord]) {
    assert!(!records.is_empty());
    for record in records {
        assert!(record.api_key_ok, "X-PAN-KEY header must carry the API key");
        assert!(
            !record.uri_has_query,
            "API request URL must contain no query"
        );
        assert!(
            !record.form.contains_key("key"),
            "API key must never enter the form"
        );
    }
}

#[tokio::test]
async fn custom_ca_supports_facts_config_and_typed_api_errors() {
    let mock = MockHttps::start().await;
    let client = mock.client("custom_ca", "\"max_concurrency\":2");
    assert!(!format!("{client:?}").contains(API_KEY));
    let response = client
        .operational(
            "<show><system><info/></system></show>",
            CancellationToken::new(),
        )
        .await
        .expect("custom CA operational read");
    let facts = parse_device_facts(&response).expect("parse facts");
    assert_eq!(facts.hostname.as_deref(), Some("mock-fw"));
    assert_eq!(facts.software_version.as_deref(), Some("11.2.4"));

    client
        .configuration(true, "/config/devices", CancellationToken::new())
        .await
        .expect("candidate config read");
    let error = client
        .operational("<show><error/></show>", CancellationToken::new())
        .await
        .expect_err("PAN-OS error envelope");
    assert!(matches!(error, PanosMcpError::Api { code: 7, .. }));

    let records = mock.state.records.lock().expect("records");
    assert_post_protocol(&records);
    assert!(records.iter().any(|record| {
        record.form.get("action").map(String::as_str) == Some("get")
            && record.form.get("xpath").map(String::as_str) == Some("/config/devices")
    }));
}

#[tokio::test]
async fn system_roots_reject_self_signed_while_exact_leaf_pin_is_enforced() {
    let mock = MockHttps::start().await;
    let system = mock.client("system", "\"max_concurrency\":1");
    assert!(matches!(
        system
            .operational("<show/>", CancellationToken::new())
            .await,
        Err(PanosMcpError::Transport { .. })
    ));

    let pinned = mock.client("pin", "\"max_concurrency\":1");
    pinned
        .operational("<show/>", CancellationToken::new())
        .await
        .expect("exact leaf pin");
    let bad_pin = mock.client("bad_pin", "\"max_concurrency\":1");
    assert!(matches!(
        bad_pin
            .operational("<show/>", CancellationToken::new())
            .await,
        Err(PanosMcpError::Transport { .. })
    ));
}

#[tokio::test]
async fn response_timeout_cancellation_concurrency_and_pooling_are_bounded() {
    let mock = MockHttps::start().await;
    let client = mock.client(
        "custom_ca",
        "\"max_concurrency\":2,\"request_timeout_secs\":1,\"max_response_bytes\":2048",
    );
    assert!(matches!(
        client
            .operational("<show><large/></show>", CancellationToken::new())
            .await,
        Err(PanosMcpError::ResponseTooLarge { .. })
    ));
    assert!(matches!(
        client
            .operational("<show><timeout/></show>", CancellationToken::new())
            .await,
        Err(PanosMcpError::Timeout { .. })
    ));

    let cancellation = CancellationToken::new();
    let cancel_now = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel_now.cancel();
    });
    assert!(matches!(
        client
            .operational("<show><slow/></show>", cancellation)
            .await,
        Err(PanosMcpError::Cancelled)
    ));

    let calls = (0..6).map(|_| {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .operational("<show><slow/></show>", CancellationToken::new())
                .await
        })
    });
    for call in calls {
        call.await.expect("join call").expect("bounded call");
    }
    assert!(mock.state.max_active.load(Ordering::SeqCst) <= 2);

    let pool_mock = MockHttps::start().await;
    let pooled = pool_mock.client("custom_ca", "\"max_concurrency\":1");
    for _ in 0..3 {
        pooled
            .operational("<show/>", CancellationToken::new())
            .await
            .expect("pooled request");
    }
    assert_eq!(pool_mock.state.peers.lock().expect("peers").len(), 1);
}

#[tokio::test]
async fn asynchronous_job_polling_reaches_terminal_state() {
    let mock = MockHttps::start().await;
    let client = mock.client("custom_ca", "\"max_concurrency\":1");
    let job = client
        .poll_job("42", Duration::from_secs(3), CancellationToken::new())
        .await
        .expect("job polling");
    assert!(job.succeeded());
    assert!(mock.state.jobs.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
#[ignore = "manual release benchmark: run with --release --ignored --nocapture"]
async fn benchmark_warm_pooled_https_read_latency() {
    let mock = MockHttps::start().await;
    let client = mock.client("custom_ca", "\"max_concurrency\":1");
    for _ in 0..10 {
        client
            .operational(
                "<show><system><info/></system></show>",
                CancellationToken::new(),
            )
            .await
            .expect("warm-up read");
    }

    let mut samples = Vec::with_capacity(200);
    for _ in 0..200 {
        let started = Instant::now();
        let result = client
            .operational(
                "<show><system><info/></system></show>",
                CancellationToken::new(),
            )
            .await
            .expect("benchmark read");
        std::hint::black_box(result);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = percentile(&samples, 50);
    let p95 = percentile(&samples, 95);
    println!("warm pooled mock HTTPS facts: p50={p50:?}, p95={p95:?}, n=200");
    assert_eq!(
        mock.state.peers.lock().expect("peers").len(),
        1,
        "benchmark must retain one pooled HTTPS connection"
    );
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let index = (samples.len() * percentile).div_ceil(100).saturating_sub(1);
    samples[index]
}

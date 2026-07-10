//! In-memory MCP client/server tool-registry drift test.

use rmcp::{ServiceExt, model::CallToolRequestParams};
use rust_panosmcp::PanosMcpServer;
use rust_panosmcp_auth::KNOWN_TOOLS;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::PanosService,
};
use std::path::Path;
use std::time::{Duration, Instant};

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

fn handler(directory: &Path) -> PanosMcpServer {
    let path = directory.join("devices.json");
    std::fs::write(
        &path,
        r#"{"version":1,"devices":[{"name":"lab-fw","endpoint":"https://fw.example.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"}}]}"#,
    )
    .expect("write inventory");
    let inventory = Inventory::load_with_environment(path, &TestEnvironment).expect("inventory");
    PanosMcpServer::new(PanosService::new(inventory).expect("PAN-OS service"))
}

#[tokio::test]
async fn client_discovers_exactly_the_registered_tools() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);
    let server = handler(directory.path());
    let server_task = tokio::spawn(async move {
        server
            .serve(server_transport)
            .await
            .expect("server initialization should succeed")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let info = client.peer_info().expect("server info");
    assert_eq!(info.server_info.name, "rust-panosmcp");

    let tools = client.list_tools(None).await.expect("tool list");
    let names: Vec<_> = tools.tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(names, KNOWN_TOOLS, "token registry must track MCP tools");

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
#[ignore = "manual release benchmark: run with --release --ignored --nocapture"]
async fn benchmark_in_memory_mcp_read_overhead() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server = handler(directory.path());
    let server_task = tokio::spawn(async move {
        server
            .serve(server_transport)
            .await
            .expect("server initialization should succeed")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");

    for _ in 0..20 {
        client
            .call_tool(CallToolRequestParams::new("list_devices"))
            .await
            .expect("warm-up call");
    }
    let mut samples = Vec::with_capacity(1_000);
    for _ in 0..1_000 {
        let started = Instant::now();
        let result = client
            .call_tool(CallToolRequestParams::new("list_devices"))
            .await
            .expect("benchmark call");
        std::hint::black_box(result);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = percentile(&samples, 50);
    let p95 = percentile(&samples, 95);
    println!("in-memory MCP list_devices: p50={p50:?}, p95={p95:?}, n=1000");
    assert!(
        p95 < Duration::from_millis(10),
        "Phase 4 mock MCP overhead target exceeded: {p95:?}"
    );

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let index = (samples.len() * percentile).div_ceil(100).saturating_sub(1);
    samples[index]
}

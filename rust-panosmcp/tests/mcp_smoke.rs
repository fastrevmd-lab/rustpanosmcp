//! In-memory MCP client/server Phase 1 discovery test.

use rmcp::ServiceExt;
use rust_panosmcp::PanosMcpServer;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::PanosService,
};
use std::path::Path;

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
async fn client_discovers_exactly_the_four_phase_one_tools() {
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
    assert_eq!(
        names,
        [
            "execute_panos_op",
            "gather_device_facts",
            "get_panos_config",
            "list_devices"
        ]
    );

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

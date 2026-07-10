//! In-memory MCP client/server initialization smoke test.

use rmcp::ServiceExt;
use rust_panosmcp::PanosMcpServer;

#[tokio::test]
async fn mock_client_initializes_and_observes_no_phase_zero_tools() {
    let (server_transport, client_transport) = tokio::io::duplex(4096);

    let server_task = tokio::spawn(async move {
        PanosMcpServer
            .serve(server_transport)
            .await
            .expect("server initialization should succeed")
            .waiting()
            .await
    });

    let client =
        ().serve(client_transport)
            .await
            .expect("mock client initialization should succeed");

    let info = client
        .peer_info()
        .expect("server info should be available after initialization");
    assert_eq!(info.server_info.name, "rust-panosmcp");

    let tools = client
        .list_tools(None)
        .await
        .expect("the empty Phase 0 tool list should be available");
    assert!(tools.tools.is_empty());

    client
        .cancel()
        .await
        .expect("client shutdown should succeed");
    server_task.abort();
}

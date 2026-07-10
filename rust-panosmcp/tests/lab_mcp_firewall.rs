//! Explicitly opt-in full MCP-to-PAN-OS validation against a real lab device.

use rmcp::{ServiceExt, model::CallToolRequestParams};
use rust_panosmcp::PanosMcpServer;
use rust_panosmcp_core::{inventory::Inventory, tools::PanosService};
use serde_json::{Map, Value, json};
use std::path::PathBuf;

fn arguments(value: Value) -> Map<String, Value> {
    value.as_object().expect("object arguments").clone()
}

async fn call_json(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &'static str,
    input: Value,
) -> Value {
    let result = client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(arguments(input)))
        .await
        .expect("MCP tool request");
    assert_ne!(
        result.is_error,
        Some(true),
        "{tool} returned an MCP tool error"
    );
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .expect("text result");
    serde_json::from_str(&text.text).expect("JSON tool result")
}

#[tokio::test]
#[ignore = "requires PANOS_LAB_INVENTORY, PANOS_LAB_DEVICE, network access, and its referenced API-key secret"]
async fn all_phase_one_tools_succeed_through_mcp_on_lab_firewall() {
    let inventory_path = std::env::var_os("PANOS_LAB_INVENTORY")
        .map(PathBuf::from)
        .expect("PANOS_LAB_INVENTORY must name an absolute Phase 1 inventory path");
    let device = std::env::var("PANOS_LAB_DEVICE")
        .expect("PANOS_LAB_DEVICE must name one exact inventory entry");
    let inventory = Inventory::load(inventory_path).expect("lab inventory");
    let handler = PanosMcpServer::new(PanosService::new(inventory).expect("PAN-OS service"));
    let (server_transport, client_transport) = tokio::io::duplex(2 * 1024 * 1024);
    let server = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("MCP server")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("MCP client");

    let devices = call_json(&client, "list_devices", json!({})).await;
    assert!(
        devices["devices"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| entry["name"] == device))
    );

    let facts = call_json(&client, "gather_device_facts", json!({"device": device})).await;
    assert!(facts["facts"]["hostname"].is_string());
    assert!(facts["facts"]["software_version"].is_string());

    let operation = call_json(
        &client,
        "execute_panos_op",
        json!({
            "device": device,
            "command": "<show><system><info/></system></show>",
            "max_bytes": 262144,
            "max_lines": 5000
        }),
    )
    .await;
    assert_eq!(operation["status"], "success");

    let config = call_json(
        &client,
        "get_panos_config",
        json!({
            "device": device,
            "source": "running",
            "xpath": "/config/devices",
            "max_bytes": 1048576,
            "max_lines": 20000
        }),
    )
    .await;
    assert_eq!(config["status"], "success");

    client.cancel().await.expect("MCP client shutdown");
    server.abort();
}

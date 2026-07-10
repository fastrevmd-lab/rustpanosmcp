//! Stdio entrypoint for the Phase 0 MCP server.

use rmcp::ServiceExt;
use rust_panosmcp::PanosMcpServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rust_panosmcp_core::observability::init_tracing();

    let service = PanosMcpServer
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    service.waiting().await?;

    Ok(())
}

//! Stdio entrypoint for the Phase 1 read-only MCP server.

use clap::Parser;
use rmcp::ServiceExt;
use rust_panosmcp::PanosMcpServer;
use rust_panosmcp_core::{inventory::Inventory, tools::PanosService};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about = "Secure, async MCP server for PAN-OS firewalls")]
struct Cli {
    /// Validated JSON device inventory.
    #[arg(short = 'f', long, default_value = "devices.json")]
    device_mapping: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rust_panosmcp_core::observability::init_tracing();
    let cli = Cli::parse();
    let inventory = Inventory::load(&cli.device_mapping)?;
    tracing::info!(
        path = %inventory.source().display(),
        devices = inventory.metadata().len(),
        "validated PAN-OS inventory"
    );
    let handler = PanosMcpServer::new(PanosService::new(inventory)?);
    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    service.waiting().await?;
    Ok(())
}

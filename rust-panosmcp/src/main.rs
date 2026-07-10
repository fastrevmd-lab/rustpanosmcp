//! Process entrypoint for local stdio and bearer-protected remote MCP.

use clap::Parser;
use rmcp::ServiceExt;
use rust_panosmcp::{
    PanosMcpServer, RuntimeState,
    cli::{Cli, Command, Transport},
    cli_validate,
    http_transport::{self, HttpOptions},
    tls, token_cmd,
};
use rust_panosmcp_core::inventory::Inventory;
use std::net::{IpAddr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rust_panosmcp_core::observability::init_tracing();
    let cli = Cli::parse();

    if let Some(Command::Token { action }) = cli.command {
        let inventory = Inventory::load(&cli.device_mapping)?;
        let known_devices = inventory
            .metadata()
            .into_iter()
            .map(|device| device.name)
            .collect::<Vec<_>>();
        token_cmd::run(action, &known_devices)?;
        return Ok(());
    }

    cli_validate::validate(&cli)?;
    let tokens = (cli.transport == Transport::StreamableHttp)
        .then_some(cli.tokens_file.as_deref())
        .flatten();
    let runtime = RuntimeState::load(&cli.device_mapping, tokens)?;
    tracing::info!(
        inventory = %runtime.inventory_path().display(),
        devices = runtime.snapshot().service.list_devices().devices.len(),
        authenticated = runtime.snapshot().tokens.is_some(),
        "validated PAN-OS runtime"
    );
    spawn_reload_handler(runtime.clone())?;

    match cli.transport {
        Transport::Stdio => {
            let service = PanosMcpServer::from_runtime(runtime)
                .serve((tokio::io::stdin(), tokio::io::stdout()))
                .await?;
            service.waiting().await?;
        }
        Transport::StreamableHttp => {
            let ip: IpAddr = cli.host.parse()?;
            let address = SocketAddr::new(ip, cli.port);
            let listener_tls = match (cli.tls_cert.as_deref(), cli.tls_key.as_deref()) {
                (Some(cert), Some(key)) => Some(tls::load(cert, key)?),
                (None, None) => None,
                _ => unreachable!("CLI refusal matrix validated the TLS pair"),
            };
            let options = HttpOptions {
                port: cli.port,
                tls: listener_tls.is_some(),
                allowed_hosts: cli.allowed_host,
                allowed_origins: cli.allowed_origin,
                ip_rate_per_minute: cli.ip_rate_per_minute,
                token_rate_per_minute: cli.token_rate_per_minute,
                request_body_limit: cli.request_body_limit,
            };
            http_transport::serve(runtime, address, options, listener_tls).await?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn spawn_reload_handler(runtime: RuntimeState) -> Result<(), std::io::Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            match runtime.reload() {
                Ok(()) => tracing::info!("atomically reloaded inventory and token store"),
                Err(error) => tracing::error!(%error, "reload refused; retaining previous runtime"),
            }
        }
    });
    Ok(())
}

#[cfg(not(unix))]
fn spawn_reload_handler(_runtime: RuntimeState) -> Result<(), std::io::Error> {
    Ok(())
}

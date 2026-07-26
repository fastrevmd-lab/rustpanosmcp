//! Process entrypoint for local stdio and bearer-protected remote MCP.

use clap::Parser;
use rmcp::ServiceExt;
use rust_panosmcp::{
    PanosMcpServer, RuntimeState,
    cli::{Cli, Command, StateAction, StateDisposition, Transport},
    cli_validate,
    http_transport::{self, HttpOptions},
    tls, token_cmd,
};
use rust_panosmcp_core::inventory::Inventory;
use std::net::{IpAddr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let audit_format = rust_panosmcp_core::observability::AuditFormat::parse(&cli.audit_format);
    let redaction = if let Some(ref policy) = cli.audit_redact {
        Some(rust_panosmcp_core::observability::AuditRedaction::parse(
            policy,
            cli.audit_hmac_key_file.as_deref(),
        )?)
    } else {
        None
    };
    let audit_cfg = rust_panosmcp_core::observability::AuditConfig {
        format: audit_format,
        audit_log_file: cli.audit_log_file.clone(),
        redaction,
        journald: cli.audit_journald,
    };
    rust_panosmcp_core::observability::init_tracing(&audit_cfg)?;

    if let Some(command) = cli.command {
        match command {
            Command::Token { action } => {
                let known_devices = Inventory::device_names(&cli.device_mapping)?;
                token_cmd::run(action, &known_devices)?;
            }
            Command::State {
                action:
                    StateAction::Resolve {
                        state_file,
                        operation_id,
                        disposition,
                        confirmation,
                    },
            } => {
                let disposition = match disposition {
                    StateDisposition::Committed => {
                        rust_panosmcp_core::mutation::RecoveryDisposition::Committed
                    }
                    StateDisposition::Discarded => {
                        rust_panosmcp_core::mutation::RecoveryDisposition::Discarded
                    }
                };
                let output = rust_panosmcp_core::mutation::resolve_persisted_operation(
                    &state_file,
                    &operation_id,
                    disposition,
                    &confirmation,
                )?;
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
        }
        return Ok(());
    }

    cli_validate::validate(&cli)?;
    let tokens = (cli.transport == Transport::StreamableHttp)
        .then_some(cli.tokens_file.as_deref())
        .flatten();
    let runtime =
        RuntimeState::load_with_state(&cli.device_mapping, tokens, cli.state_file.as_deref())?;
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
                max_inflight_requests: cli.max_inflight_requests,
                max_inflight_requests_per_token: cli.max_inflight_requests_per_token,
                max_inflight_requests_per_target: cli.max_inflight_requests_per_target,
                max_sessions: cli.max_sessions,
                max_sessions_per_token: cli.max_sessions_per_token,
            };
            http_transport::serve(runtime, address, options, cli.enable_metrics, listener_tls)
                .await?;
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

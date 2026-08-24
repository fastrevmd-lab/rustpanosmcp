//! Process entrypoint for local stdio and bearer-protected remote MCP.

use clap::Parser;
use rmcp::ServiceExt;
use rust_panosmcp::{
    PanosMcpServer, RuntimeState,
    cli::{Cli, Command, StateAction, StateDisposition, Transport},
    cli_validate,
    http_transport::{self, HttpOptions},
    token_cmd,
};
use rust_panosmcp_core::inventory::Inventory;
use std::net::{IpAddr, SocketAddr};

/// Scan for stale secret files and warn if any are found.
///
/// Checks both /etc/rust-panosmcp and /var/lib/rust-panosmcp for superseded
/// tokens, retired TLS keys, and backup files. Warns but does not fail — a
/// stale file should not block startup.
fn check_stale_secrets(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    use mecmcp_auth::find_stale_secrets;
    use std::path::Path;

    // Live files in /etc/rust-panosmcp that should not be flagged as stale.
    //
    // `tokens.json` IS listed here even though /etc is the legacy location. It has
    // to be: find_stale_secrets classifies a superseded file by its live-name
    // prefix, so dropping "tokens.json" would stop `tokens.json.pre-17` and friends
    // being recognised — and it would NOT cause the bare legacy store to be
    // reported, because the helper only knows backup suffixes, retired keys, and
    // prefixed superseded files. A bare `tokens.json` matches none of those.
    //
    // The legacy store is therefore reported explicitly, below.
    let config_live_files = [
        "devices.json",
        "devices.json.example",
        "audit-hmac.key",
        "tokens.json",
    ];

    // Live files in /var/lib/rust-panosmcp that should not be flagged as stale.
    let state_live_files = [
        "tokens.json",
        "mutation-state.json",
        "audit.jsonl",
        "evidence-outbox.ndjson",
        "evidence-ledger.ndjson",
    ];

    // Check /etc/rust-panosmcp
    let config_dir = cli
        .device_mapping
        .parent()
        .unwrap_or_else(|| Path::new("/etc/rust-panosmcp"));
    let config_stale = find_stale_secrets(config_dir, &config_live_files);

    // Check /var/lib/rust-panosmcp
    let state_dir = cli
        .state_file
        .as_ref()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| Path::new("/var/lib/rust-panosmcp"));
    let state_stale = find_stale_secrets(state_dir, &state_live_files);

    // Also check for TLS key if configured
    let mut tls_stale = Vec::new();
    if let Some(ref key_path) = cli.tls_key
        && let Some(tls_dir) = key_path.parent()
    {
        // Only flag keys in the same directory, not the key itself.
        // TLS keys live under /etc, so use the config live list.
        let key_file_name = key_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("server.key");
        let mut extended_live = config_live_files.to_vec();
        extended_live.push(key_file_name);
        tls_stale = find_stale_secrets(tls_dir, &extended_live);
    }

    // The legacy token store itself. find_stale_secrets cannot classify a bare
    // live-named file, so detect it by path. #125 moved the store to /var/lib;
    // a copy left in /etc is a duplicated bearer-token secret on disk, and /etc
    // is read-only to the service under ProtectSystem=strict so it is not the
    // file being maintained.
    // Only when it is NOT the store this process is actually using. A source or
    // Phase 2 deployment may legitimately run with
    // `--tokens-file /etc/rust-panosmcp/tokens.json`; warning there would tell
    // an operator to securely erase their live credentials, and following the
    // advice would leave the next start with no tokens at all. A warning that
    // can destroy a working deployment is worse than the duplicate it reports.
    let legacy_tokens = Path::new("/etc/rust-panosmcp/tokens.json");
    let configured_is_legacy = cli
        .tokens_file
        .as_deref()
        .is_some_and(|p| p.as_os_str() == legacy_tokens.as_os_str());
    if legacy_tokens.is_file() && !configured_is_legacy {
        tracing::warn!(
            path = %legacy_tokens.display(),
            "legacy token store present and NOT the configured store; migrate deliberately \
             and securely erase this copy — it may hold revoked credentials"
        );
    }

    let total_stale = config_stale.len() + state_stale.len() + tls_stale.len();
    if total_stale > 0 {
        tracing::warn!(
            "found {} potentially stale secret file(s) - review and remove manually if unused:",
            total_stale
        );
        for secret in config_stale.iter().chain(&state_stale).chain(&tls_stale) {
            tracing::warn!("  {} ({:?})", secret.path.display(), secret.reason);
        }
        tracing::warn!(
            "stale tokens may still hold revoked credentials; \
             retired TLS keys can decrypt captured traffic"
        );
    }

    Ok(())
}

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
                // The shared recovery function takes the size cap explicitly, so a
                // deployment that raised max_state_bytes can still open the file
                // this repairs.
                let output = rust_panosmcp_core::mutation::resolve_persisted_operation(
                    &state_file,
                    &operation_id,
                    disposition,
                    &confirmation,
                    rust_panosmcp_core::mutation::PublicOperationLimits::default(),
                )?;
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
        }
        return Ok(());
    }

    cli_validate::validate(&cli)?;

    // Lab mode removes two-person control, so say so where an operator will
    // actually see it. Reading it off flags typed weeks ago is not visibility.
    if cli.lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets are approved on creation with no second principal. \
             Records carry approval_waiver=lab-mode. Do not run this against production devices."
        );
    }
    // Emit the plane-owned device protection posture on the normal log target,
    // not "audit": the audit stream carries one record per tool call with a fixed
    // schema (request_id, caller, tool, action, result), and a startup banner has
    // none of those fields. An audit-target banner pollutes the stream with
    // something no consumer can interpret as an action record.
    if cli.allow_plane_owned_writes {
        tracing::warn!(
            "allow-plane-owned-writes enabled: commit_panos_candidate on devices owned by \
             management planes (Panorama, Strata Cloud Manager) will proceed with a warning \
             instead of refusal. Changes to plane-owned devices may be overwritten at the \
             next push. This flag is for break-glass scenarios only."
        );
    } else {
        tracing::info!(
            "plane-owned device protection active: commit_panos_candidate refuses operations \
             on devices whose config_authority is not local or unknown"
        );
    }
    let tokens = (cli.transport == Transport::StreamableHttp)
        .then_some(cli.tokens_file.as_deref())
        .flatten();
    // Built before the runtime because the coordinator inside it takes the
    // recorder, and started eagerly so a misconfiguration stops the server here
    // rather than at the first change.
    let evidence = match cli.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let transport = std::sync::Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    cli.evidence.ca_file(),
                    provider,
                )?,
            );
            Some(mecmcp_audit::EvidenceService::start_with_transport(
                config, transport,
            )?)
        }
        Ok(None) => None,
        Err(error) => return Err(format!("SSDF evidence configuration: {error}").into()),
    };

    let runtime = RuntimeState::load_with_state(
        &cli.device_mapping,
        tokens,
        cli.state_file.as_deref(),
        cli.lab_mode,
        Some(cli.approval_timeout_secs),
        cli.allow_plane_owned_writes,
        evidence
            .as_ref()
            .map(mecmcp_audit::EvidenceService::recorder),
    )?;
    tracing::info!(
        inventory = %runtime.inventory_path().display(),
        devices = runtime.snapshot().service.list_devices(None).devices.len(),
        authenticated = runtime.snapshot().tokens.is_some(),
        "validated PAN-OS runtime"
    );

    // Scan for stale secret files in config and state directories.
    check_stale_secrets(&cli)?;

    spawn_reload_handler(runtime.clone())?;

    // Bound rather than propagated with `?`, so the evidence flush below runs
    // whichever way serving ended. `EvidenceService::Drop` deliberately does not
    // spool -- a Drop performing network I/O turns teardown into an
    // unpredictable stall -- so returning the error directly would lose every
    // proposal and approval the recorder still held, on exactly the controlled
    // failure the trail exists to describe.
    let served: Result<(), Box<dyn std::error::Error>> = async {
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
                    (Some(cert), Some(key)) => {
                        let provider =
                            std::sync::Arc::new(rustls::crypto::ring::default_provider());
                        Some(mecmcp_transport::tls::load(cert, key, provider)?)
                    }
                    (None, None) => None,
                    _ => unreachable!("CLI refusal matrix validated the TLS pair"),
                };
                let options = HttpOptions {
                    port: cli.port,
                    tls: listener_tls.is_some(),
                    allow_insecure_bind: cli.allow_insecure_bind,
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
    .await;

    // Deliver what is still spooled before leaving. The drain ships on an
    // interval, so without this every record since the last tick waits for the
    // next start, and a segment still open has never been spooled at all.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
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

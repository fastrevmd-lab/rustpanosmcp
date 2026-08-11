//! Bearer-protected MCP Streamable HTTP transport using mecmcp-transport 0.8.0.

use crate::{PanosMcpServer, RuntimeState};
use mecmcp_auth::{BearerSyntax, CallerCtx, NoGrant};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy, HttpServeError,
    HttpShutdown, HttpTransportBuildError, HttpTransportConfig, LimitsConfig,
    MalformedArgumentsPolicy, TargetField, ToolScopePreflight, TransportIdentity,
    build_streamable_http_router, loopback_origins, serve_router,
};
use rust_panosmcp_auth::MUTATION_TOOLS;
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;

/// Validated transport settings.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Listening port, used to build strict loopback Origin entries.
    pub port: u16,
    /// Whether the listener itself uses TLS.
    pub tls: bool,
    /// Additional exact Host authorities.
    pub allowed_hosts: Vec<String>,
    /// Additional exact browser origins.
    pub allowed_origins: Vec<String>,
    /// Per-source-IP requests per minute.
    pub ip_rate_per_minute: u32,
    /// Per-token requests per minute.
    pub token_rate_per_minute: u32,
    /// Maximum request body bytes.
    pub request_body_limit: usize,
    /// Maximum concurrent in-flight requests across all callers.
    pub max_inflight_requests: usize,
    /// Maximum concurrent in-flight requests per bearer token.
    pub max_inflight_requests_per_token: usize,
    /// Maximum concurrent in-flight requests per target device.
    pub max_inflight_requests_per_target: usize,
    /// Maximum concurrent MCP sessions.
    pub max_sessions: usize,
    /// Maximum concurrent MCP sessions per bearer token.
    pub max_sessions_per_token: usize,
}

/// Build the complete shared HTTP router with PAN-OS-owned identity and scope fields.
pub fn build_router(
    runtime: RuntimeState,
    options: HttpOptions,
    enable_metrics: bool,
    shutdown: CancellationToken,
) -> Result<(axum::Router, HttpShutdown), HttpTransportBuildError> {
    let identity =
        TransportIdentity::new("panosmcp", "panos", "rust-panosmcp", ["device", "devices"]);

    // Convert per-minute rates to per-second for mecmcp-transport's token bucket.
    // Burst = rate to allow the full per-minute quota within the first second.
    let limits = LimitsConfig {
        max_request_body_bytes: options.request_body_limit,
        max_requests_per_second_per_ip: u64::from(options.ip_rate_per_minute),
        max_request_burst_per_ip: u64::from(options.ip_rate_per_minute),
        max_requests_per_second_per_token: u64::from(options.token_rate_per_minute),
        max_request_burst_per_token: u64::from(options.token_rate_per_minute),
        max_sessions: options.max_sessions,
        max_sessions_per_token: options.max_sessions_per_token,
        max_inflight_requests: options.max_inflight_requests,
        max_inflight_requests_per_token: options.max_inflight_requests_per_token,
        max_inflight_requests_per_device: options.max_inflight_requests_per_target,
        session_idle_timeout_secs: 300,
        session_max_lifetime_secs: 3600,
    };

    // Build complete Origin list including loopback
    let all_origins = loopback_origins(options.port, options.tls, options.allowed_origins.clone());

    let mut config = HttpTransportConfig::<NoGrant>::new(
        identity.clone(),
        limits.clone(),
        HostOriginPolicy::enforced(options.allowed_hosts.clone(), all_origins),
        shutdown,
    )
    .with_metrics(enable_metrics);

    // Add bearer boundary if tokens are present
    let snapshot = runtime.snapshot();
    if snapshot.tokens.is_some() {
        let auth_runtime = runtime.clone();
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
            let snapshot = auth_runtime.snapshot();
            let store = snapshot.tokens.as_ref()?;
            let entry = store.authenticate(candidate)?;
            // mecmcp-transport inserts CallerCtx<NoGrant> into extensions.
            // Manually construct from TokenEntry<MutationGrant> with grant: None.
            Some(CallerCtx::<NoGrant> {
                token_name: entry.name.clone(),
                devices: entry.devices.clone(),
                tools: entry.tools.clone(),
                grant: None,
                provider: entry.provider.clone(),
                provider_tier: entry.provider_tier,
                on_behalf_of: entry.on_behalf_of.clone(),
                actor_type: entry.actor_type,
            })
        });
        let preflight = ToolScopePreflight::new(
            MUTATION_TOOLS,
            [TargetField::scalar("device")],
            MalformedArgumentsPolicy::Deny,
        );
        let boundary =
            BearerBoundary::new(authenticator, BearerResponseProfile::detailed("panosmcp"))
                .with_preflight(preflight);
        config = config.with_bearer(boundary);
    }
    drop(snapshot);

    let service_factory = move || {
        let server = PanosMcpServer::from_runtime(runtime.clone());
        Ok::<_, std::io::Error>(server)
    };

    build_streamable_http_router(service_factory, config)
}

/// Serve until shutdown or listener failure.
pub async fn serve(
    runtime: RuntimeState,
    address: SocketAddr,
    options: HttpOptions,
    enable_metrics: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), HttpServeError> {
    let shutdown = CancellationToken::new();

    // Install signal handlers
    let signal_shutdown = shutdown.clone();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())
            .map_err(|e| HttpServeError::Serve { address, error: e })?;
        let mut sigint = signal(SignalKind::interrupt())
            .map_err(|e| HttpServeError::Serve { address, error: e })?;
        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("SIGTERM received");
                }
                _ = sigint.recv() => {
                    tracing::info!("SIGINT received");
                }
            }
            signal_shutdown.cancel();
        });
    }
    #[cfg(not(unix))]
    {
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Ctrl+C received");
            signal_shutdown.cancel();
        });
    }

    let (router, shutdown_token) = build_router(runtime, options, enable_metrics, shutdown)
        .map_err(|error| HttpServeError::Serve {
            address,
            error: std::io::Error::other(error.to_string()),
        })?;

    // Graceful shutdown timeout: 10 seconds for in-flight requests/SSE streams.
    // LXC 608's systemd unit has TimeoutStopSec=30s, so this drain completes well
    // before systemd's SIGKILL. While any SSE stream is open (e.g., an MCP session),
    // shutdown takes the full timeout rather than ending immediately.
    let shutdown_timeout = std::time::Duration::from_secs(10);
    serve_router(router, address, tls, shutdown_token, shutdown_timeout).await
}

#[cfg(test)]
mod tests {
    use mecmcp_auth::{ScopeSet, TokenDigest, TokenEntry, TokenStore};

    #[test]
    fn token_store_fixture_authenticates_without_exposing_digest() {
        let store: TokenStore = TokenStore::try_new(vec![TokenEntry {
            name: "test".to_owned(),
            digest: TokenDigest::from_secret("secret"),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at: chrono::DateTime::from_timestamp(1, 0).expect("timestamp"),
            expires_at: None,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Unknown,
        }])
        .expect("store");
        assert_eq!(
            store.authenticate("secret").map(|entry| &entry.name),
            Some(&"test".to_owned())
        );
    }
}

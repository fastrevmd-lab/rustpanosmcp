//! Bearer-protected MCP Streamable HTTP transport using mecmcp-transport.

use crate::{PanosMcpServer, RuntimeState};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use mecmcp_transport::{
    ConcurrencyState, LimitedSessionManager, LimitsConfig, OptionalPreflight, PrometheusRuntime,
    ScopePreflight, TransportIdentity, apply_body_limit, apply_rate_limit, concurrency_middleware,
    preflight::run_preflight,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use rust_panosmcp_auth::{CallerContext, MUTATION_TOOLS, parse_bearer_header};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};

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

/// Listener setup or runtime failure.
#[derive(Debug, thiserror::Error)]
pub enum HttpTransportError {
    /// Binding the TCP listener failed.
    #[error("failed to bind {address}: {error}")]
    Bind {
        /// Requested address.
        address: SocketAddr,
        /// Underlying socket error.
        #[source]
        error: std::io::Error,
    },
    /// HTTP server exited with an error.
    #[error("Streamable HTTP server failed: {0}")]
    Serve(#[from] std::io::Error),
}

/// PAN-OS scope preflight implementation.
struct PanosPreflight;

impl ScopePreflight for PanosPreflight {
    fn check(&self, body: &[u8], caller: &mecmcp_auth::CallerCtx) -> Result<(), String> {
        if request_exceeds_scope(body, caller) {
            Err("insufficient_scope".to_owned())
        } else {
            Ok(())
        }
    }
}

fn request_exceeds_scope(bytes: &[u8], caller: &mecmcp_auth::CallerCtx) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| tool_call_exceeds_scope(value, caller)),
        value => tool_call_exceeds_scope(&value, caller),
    }
}

fn tool_call_exceeds_scope(value: &Value, caller: &mecmcp_auth::CallerCtx) -> bool {
    if value.get("method").and_then(Value::as_str) != Some("tools/call") {
        return false;
    }
    let Some(params) = value.get("params") else {
        return false;
    };
    let Some(tool) = params.get("name").and_then(Value::as_str) else {
        return false;
    };
    if !caller.tools.allows_tool(tool, MUTATION_TOOLS) {
        return true;
    }
    params
        .get("arguments")
        .and_then(|arguments| arguments.get("device"))
        .and_then(Value::as_str)
        .is_some_and(|device| !caller.devices.allows(device))
}

#[derive(Clone)]
struct SecurityState {
    runtime: RuntimeState,
    identity: TransportIdentity,
    preflight: OptionalPreflight,
    body_limit: usize,
}

async fn security_boundary(
    axum::extract::State(state): axum::extract::State<SecurityState>,
    request: Request,
    next: Next,
) -> Response {
    // Bearer authentication
    let snapshot = state.runtime.snapshot();
    let caller = if let Some(store) = &snapshot.tokens {
        let Some(candidate) = bearer_candidate(request.headers()) else {
            return unauthorized(&state.identity.bearer_realm);
        };
        let Some(entry) = store.authenticate(candidate) else {
            return unauthorized(&state.identity.bearer_realm);
        };
        Some(CallerContext::from(entry))
    } else {
        None
    };
    drop(snapshot);

    // Buffer and limit body size
    let (mut parts, body) = request.into_parts();
    let body_bytes = match to_bytes(body, state.body_limit).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return payload_too_large();
        }
    };

    // Scope preflight check if caller is present
    if let Some(caller) = &caller {
        let caller_ctx = mecmcp_auth::CallerCtx {
            token_name: caller.token_name.clone(),
            devices: caller.devices.clone(),
            tools: caller.tools.clone(),
            grant: None,
            provider: caller.provider.clone(),
            provider_tier: caller.provider_tier,
            on_behalf_of: caller.on_behalf_of.clone(),
            actor_type: caller.actor_type,
        };
        if let Err(reason) = run_preflight(&state.preflight, &body_bytes, &caller_ctx) {
            return forbidden(&state.identity.bearer_realm, &reason);
        }
        // Insert CallerCtx into extensions for apply_rate_limit
        parts.extensions.insert(caller_ctx);
    }

    // Insert local caller context into extensions for downstream handlers
    if let Some(caller) = caller {
        parts.extensions.insert(caller);
    }
    let request = Request::from_parts(parts, Body::from(body_bytes));

    next.run(request).await
}

fn bearer_candidate(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    parse_bearer_header(value.to_str().ok()?).ok()
}

fn unauthorized(realm: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            format!("Bearer realm=\"{realm}\", error=\"invalid_token\""),
        )],
        axum::Json(json!({"error": "invalid_token"})),
    )
        .into_response()
}

fn forbidden(realm: &str, reason: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [(
            header::WWW_AUTHENTICATE,
            format!("Bearer realm=\"{realm}\", error=\"{reason}\""),
        )],
        axum::Json(json!({"error": reason})),
    )
        .into_response()
}

fn payload_too_large() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        axum::Json(json!({"error": "request_too_large"})),
    )
        .into_response()
}

/// Build the fully protected `/mcp` router. Exposed for integration tests.
pub fn build_router(runtime: RuntimeState, options: HttpOptions, enable_metrics: bool) -> Router {
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

    // Built from `streamable_http_server_config` rather than
    // `StreamableHttpServerConfig::default()`. rmcp 3 added its own
    // `max_request_body_bytes`, defaulting to 4 MiB and enforced *inside* rmcp
    // after `apply_body_limit` has already accepted the request. On `default()`
    // every request between 4 MiB and `--request-body-limit` would 413 from a
    // limit that appears nowhere in this server's config — and staged PAN-OS
    // candidate configs are exactly the payload that gets large.
    let mut config = mecmcp_transport::streamable_http_server_config(&limits);
    config = config.with_allowed_origins(origins(&options));
    config.allowed_hosts.extend(options.allowed_hosts);

    let session_mgr = LimitedSessionManager::new(LocalSessionManager::default(), &limits);
    let conc = ConcurrencyState::new(
        &limits,
        identity.target_keys.clone(),
        Some(session_mgr.tracker()),
    );

    let service = StreamableHttpService::new(
        {
            let runtime = runtime.clone();
            move || Ok::<_, std::io::Error>(PanosMcpServer::from_runtime(runtime.clone()))
        },
        session_mgr,
        config,
    );

    let security = SecurityState {
        runtime,
        identity: identity.clone(),
        preflight: Some(Arc::new(PanosPreflight)),
        body_limit: options.request_body_limit,
    };

    // Layer order (innermost to outermost in request flow):
    // 1. Concurrency middleware (enforces session/inflight caps)
    // 2. Rate limiting (enforces per-IP/token RPS)
    // 3. Auth + scope preflight (validates bearer token and scope)
    // 4. Body limit (rejects oversized bodies before buffering)
    let rmcp_router = Router::new().nest_service("/mcp", service);

    let mut app = rmcp_router.layer(middleware::from_fn_with_state(conc, concurrency_middleware));
    app = apply_rate_limit(app, &limits);
    app = app.layer(middleware::from_fn_with_state(security, security_boundary));
    app = apply_body_limit(app, &limits);

    if enable_metrics {
        let metrics_runtime =
            PrometheusRuntime::install(&identity.metric_prefix, &identity.server_label)
                .expect("Prometheus metrics initialization");
        app = app.merge(metrics_runtime.router());
    }

    app
}

fn origins(options: &HttpOptions) -> Vec<String> {
    let scheme = if options.tls { "https" } else { "http" };
    let mut origins = vec![
        format!("{scheme}://localhost:{}", options.port),
        format!("{scheme}://127.0.0.1:{}", options.port),
        format!("{scheme}://[::1]:{}", options.port),
    ];
    origins.extend(options.allowed_origins.iter().cloned());
    origins.sort();
    origins.dedup();
    origins
}

/// Serve until shutdown or listener failure.
pub async fn serve(
    runtime: RuntimeState,
    address: SocketAddr,
    options: HttpOptions,
    enable_metrics: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), HttpTransportError> {
    let app = build_router(runtime, options, enable_metrics);
    if let Some(config) = tls {
        tracing::info!(%address, "Streamable HTTP listening with TLS");
        let config = axum_server::tls_rustls::RustlsConfig::from_config(config);
        axum_server::bind_rustls(address, config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
        return Ok(());
    }

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| HttpTransportError::Bind { address, error })?;
    tracing::info!(%address, "Streamable HTTP listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_auth::{ScopeSet, TokenDigest, TokenEntry, TokenStore};

    fn caller(tools: ScopeSet, devices: ScopeSet) -> mecmcp_auth::CallerCtx {
        mecmcp_auth::CallerCtx {
            token_name: "test".to_owned(),
            tools,
            devices,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Unknown,
        }
    }

    #[test]
    fn scope_preflight_checks_exact_tool_and_device() {
        let limited = caller(
            ScopeSet::Allowlist(vec!["get_panos_config".to_owned()]),
            ScopeSet::Allowlist(vec!["fw-a".to_owned()]),
        );
        assert!(!request_exceeds_scope(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_panos_config","arguments":{"device":"fw-a"}}}"#,
            &limited,
        ));
        assert!(request_exceeds_scope(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_panos_op","arguments":{"device":"fw-a"}}}"#,
            &limited,
        ));
        let wildcard = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);
        assert!(request_exceeds_scope(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"stage_panos_config","arguments":{"device":"fw-a"}}}"#,
            &wildcard,
        ));
        assert!(request_exceeds_scope(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_panos_config","arguments":{"device":"fw-b"}}}"#,
            &limited,
        ));
    }

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

//! Bearer-protected MCP Streamable HTTP transport and boundary controls.

use crate::{PanosMcpServer, RuntimeState};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rust_panosmcp_auth::{CallerContext, parse_bearer_header};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_IP_WINDOWS: usize = 8_192;
const MAX_TOKEN_WINDOWS: usize = 2_048;

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

#[derive(Debug, Clone)]
struct SecurityState {
    runtime: RuntimeState,
    body_limit: usize,
    ip_limiter: FixedWindowLimiter,
    token_limiter: FixedWindowLimiter,
}

#[derive(Debug, Clone)]
struct FixedWindowLimiter {
    limit: u32,
    maximum_keys: usize,
    windows: Arc<Mutex<HashMap<String, Window>>>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    count: u32,
}

impl FixedWindowLimiter {
    fn new(limit: u32, maximum_keys: usize) -> Self {
        Self {
            limit,
            maximum_keys,
            windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn check(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut windows = self.windows.lock().await;
        if windows.len() >= self.maximum_keys && !windows.contains_key(key) {
            windows.retain(|_, window| now.duration_since(window.started) < RATE_WINDOW);
            if windows.len() >= self.maximum_keys {
                return Err(RATE_WINDOW.as_secs());
            }
        }
        let window = windows.entry(key.to_owned()).or_insert(Window {
            started: now,
            count: 0,
        });
        let elapsed = now.duration_since(window.started);
        if elapsed >= RATE_WINDOW {
            *window = Window {
                started: now,
                count: 1,
            };
            return Ok(());
        }
        if window.count >= self.limit {
            return Err((RATE_WINDOW - elapsed).as_secs().max(1));
        }
        window.count += 1;
        Ok(())
    }
}

/// Build the fully protected `/mcp` router. Exposed for integration tests.
pub fn build_router(runtime: RuntimeState, options: HttpOptions) -> Router {
    let mut config = StreamableHttpServerConfig::default();
    config = config.with_allowed_origins(origins(&options));
    config.allowed_hosts.extend(options.allowed_hosts);

    let service = StreamableHttpService::new(
        {
            let runtime = runtime.clone();
            move || Ok::<_, std::io::Error>(PanosMcpServer::from_runtime(runtime.clone()))
        },
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let security = SecurityState {
        runtime,
        body_limit: options.request_body_limit,
        ip_limiter: FixedWindowLimiter::new(options.ip_rate_per_minute, MAX_IP_WINDOWS),
        token_limiter: FixedWindowLimiter::new(options.token_rate_per_minute, MAX_TOKEN_WINDOWS),
    };
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(security, security_boundary))
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
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), HttpTransportError> {
    let app = build_router(runtime, options);
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

async fn security_boundary(
    axum::extract::State(state): axum::extract::State<SecurityState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned());

    if let Err(retry) = state.ip_limiter.check(&source).await {
        return audited(
            too_many_requests(retry),
            started,
            &method,
            &path,
            &source,
            None,
        );
    }

    let snapshot = state.runtime.snapshot();
    let caller = if let Some(store) = &snapshot.tokens {
        let Some(candidate) = bearer_candidate(request.headers()) else {
            return audited(unauthorized(), started, &method, &path, &source, None);
        };
        let Some(entry) = store.authenticate(candidate) else {
            return audited(unauthorized(), started, &method, &path, &source, None);
        };
        let caller = CallerContext::from(entry);
        if let Err(retry) = state.token_limiter.check(&caller.token_name).await {
            return audited(
                too_many_requests(retry),
                started,
                &method,
                &path,
                &source,
                Some(&caller.token_name),
            );
        }
        Some(caller)
    } else {
        None
    };
    drop(snapshot);

    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, state.body_limit).await {
        Ok(body) => body,
        Err(_) => {
            return audited(
                payload_too_large(),
                started,
                &method,
                &path,
                &source,
                caller.as_ref().map(|value| value.token_name.as_str()),
            );
        }
    };
    if let Some(caller) = &caller
        && request_exceeds_scope(&body, caller)
    {
        return audited(
            forbidden(),
            started,
            &method,
            &path,
            &source,
            Some(&caller.token_name),
        );
    }
    request = Request::from_parts(parts, Body::from(body));
    if let Some(caller) = caller.clone() {
        request.extensions_mut().insert(caller);
    }

    let response = next.run(request).await;
    audited(
        response,
        started,
        &method,
        &path,
        &source,
        caller.as_ref().map(|value| value.token_name.as_str()),
    )
}

fn bearer_candidate(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    parse_bearer_header(value.to_str().ok()?).ok()
}

fn request_exceeds_scope(bytes: &[u8], caller: &CallerContext) -> bool {
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

fn tool_call_exceeds_scope(value: &Value, caller: &CallerContext) -> bool {
    if value.get("method").and_then(Value::as_str) != Some("tools/call") {
        return false;
    }
    let Some(params) = value.get("params") else {
        return false;
    };
    let Some(tool) = params.get("name").and_then(Value::as_str) else {
        return false;
    };
    if !caller.tools.allows(tool) {
        return true;
    }
    params
        .get("arguments")
        .and_then(|arguments| arguments.get("device"))
        .and_then(Value::as_str)
        .is_some_and(|device| !caller.devices.allows(device))
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            "Bearer realm=\"rust-panosmcp\", error=\"invalid_token\"",
        )],
        axum::Json(json!({"error": "invalid_token"})),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        [(
            header::WWW_AUTHENTICATE,
            "Bearer realm=\"rust-panosmcp\", error=\"insufficient_scope\"",
        )],
        axum::Json(json!({"error": "insufficient_scope"})),
    )
        .into_response()
}

fn too_many_requests(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string())],
        axum::Json(json!({"error": "rate_limited"})),
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

fn audited(
    response: Response,
    started: Instant,
    method: &Method,
    path: &str,
    source: &str,
    token_name: Option<&str>,
) -> Response {
    tracing::info!(
        %method,
        path,
        source_ip = source,
        token_name = token_name.unwrap_or("anonymous"),
        status = response.status().as_u16(),
        duration_ms = started.elapsed().as_millis(),
        "MCP HTTP request"
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_panosmcp_auth::{ScopeSet, TokenDigest, TokenEntry, TokenStore};

    fn caller(tools: ScopeSet, devices: ScopeSet) -> CallerContext {
        CallerContext {
            token_name: "test".to_owned(),
            tools,
            devices,
        }
    }

    #[test]
    fn scope_preflight_checks_exact_tool_and_device() {
        let caller = caller(
            ScopeSet::Allowlist(vec!["get_panos_config".to_owned()]),
            ScopeSet::Allowlist(vec!["fw-a".to_owned()]),
        );
        assert!(!request_exceeds_scope(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_panos_config","arguments":{"device":"fw-a"}}}"#,
            &caller,
        ));
        assert!(request_exceeds_scope(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_panos_op","arguments":{"device":"fw-a"}}}"#,
            &caller,
        ));
        assert!(request_exceeds_scope(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_panos_config","arguments":{"device":"fw-b"}}}"#,
            &caller,
        ));
    }

    #[tokio::test]
    async fn limiter_enforces_fixed_window() {
        let limiter = FixedWindowLimiter::new(2, 4);
        assert!(limiter.check("one").await.is_ok());
        assert!(limiter.check("one").await.is_ok());
        assert!(limiter.check("one").await.is_err());
        assert!(limiter.check("two").await.is_ok());
    }

    #[test]
    fn token_store_fixture_authenticates_without_exposing_digest() {
        let store = TokenStore::new(vec![TokenEntry {
            name: "test".to_owned(),
            digest: TokenDigest::from_secret("secret"),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at_unix: 1,
        }])
        .expect("store");
        assert_eq!(
            store.authenticate("secret").map(|entry| &entry.name),
            Some(&"test".to_owned())
        );
    }
}

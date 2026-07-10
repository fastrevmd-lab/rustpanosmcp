//! MCP adapters and atomically reloadable runtime state for rust-panosmcp.

pub mod cli;
pub mod cli_validate;
pub mod http_transport;
pub mod tls;
pub mod token_cmd;

use arc_swap::ArcSwap;
use rmcp::{
    ServerHandler,
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, ContentBlock, Extensions, Implementation, ServerCapabilities, ServerInfo,
    },
    tool, tool_handler, tool_router,
};
use rust_panosmcp_auth::{CallerContext, TokenStore, TokenStoreFile};
use rust_panosmcp_core::{
    Result as CoreResult,
    inventory::Inventory,
    tools::{ExecutePanosOpInput, GatherDeviceFactsInput, GetPanosConfigInput, PanosService},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

/// Complete immutable runtime replaced in one atomic operation on reload.
#[derive(Debug)]
pub struct RuntimeSnapshot {
    /// Validated device service and reusable HTTPS pools.
    pub service: Arc<PanosService>,
    /// Validated bearer store for remote HTTP; absent for stdio/no-auth mode.
    pub tokens: Option<Arc<TokenStore>>,
}

/// Shared runtime plus its reload sources.
#[derive(Debug, Clone)]
pub struct RuntimeState {
    current: Arc<ArcSwap<RuntimeSnapshot>>,
    inventory_path: Arc<PathBuf>,
    token_path: Option<Arc<PathBuf>>,
}

impl RuntimeState {
    /// Load and fully validate inventory, clients, and optional tokens.
    pub fn load(
        inventory_path: impl AsRef<Path>,
        token_path: Option<&Path>,
    ) -> Result<Self, RuntimeLoadError> {
        let inventory_path = inventory_path.as_ref().to_path_buf();
        let token_path = token_path.map(Path::to_path_buf);
        let snapshot = load_snapshot(&inventory_path, token_path.as_deref())?;
        Ok(Self {
            current: Arc::new(ArcSwap::from_pointee(snapshot)),
            inventory_path: Arc::new(inventory_path),
            token_path: token_path.map(Arc::new),
        })
    }

    /// Construct an embedding/test runtime from already validated parts.
    #[must_use]
    pub fn from_parts(service: PanosService, tokens: Option<TokenStore>) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(RuntimeSnapshot {
                service: Arc::new(service),
                tokens: tokens.map(Arc::new),
            })),
            inventory_path: Arc::new(PathBuf::new()),
            token_path: None,
        }
    }

    /// Current consistent service/token snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    /// Build a complete replacement and publish it only after all validation.
    pub fn reload(&self) -> Result<(), RuntimeLoadError> {
        if self.inventory_path.as_os_str().is_empty() {
            return Err(RuntimeLoadError::Configuration(
                "embedded runtime has no reload source".to_owned(),
            ));
        }
        let replacement = load_snapshot(
            &self.inventory_path,
            self.token_path.as_ref().map(|path| path.as_path()),
        )?;
        self.current.store(Arc::new(replacement));
        Ok(())
    }

    /// Configured inventory path.
    #[must_use]
    pub fn inventory_path(&self) -> &Path {
        &self.inventory_path
    }

    /// Configured token path, when remote auth is enabled.
    #[must_use]
    pub fn token_path(&self) -> Option<&Path> {
        self.token_path.as_deref().map(PathBuf::as_path)
    }
}

fn load_snapshot(
    inventory_path: &Path,
    token_path: Option<&Path>,
) -> Result<RuntimeSnapshot, RuntimeLoadError> {
    let inventory = Inventory::load(inventory_path)?;
    let names: Vec<String> = inventory
        .metadata()
        .into_iter()
        .map(|device| device.name)
        .collect();
    let service = Arc::new(PanosService::new(inventory)?);
    let tokens = token_path
        .map(|path| TokenStoreFile::load(path, &names).map(Arc::new))
        .transpose()?;
    Ok(RuntimeSnapshot { service, tokens })
}

/// Startup/reload validation error.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeLoadError {
    /// Inventory or PAN-OS client validation failed.
    #[error(transparent)]
    Core(#[from] rust_panosmcp_core::PanosMcpError),
    /// Bearer-token file validation failed.
    #[error(transparent)]
    Tokens(#[from] rust_panosmcp_auth::TokenStoreFileError),
    /// Runtime configuration has no safe interpretation.
    #[error("runtime configuration error: {0}")]
    Configuration(String),
}

/// MCP server whose sessions share one atomically reloadable runtime.
#[derive(Debug, Clone)]
pub struct PanosMcpServer {
    runtime: RuntimeState,
    tool_router: rmcp::handler::server::tool::ToolRouter<Self>,
}

impl PanosMcpServer {
    /// Wrap one validated PAN-OS service for local stdio/embedding.
    #[must_use]
    pub fn new(service: PanosService) -> Self {
        Self::from_runtime(RuntimeState::from_parts(service, None))
    }

    /// Wrap shared atomically reloadable runtime for HTTP sessions.
    #[must_use]
    pub fn from_runtime(runtime: RuntimeState) -> Self {
        Self {
            runtime,
            tool_router: Self::tool_router(),
        }
    }

    fn to_call_result<T: Serialize>(
        result: CoreResult<T>,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        Ok(match result {
            Ok(value) => match serde_json::to_string_pretty(&value) {
                Ok(json) => CallToolResult::success(vec![ContentBlock::text(json)]),
                Err(error) => CallToolResult::error(vec![ContentBlock::text(format!(
                    "failed to serialize tool result: {error}"
                ))]),
            },
            Err(error) => CallToolResult::error(vec![ContentBlock::text(error.to_string())]),
        })
    }

    fn caller(extensions: &Extensions) -> Option<&CallerContext> {
        extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<CallerContext>())
    }

    fn authorize(
        caller: Option<&CallerContext>,
        tool: &'static str,
        device: Option<&str>,
    ) -> Option<CallToolResult> {
        let caller = caller?;
        if !caller.tools.allows(tool) {
            return Some(CallToolResult::error(vec![ContentBlock::text(format!(
                "token '{}' is not authorized for tool '{tool}'",
                caller.token_name
            ))]));
        }
        if let Some(device) = device
            && !caller.devices.allows(device)
        {
            return Some(CallToolResult::error(vec![ContentBlock::text(format!(
                "token '{}' is not authorized for the requested device",
                caller.token_name
            ))]));
        }
        None
    }
}

/// Empty input object for `list_devices`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

#[tool_router]
impl PanosMcpServer {
    /// List devices visible to the authenticated caller.
    #[tool(
        name = "list_devices",
        description = "List authorized PAN-OS devices and safe metadata; never returns API keys"
    )]
    async fn list_devices(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
        extensions: Extensions,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        let caller = Self::caller(&extensions);
        if let Some(denial) = Self::authorize(caller, "list_devices", None) {
            return Ok(denial);
        }
        let mut output = self.runtime.snapshot().service.list_devices();
        if let Some(caller) = caller {
            output
                .devices
                .retain(|device| caller.devices.allows(&device.name));
        }
        Self::to_call_result(Ok(output))
    }

    /// Gather selected device facts using `show system info`.
    #[tool(
        name = "gather_device_facts",
        description = "Gather hostname, model, serial, version, management IP, and uptime from an authorized PAN-OS device"
    )]
    async fn gather_device_facts(
        &self,
        Parameters(input): Parameters<GatherDeviceFactsInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "gather_device_facts",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.gather_device_facts(input, cancellation).await)
    }

    /// Execute only a single `<show>` operational command.
    #[tool(
        name = "execute_panos_op",
        description = "Execute a read-only PAN-OS XML command rooted at <show> on an authorized device, with output caps"
    )]
    async fn execute_panos_op(
        &self,
        Parameters(input): Parameters<ExecutePanosOpInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "execute_panos_op",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.execute_panos_op(input, cancellation).await)
    }

    /// Read running or candidate configuration under `/config`.
    #[tool(
        name = "get_panos_config",
        description = "Read running or candidate PAN-OS configuration at a validated /config XPath on an authorized device"
    )]
    async fn get_panos_config(
        &self,
        Parameters(input): Parameters<GetPanosConfigInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "get_panos_config",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.get_panos_config(input, cancellation).await)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for PanosMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rust-panosmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "PAN-OS MCP server. Remote callers are restricted by exact bearer-token tool and device scopes.",
            )
    }
}

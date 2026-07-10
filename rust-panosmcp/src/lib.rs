//! MCP transport adapter for rust-panosmcp.

use rmcp::{
    ServerHandler,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use rust_panosmcp_core::{
    Result as CoreResult,
    tools::{ExecutePanosOpInput, GatherDeviceFactsInput, GetPanosConfigInput, PanosService},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Phase 1 read-only MCP server.
#[derive(Debug, Clone)]
pub struct PanosMcpServer {
    service: Arc<PanosService>,
    tool_router: rmcp::handler::server::tool::ToolRouter<Self>,
}

impl PanosMcpServer {
    /// Wrap a fully validated PAN-OS service in the MCP adapter.
    #[must_use]
    pub fn new(service: PanosService) -> Self {
        Self {
            service: Arc::new(service),
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
}

/// Empty input object for `list_devices`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

#[tool_router]
impl PanosMcpServer {
    /// List configured PAN-OS devices without credentials or trust material.
    #[tool(
        name = "list_devices",
        description = "List configured PAN-OS devices and safe metadata; never returns API keys"
    )]
    async fn list_devices(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(Ok(self.service.list_devices()))
    }

    /// Gather selected device facts using `show system info`.
    #[tool(
        name = "gather_device_facts",
        description = "Gather hostname, model, serial, version, management IP, and uptime from a PAN-OS device"
    )]
    async fn gather_device_facts(
        &self,
        Parameters(input): Parameters<GatherDeviceFactsInput>,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(self.service.gather_device_facts(input, cancellation).await)
    }

    /// Execute only a single `<show>` operational command.
    #[tool(
        name = "execute_panos_op",
        description = "Execute a read-only PAN-OS XML operational command rooted at <show>, with byte and line output caps"
    )]
    async fn execute_panos_op(
        &self,
        Parameters(input): Parameters<ExecutePanosOpInput>,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(self.service.execute_panos_op(input, cancellation).await)
    }

    /// Read running or candidate configuration under `/config`.
    #[tool(
        name = "get_panos_config",
        description = "Read running or candidate PAN-OS configuration at a validated /config XPath, with byte and line output caps"
    )]
    async fn get_panos_config(
        &self,
        Parameters(input): Parameters<GetPanosConfigInput>,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(self.service.get_panos_config(input, cancellation).await)
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
                "Read-only PAN-OS MCP server. Call list_devices first, then gather facts, execute a guarded <show> command, or read configuration.",
            )
    }
}

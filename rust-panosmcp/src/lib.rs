//! MCP transport adapter for rust-panosmcp.

use rmcp::{ServerHandler, model::Implementation, model::ServerCapabilities, model::ServerInfo};

/// Phase 0 server used to prove MCP initialization and transport wiring.
///
/// Tool registration begins with the read-only Phase 1 implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct PanosMcpServer;

impl ServerHandler for PanosMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::default())
            .with_server_info(Implementation::new(
                "rust-panosmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "PAN-OS MCP server foundation. No device tools are enabled in Phase 0.",
            )
    }
}

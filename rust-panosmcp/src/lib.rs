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
    mutation::{
        ApplyChangeSetInput, ApproveChangeSetInput, CandidateFingerprintInput,
        ChangeSetStatusInput, CreateChangeSetInput, OperationInput, OperationStatusInput,
        StageConfigInput,
    },
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
        Self::load_with_state(inventory_path, token_path, None)
    }

    /// Load runtime with an optional persistent private mutation-state file.
    pub fn load_with_state(
        inventory_path: impl AsRef<Path>,
        token_path: Option<&Path>,
        state_path: Option<&Path>,
    ) -> Result<Self, RuntimeLoadError> {
        let inventory_path = inventory_path.as_ref().to_path_buf();
        let token_path = token_path.map(Path::to_path_buf);
        let snapshot = load_snapshot(&inventory_path, token_path.as_deref(), None, state_path)?;
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
        let current = self.snapshot();
        let replacement = load_snapshot(
            &self.inventory_path,
            self.token_path.as_ref().map(|path| path.as_path()),
            Some(&current.service),
            None,
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
    previous_service: Option<&PanosService>,
    state_path: Option<&Path>,
) -> Result<RuntimeSnapshot, RuntimeLoadError> {
    let inventory = Inventory::load(inventory_path)?;
    let names: Vec<String> = inventory
        .metadata()
        .into_iter()
        .map(|device| device.name)
        .collect();
    let service = Arc::new(match previous_service {
        Some(previous) => PanosService::reload(inventory, previous)?,
        None => PanosService::new_with_state(inventory, state_path)?,
    });
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
        if !caller.tools.allows_tool(tool) {
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

    fn mutation_principal(extensions: &Extensions) -> Result<&str, CallToolResult> {
        if let Some(caller) = Self::caller(extensions) {
            return Ok(&caller.token_name);
        }
        if extensions.get::<http::request::Parts>().is_some() {
            return Err(CallToolResult::error(vec![ContentBlock::text(
                "candidate mutation requires authenticated HTTP or local stdio",
            )]));
        }
        Ok("local-stdio")
    }

    fn change_set_identity(
        extensions: &Extensions,
    ) -> Result<(&str, Option<rust_panosmcp_auth::MutationGrant>), CallToolResult> {
        let principal = Self::mutation_principal(extensions)?;
        let caller = Self::caller(extensions);
        if caller.is_some_and(|caller| caller.mutation.is_none()) {
            return Err(CallToolResult::error(vec![ContentBlock::text(
                "v0.2 change-set writes require a token-specific mutation grant",
            )]));
        }
        Ok((principal, caller.and_then(|caller| caller.mutation.clone())))
    }
}

/// Empty input object for `list_devices`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

#[tool_router]
impl PanosMcpServer {
    /// Persist a fingerprint-bound multi-action plan without changing PAN-OS.
    #[tool(
        name = "create_panos_change_set",
        description = "Plan and persist 1-64 ordered PAN-OS candidate actions under inventory and token XPath/action scopes"
    )]
    async fn create_panos_change_set(
        &self,
        Parameters(input): Parameters<CreateChangeSetInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "create_panos_change_set",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let (principal, grant) = match Self::change_set_identity(&extensions) {
            Ok(identity) => identity,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(
            service
                .create_change_set(input, principal, grant.as_ref(), cancellation)
                .await,
        )
    }

    /// Independently approve the exact digest of another principal's plan.
    #[tool(
        name = "approve_panos_change_set",
        description = "Approve an unexpired exact change-set digest; self-approval is refused"
    )]
    async fn approve_panos_change_set(
        &self,
        Parameters(input): Parameters<ApproveChangeSetInput>,
        extensions: Extensions,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "approve_panos_change_set",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.approve_change_set(input, principal).await)
    }

    /// Inspect the exact persistent plan, approval, expiry, and apply state.
    #[tool(
        name = "get_panos_change_set",
        description = "Return the exact actions, digest, approval, expiry, and operation state for review or recovery"
    )]
    async fn get_panos_change_set(
        &self,
        Parameters(input): Parameters<ChangeSetStatusInput>,
        extensions: Extensions,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "get_panos_change_set",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        if let Err(denial) = Self::mutation_principal(&extensions) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.change_set_status(input).await)
    }

    /// Apply one independently approved plan as a normal staged operation.
    #[tool(
        name = "apply_panos_change_set",
        description = "Apply an independently approved exact change set under one endpoint/config lock, reverting partial failure"
    )]
    async fn apply_panos_change_set(
        &self,
        Parameters(input): Parameters<ApplyChangeSetInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "apply_panos_change_set",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let (principal, grant) = match Self::change_set_identity(&extensions) {
            Ok(identity) => identity,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(
            service
                .apply_change_set(input, principal, grant.as_ref(), cancellation)
                .await,
        )
    }

    /// Fingerprint all operator-authorized candidate subtrees before mutation.
    #[tool(
        name = "get_candidate_fingerprint",
        description = "Return a SHA-256 fingerprint over all operator-authorized candidate subtrees"
    )]
    async fn get_candidate_fingerprint(
        &self,
        Parameters(input): Parameters<CandidateFingerprintInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "get_candidate_fingerprint",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.candidate_fingerprint(input, cancellation).await)
    }

    /// Stage one guarded set/delete candidate action.
    #[tool(
        name = "stage_panos_config",
        description = "Stage one policy-bounded PAN-OS candidate set/delete using an expected fingerprint"
    )]
    async fn stage_panos_config(
        &self,
        Parameters(input): Parameters<StageConfigInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "stage_panos_config",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.stage_config(input, principal, cancellation).await)
    }

    /// Read a bounded PAN-OS running/candidate change summary.
    #[tool(
        name = "diff_panos_candidate",
        description = "Return a bounded PAN-OS change summary for the exact staged candidate fingerprint"
    )]
    async fn diff_panos_candidate(
        &self,
        Parameters(input): Parameters<OperationInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "diff_panos_candidate",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.diff_candidate(input, principal, cancellation).await)
    }

    /// Run full PAN-OS validation for the staged fingerprint.
    #[tool(
        name = "validate_panos_candidate",
        description = "Validate a staged candidate and make only the same fingerprint eligible for commit"
    )]
    async fn validate_panos_candidate(
        &self,
        Parameters(input): Parameters<OperationInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "validate_panos_candidate",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(
            service
                .validate_candidate(input, principal, cancellation)
                .await,
        )
    }

    /// Start the second, admin-scoped commit step and reconcile its job.
    #[tool(
        name = "commit_panos_candidate",
        description = "Commit only a successfully validated operation using an exact candidate fingerprint"
    )]
    async fn commit_panos_candidate(
        &self,
        Parameters(input): Parameters<OperationInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "commit_panos_candidate",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(
            service
                .commit_candidate(input, principal, cancellation)
                .await,
        )
    }

    /// Revert candidate changes belonging to the configured dedicated PAN-OS admin.
    #[tool(
        name = "discard_panos_candidate",
        description = "Discard a staged operation through an admin-scoped partial candidate revert"
    )]
    async fn discard_panos_candidate(
        &self,
        Parameters(input): Parameters<OperationInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "discard_panos_candidate",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(
            service
                .discard_candidate(input, principal, cancellation)
                .await,
        )
    }

    /// Poll detached or completed lifecycle state.
    #[tool(
        name = "get_panos_operation",
        description = "Return safe status for an owned PAN-OS candidate lifecycle operation"
    )]
    async fn get_panos_operation(
        &self,
        Parameters(input): Parameters<OperationStatusInput>,
        extensions: Extensions,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            Self::caller(&extensions),
            "get_panos_operation",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        Self::to_call_result(service.operation_status(input, principal).await)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_principal_refuses_unauthenticated_http_but_allows_stdio() {
        let local = Extensions::default();
        assert_eq!(
            PanosMcpServer::mutation_principal(&local).expect("local stdio"),
            "local-stdio"
        );

        let (parts, _) = http::Request::new(()).into_parts();
        let mut remote = Extensions::default();
        remote.insert(parts);
        assert!(PanosMcpServer::mutation_principal(&remote).is_err());
    }
}

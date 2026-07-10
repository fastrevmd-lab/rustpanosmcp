//! Transport-independent PAN-OS service and read-only tool behavior.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    inventory::{DeviceMetadata, Inventory},
    xml::{DeviceFacts, parse_device_facts, validate_read_only_op_command, validate_read_xpath},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tokio_util::sync::CancellationToken;

const DEFAULT_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_OUTPUT_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_OUTPUT_LINES: usize = 10_000;
const MAX_OUTPUT_LINES: usize = 100_000;
const SYSTEM_INFO_COMMAND: &str = "<show><system><info></info></system></show>";

/// Shared service behind read tools and the guarded candidate lifecycle.
#[derive(Debug, Clone)]
pub struct PanosService {
    inventory: Inventory,
    clients: Arc<BTreeMap<String, Arc<PanosClient>>>,
    pub(crate) mutations: Arc<crate::mutation::MutationCoordinator>,
}

impl PanosService {
    /// Build and validate all pooled device clients before serving requests.
    pub fn new(inventory: Inventory) -> Result<Self> {
        Self::new_with_state(inventory, None)
    }

    /// Build clients and optionally restore private mutation/approval state.
    pub fn new_with_state(inventory: Inventory, state_path: Option<&Path>) -> Result<Self> {
        Self::build(
            inventory,
            Arc::new(crate::mutation::MutationCoordinator::load(state_path)?),
        )
    }

    /// Rebuild clients while retaining in-flight mutation state across atomic reload.
    pub fn reload(inventory: Inventory, previous: &Self) -> Result<Self> {
        Self::build(inventory, previous.mutations.clone())
    }

    fn build(
        inventory: Inventory,
        mutations: Arc<crate::mutation::MutationCoordinator>,
    ) -> Result<Self> {
        let mut clients = BTreeMap::new();
        for device in inventory.entries() {
            let client = Arc::new(PanosClient::new(device)?);
            clients.insert(client.device_name().to_owned(), client);
        }
        Ok(Self {
            inventory,
            clients: Arc::new(clients),
            mutations,
        })
    }

    /// Return only non-secret inventory metadata in stable name order.
    #[must_use]
    pub fn list_devices(&self) -> ListDevicesOutput {
        ListDevicesOutput {
            devices: self.inventory.metadata(),
        }
    }

    /// Gather selected facts via the documented `show system info` command.
    pub async fn gather_device_facts(
        &self,
        input: GatherDeviceFactsInput,
        cancellation: CancellationToken,
    ) -> Result<GatherDeviceFactsOutput> {
        let client = self.client(&input.device)?;
        let response = client
            .operational(SYSTEM_INFO_COMMAND, cancellation)
            .await?;
        let facts = parse_device_facts(&response)?;
        Ok(GatherDeviceFactsOutput {
            device: input.device,
            facts,
        })
    }

    /// Execute an explicitly read-only `<show>` operational command.
    pub async fn execute_panos_op(
        &self,
        input: ExecutePanosOpInput,
        cancellation: CancellationToken,
    ) -> Result<XmlToolOutput> {
        validate_read_only_op_command(&input.command)?;
        let limits = OutputLimits::resolve(input.max_bytes, input.max_lines)?;
        let client = self.client(&input.device)?;
        let response = client.operational(&input.command, cancellation).await?;
        Ok(XmlToolOutput {
            device: input.device,
            status: response.status,
            code: response.code,
            output: bounded_text(&response.xml, limits),
        })
    }

    /// Read running or candidate configuration under `/config`.
    pub async fn get_panos_config(
        &self,
        input: GetPanosConfigInput,
        cancellation: CancellationToken,
    ) -> Result<ConfigToolOutput> {
        let xpath = input.xpath.unwrap_or_else(|| "/config".to_owned());
        validate_read_xpath(&xpath)?;
        let limits = OutputLimits::resolve(input.max_bytes, input.max_lines)?;
        let client = self.client(&input.device)?;
        let response = client
            .configuration(
                input.source == ConfigSource::Candidate,
                &xpath,
                cancellation,
            )
            .await?;
        Ok(ConfigToolOutput {
            device: input.device,
            source: input.source,
            xpath,
            status: response.status,
            code: response.code,
            output: bounded_text(&response.xml, limits),
        })
    }

    pub(crate) fn client(&self, name: &str) -> Result<Arc<PanosClient>> {
        self.clients
            .get(name)
            .cloned()
            .ok_or_else(|| PanosMcpError::UnknownDevice(name.to_owned()))
    }
}

/// Result of `list_devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ListDevicesOutput {
    /// Configured devices without API keys or trust material.
    pub devices: Vec<DeviceMetadata>,
}

/// Input for `gather_device_facts`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GatherDeviceFactsInput {
    /// Exact inventory device name.
    pub device: String,
}

/// Result of `gather_device_facts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GatherDeviceFactsOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Selected facts from `show system info`.
    pub facts: DeviceFacts,
}

/// Input for `execute_panos_op`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutePanosOpInput {
    /// Exact inventory device name.
    pub device: String,
    /// A single XML operational command rooted at `<show>`.
    pub command: String,
    /// Optional returned-content cap; defaults to 524288 and cannot exceed 5242880.
    #[serde(default)]
    pub max_bytes: Option<usize>,
    /// Optional returned-line cap; defaults to 10000 and cannot exceed 100000.
    #[serde(default)]
    pub max_lines: Option<usize>,
}

/// PAN-OS configuration data source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    /// Active/running configuration via XML API action `show`.
    #[default]
    Running,
    /// Candidate configuration via XML API action `get`.
    Candidate,
}

/// Input for `get_panos_config`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanosConfigInput {
    /// Exact inventory device name.
    pub device: String,
    /// Running or candidate configuration; defaults to running.
    #[serde(default)]
    pub source: ConfigSource,
    /// Optional XPath rooted at `/config`; defaults to `/config`.
    #[serde(default)]
    pub xpath: Option<String>,
    /// Optional returned-content cap; defaults to 524288 and cannot exceed 5242880.
    #[serde(default)]
    pub max_bytes: Option<usize>,
    /// Optional returned-line cap; defaults to 10000 and cannot exceed 100000.
    #[serde(default)]
    pub max_lines: Option<usize>,
}

/// Bounded XML result shared by operational reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct XmlToolOutput {
    /// Exact inventory device name.
    pub device: String,
    /// PAN-OS envelope status.
    pub status: String,
    /// PAN-OS numeric response code, when supplied.
    pub code: Option<i32>,
    /// Bounded XML and truncation metadata.
    pub output: BoundedText,
}

/// Bounded configuration result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ConfigToolOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configuration data source.
    pub source: ConfigSource,
    /// Validated XPath sent to PAN-OS.
    pub xpath: String,
    /// PAN-OS envelope status.
    pub status: String,
    /// PAN-OS numeric response code, when supplied.
    pub code: Option<i32>,
    /// Bounded XML and truncation metadata.
    pub output: BoundedText,
}

/// Caller-visible bounded text plus exact truncation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct BoundedText {
    /// UTF-8 content, never exceeding the requested byte or line cap.
    pub content: String,
    /// Bytes in the complete device response.
    pub original_bytes: usize,
    /// Lines in the complete device response.
    pub original_lines: usize,
    /// Bytes returned in `content`.
    pub returned_bytes: usize,
    /// Lines returned in `content`.
    pub returned_lines: usize,
    /// Whether either output limit removed content.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy)]
struct OutputLimits {
    max_bytes: usize,
    max_lines: usize,
}

impl OutputLimits {
    fn resolve(max_bytes: Option<usize>, max_lines: Option<usize>) -> Result<Self> {
        let max_bytes = max_bytes.unwrap_or(DEFAULT_OUTPUT_BYTES);
        let max_lines = max_lines.unwrap_or(DEFAULT_OUTPUT_LINES);
        if !(1..=MAX_OUTPUT_BYTES).contains(&max_bytes) {
            return Err(PanosMcpError::Policy {
                field: "max_bytes",
                reason: format!("value must be between 1 and {MAX_OUTPUT_BYTES}"),
            });
        }
        if !(1..=MAX_OUTPUT_LINES).contains(&max_lines) {
            return Err(PanosMcpError::Policy {
                field: "max_lines",
                reason: format!("value must be between 1 and {MAX_OUTPUT_LINES}"),
            });
        }
        Ok(Self {
            max_bytes,
            max_lines,
        })
    }
}

fn bounded_text(input: &str, limits: OutputLimits) -> BoundedText {
    let original_bytes = input.len();
    let original_lines = input.lines().count();
    let mut boundary = input.len().min(limits.max_bytes);
    while !input.is_char_boundary(boundary) {
        boundary -= 1;
    }
    if original_lines > limits.max_lines
        && let Some((index, _)) = input.match_indices('\n').nth(limits.max_lines - 1)
    {
        boundary = boundary.min(index);
    }
    let content = input[..boundary].to_owned();
    BoundedText {
        original_bytes,
        original_lines,
        returned_bytes: content.len(),
        returned_lines: content.lines().count(),
        truncated: boundary < input.len(),
        content,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_utf8_safe_and_reports_truncation() {
        let output = bounded_text(
            "one\ntwø\nthree",
            OutputLimits {
                max_bytes: 8,
                max_lines: 2,
            },
        );
        assert_eq!(output.content, "one\ntwø");
        assert_eq!(output.original_lines, 3);
        assert!(output.truncated);
    }

    #[test]
    fn output_limits_refuse_zero_and_excessive_values() {
        assert!(OutputLimits::resolve(Some(0), None).is_err());
        assert!(OutputLimits::resolve(None, Some(MAX_OUTPUT_LINES + 1)).is_err());
    }
}

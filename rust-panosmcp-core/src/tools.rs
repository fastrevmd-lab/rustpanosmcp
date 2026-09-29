//! Transport-independent PAN-OS service and read-only tool behavior.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    inventory::{DeviceMetadata, Inventory},
    observability::AuditScope,
    xml::{
        ConfigEntry, DeviceFacts, collect_text_for_elements, panos_api_code_name,
        parse_device_facts, scan_config_entries, validate_read_only_op_command,
        validate_read_xpath,
    },
};
use mecmcp_policy::{
    CommandAllowlist, CommandDomain, CommandMode, DomainRules, Policy, RuleSource, compile_rules,
};
use rust_panosmcp_auth::CallerContext;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tokio_util::sync::CancellationToken;

const DEFAULT_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_OUTPUT_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_OUTPUT_LINES: usize = 10_000;
const MAX_OUTPUT_LINES: usize = 100_000;
const SYSTEM_INFO_COMMAND: &str = "<show><system><info></info></system></show>";
const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 500;
/// Depth, in tag-name-stack entries, at which a list container's `<entry>`
/// children sit below `<response>`: `response`/`result`/`container`/`entry`.
const LIST_CONTAINER_ENTRY_DEPTH: usize = 3;
/// Depth for an XPath that already resolves to a single entry directly under
/// `<result>`: `response`/`result`/`entry`.
const SINGLE_ENTRY_DEPTH: usize = 2;

/// PAN-OS policy action: only Deny is used (fail-open blocklist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Deny,
}

/// Shared service behind read tools and the guarded candidate lifecycle.
#[derive(Debug, Clone)]
pub struct PanosService {
    inventory: Inventory,
    clients: Arc<BTreeMap<String, Arc<PanosClient>>>,
    pub(crate) mutations: Arc<mecmcp_changeset::ChangesetCoordinator>,
    /// SSDF evidence recorder, when the pipeline is configured.
    ///
    /// Held alongside the coordinator because PAN-OS commits through its own
    /// worker rather than `ChangesetCoordinator::commit_operation`, and that
    /// call is the only coordinator path emitting apply intent and the receipt.
    /// Proposal and approval come from the coordinator; execution comes from
    /// here. **Both must share one recorder** -- a different one splits a single
    /// change across two chains, and both halves verify as valid chains.
    pub(crate) evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    policy: Option<Arc<Policy<Action>>>,
    pub(crate) allow_plane_owned_writes: bool,
    /// Gate for `commit_candidate` calls with no change_set_id -- committed
    /// with no second-principal approval at all. Refused by default; set via
    /// --allow-direct-commit.
    pub(crate) direct_commit: mecmcp_audit::DirectCommitPolicy,
}

impl PanosService {
    /// Build and validate all pooled device clients before serving requests.
    pub fn new(inventory: Inventory) -> Result<Self> {
        Self::new_with_state(inventory, None, false)
    }

    /// Build clients and optionally restore private mutation/approval state.
    ///
    /// `lab_mode` waives two-person control for single-operator environments;
    /// see the `--lab-mode` flag (mecmcp#94).
    pub fn new_with_state(
        inventory: Inventory,
        state_path: Option<&Path>,
        lab_mode: bool,
    ) -> Result<Self> {
        Self::new_with_options(inventory, state_path, lab_mode, None, false, false, None)
    }

    /// As [`new_with_state`](Self::new_with_state), with an approval TTL override.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        inventory: Inventory,
        state_path: Option<&Path>,
        lab_mode: bool,
        approval_timeout_secs: Option<u64>,
        allow_plane_owned_writes: bool,
        allow_direct_commit: bool,
        evidence: Option<std::sync::Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    ) -> Result<Self> {
        let limits = mecmcp_changeset::OperationLimits {
            max_operations: crate::mutation::MAX_OPERATIONS,
            max_change_sets: crate::mutation::MAX_CHANGE_SETS,
            max_actions_per_set: crate::mutation::MAX_CHANGE_SET_ACTIONS,
            max_change_set_bytes: crate::mutation::MAX_CHANGE_SET_BYTES as u64,
            max_state_bytes: crate::mutation::MAX_STATE_BYTES,
            // mecmcp 0.3.8 added these. Taking the shared defaults rather than
            // inventing PAN-OS constants: this server creates no multi-target
            // change set and stores no preview, so neither limit is reachable
            // from here. Give them product values if that changes.
            ..mecmcp_changeset::OperationLimits::default()
        };
        let approval_ttl = std::time::Duration::from_secs(
            approval_timeout_secs.unwrap_or(crate::mutation::APPROVAL_TTL_SECS),
        );

        // PAN-OS keeps the candidate server-side and identifies it by operation
        // id, so a staged operation survives a restart intact — unlike Junos,
        // whose staged handle is a live NETCONF session. Declaring that here lets
        // the coordinator apply it while loading, so memory and the state file are
        // written by one owner. The previous approach rewrote the file after
        // construction and left the two divergent (#72).
        let mut coordinator = mecmcp_changeset::ChangesetCoordinator::load_with_recovery(
            state_path,
            limits,
            approval_ttl,
            lab_mode,
            mecmcp_changeset::StagedRecovery::Retain,
        )
        .map_err(crate::mutation::coord_error)?;
        // `reload` rebuilds from `previous.mutations`, so the recorder attached
        // here survives a SIGHUP without any further plumbing.
        if let Some(recorder) = evidence.clone() {
            coordinator = coordinator.with_evidence(recorder);
        }
        let coordinator = Arc::new(coordinator);

        Self::build(
            inventory,
            coordinator,
            evidence,
            allow_plane_owned_writes,
            allow_direct_commit,
        )
    }

    /// Rebuild clients while retaining in-flight mutation state across atomic reload.
    pub fn reload(inventory: Inventory, previous: &Self) -> Result<Self> {
        Self::build(
            inventory,
            previous.mutations.clone(),
            // The same recorder the previous service used: reload must not
            // start a second chain for one writer.
            previous.evidence.clone(),
            previous.allow_plane_owned_writes,
            previous.direct_commit.is_allowed(),
        )
    }

    fn build(
        inventory: Inventory,
        mutations: Arc<mecmcp_changeset::ChangesetCoordinator>,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
        allow_plane_owned_writes: bool,
        allow_direct_commit: bool,
    ) -> Result<Self> {
        let mut clients = BTreeMap::new();
        for device in inventory.entries() {
            let client = Arc::new(PanosClient::new(device)?);
            clients.insert(client.device_name().to_owned(), client);
        }

        // Build policy from per-device blocklist rules (fail-open: no rules = allow all)
        let policy = Self::build_policy(&inventory)?;

        Ok(Self {
            inventory,
            clients: Arc::new(clients),
            mutations,
            evidence,
            policy: policy.map(Arc::new),
            allow_plane_owned_writes,
            direct_commit: mecmcp_audit::DirectCommitPolicy::new(allow_direct_commit),
        })
    }

    /// `/readyz` probe: `Err` once any device's most recent PAN-OS request
    /// came back unauthorized or session-timed-out (see
    /// [`crate::client::PanosClient::is_auth_healthy`]).
    ///
    /// A device that has made no request yet reports healthy -- readiness
    /// reflects proven auth failure, not silence.
    pub fn auth_health_check(&self) -> std::result::Result<(), &'static str> {
        if self.clients.values().all(|client| client.is_auth_healthy()) {
            Ok(())
        } else {
            Err("PAN-OS authentication failed for one or more devices")
        }
    }

    fn build_policy(inventory: &Inventory) -> Result<Option<Policy<Action>>> {
        let mut commands_domain = DomainRules::default();
        let mut config_domain = DomainRules::default();
        let pfe_commands_domain = DomainRules::default(); // PAN-OS has no PFE commands

        let mut has_any_rules = false;

        for device in inventory.entries() {
            if let Some(blocklist) = &device.blocklist {
                if !blocklist.commands.is_empty() {
                    has_any_rules = true;
                    let rules: Vec<(Action, String)> = blocklist
                        .commands
                        .iter()
                        .map(|pattern| (Action::Deny, pattern.clone()))
                        .collect();
                    let compiled = compile_rules(
                        &rules,
                        &device.metadata.name,
                        RuleSource::Device,
                        |scope, pattern, error| {
                            PanosMcpError::Inventory(format!(
                                "device '{scope}' blocklist command pattern '{pattern}' is invalid: {error}"
                            ))
                        },
                    )?;
                    commands_domain
                        .device_specific
                        .insert(device.metadata.name.clone(), compiled);
                }

                if !blocklist.xpath.is_empty() {
                    has_any_rules = true;
                    let rules: Vec<(Action, String)> = blocklist
                        .xpath
                        .iter()
                        .map(|pattern| (Action::Deny, pattern.clone()))
                        .collect();
                    let compiled = compile_rules(
                        &rules,
                        &device.metadata.name,
                        RuleSource::Device,
                        |scope, pattern, error| {
                            PanosMcpError::Inventory(format!(
                                "device '{scope}' blocklist xpath pattern '{pattern}' is invalid: {error}"
                            ))
                        },
                    )?;
                    config_domain
                        .device_specific
                        .insert(device.metadata.name.clone(), compiled);
                }
            }
        }

        if has_any_rules {
            // Blocklist mode keeps this server's existing semantics (commands
            // are allowed unless a rule denies them). mecmcp >= 0.24 made the
            // mode explicit and defaults to Allowlist, so it must be passed.
            Ok(Some(Policy::new(
                CommandMode::Blocklist,
                CommandDomain {
                    blocklist: commands_domain,
                    allowlist: CommandAllowlist::default(),
                },
                config_domain,
                CommandDomain {
                    blocklist: pfe_commands_domain,
                    allowlist: CommandAllowlist::default(),
                },
            )))
        } else {
            Ok(None)
        }
    }

    /// Return only non-secret inventory metadata in stable name order.
    #[must_use]
    pub fn list_devices(&self, ctx: Option<&CallerContext>) -> ListDevicesOutput {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(ctx, "list_devices", "list", vec![]),
            None => AuditScope::stdio("list_devices", "list", vec![]),
        };
        let result = ListDevicesOutput {
            devices: self.inventory.metadata(),
        };
        audit.meta("device_count", result.devices.len() as u64);
        audit.succeed();
        result
    }

    /// Gather selected facts via the documented `show system info` command.
    pub async fn gather_device_facts(
        &self,
        input: GatherDeviceFactsInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<GatherDeviceFactsOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "gather_device_facts",
                "gather-facts",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "gather_device_facts",
                "gather-facts",
                vec![input.device.clone()],
            ),
        };
        let client = self.client(&input.device)?;
        let response = match client.operational(SYSTEM_INFO_COMMAND, cancellation).await {
            Ok(r) => r,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        let facts = match parse_device_facts(&response) {
            Ok(f) => f,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        let advisories: Vec<String> = facts
            .software_version
            .as_deref()
            .and_then(crate::version_advisory::cve_2026_0310_warning)
            .into_iter()
            .collect();
        if let Some(warning) = advisories.first() {
            audit.meta("version_advisory", warning.clone());
        }
        audit.succeed();
        Ok(GatherDeviceFactsOutput {
            device: input.device,
            facts,
            advisories,
        })
    }

    /// Execute an explicitly read-only `<show>` operational command.
    pub async fn execute_panos_op(
        &self,
        input: ExecutePanosOpInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<XmlToolOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "execute_panos_op",
                "show-op",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("execute_panos_op", "show-op", vec![input.device.clone()]),
        };
        let result = async {
            validate_read_only_op_command(&input.command)?;

            // Check blocklist policy if configured (fail-open: no policy = allow all)
            if let Some(policy) = &self.policy {
                use mecmcp_policy::{Decision, normalize_input};
                let normalized = normalize_input(&input.command);
                match policy.check_command(&input.device, &normalized, Action::Deny) {
                    Decision::Allow => {}
                    Decision::Deny { rule, source, .. } => {
                        return Err(PanosMcpError::Policy {
                            field: "command",
                            reason: format!(
                                "blocked by {} blocklist rule '{}'",
                                source.as_str(),
                                rule.pattern
                            ),
                        });
                    }
                    // Must deny (Percy F1, MEC-352): never a wildcard or allow.
                    // Unreachable in Blocklist mode today, but a future mode
                    // change must fail closed rather than silently allow.
                    Decision::DenyAllowlist { reason, .. } => {
                        return Err(PanosMcpError::Policy {
                            field: "command",
                            reason: format!("blocked by command allowlist: {reason:?}"),
                        });
                    }
                }
            }

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
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Read running or candidate configuration under `/config`.
    pub async fn get_panos_config(
        &self,
        input: GetPanosConfigInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ConfigToolOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_config",
                "get-config",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("get_panos_config", "get-config", vec![input.device.clone()]),
        };
        let result = async {
            let xpath = input.xpath.unwrap_or_else(|| "/config".to_owned());
            validate_read_xpath(&xpath)?;
            self.check_xpath_policy(&input.device, &xpath)?;

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
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Read entries from a list container without materializing the whole
    /// thing: a response over the byte cap is truncated and marked rather
    /// than refused, and only the requested `[offset, offset + limit)` window
    /// is decoded into owned strings.
    pub async fn list_panos_entries(
        &self,
        input: ListPanosEntriesInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ListPanosEntriesOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "list_panos_entries",
                "list-entries",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "list_panos_entries",
                "list-entries",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            validate_read_xpath(&input.xpath)?;
            self.check_xpath_policy(&input.device, &input.xpath)?;

            let offset = input.offset.unwrap_or(0);
            let limit = input.limit.unwrap_or(DEFAULT_LIST_LIMIT);
            if limit == 0 || limit > MAX_LIST_LIMIT {
                return Err(PanosMcpError::Policy {
                    field: "limit",
                    reason: format!("value must be between 1 and {MAX_LIST_LIMIT}"),
                });
            }

            let client = self.client(&input.device)?;
            let (bytes, response_truncated) = client
                .configuration_entries(
                    input.source == ConfigSource::Candidate,
                    &input.xpath,
                    cancellation,
                )
                .await?;
            let scan = scan_config_entries(&bytes, offset, limit, LIST_CONTAINER_ENTRY_DEPTH)?;
            ensure_scan_success(&input.device, &bytes, &scan)?;

            let returned = scan.entries.len();
            Ok(ListPanosEntriesOutput {
                device: input.device,
                source: input.source,
                xpath: input.xpath,
                entries: scan.entries,
                offset,
                limit,
                returned,
                total_entries: scan.total_seen,
                truncated: response_truncated
                    || scan.truncated
                    || offset + returned < scan.total_seen,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Digest one entry by its exact XPath, without reading anything else.
    ///
    /// Meant for drift checks on a single rule or object: unlike
    /// `get_candidate_fingerprint`, which hashes every operator-authorized
    /// write root to detect any change, this issues one request scoped to
    /// the caller's entry and says only whether *that* entry's XML changed.
    pub async fn get_panos_entry_digest(
        &self,
        input: GetPanosEntryDigestInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<GetPanosEntryDigestOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_entry_digest",
                "entry-digest",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_entry_digest",
                "entry-digest",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            validate_read_xpath(&input.xpath)?;
            if !input.xpath.ends_with(']') {
                return Err(PanosMcpError::Policy {
                    field: "xpath",
                    reason: "must select exactly one entry via a [@name='...'] predicate"
                        .to_owned(),
                });
            }
            self.check_xpath_policy(&input.device, &input.xpath)?;

            let client = self.client(&input.device)?;
            let response = client
                .configuration(
                    input.source == ConfigSource::Candidate,
                    &input.xpath,
                    cancellation,
                )
                .await?;
            let scan = scan_config_entries(response.xml.as_bytes(), 0, 1, SINGLE_ENTRY_DEPTH)?;
            match scan.entries.into_iter().next() {
                Some(entry) => Ok(GetPanosEntryDigestOutput {
                    device: input.device,
                    source: input.source,
                    xpath: input.xpath,
                    found: true,
                    name: Some(entry.name),
                    digest: Some(entry.digest),
                }),
                None => Ok(GetPanosEntryDigestOutput {
                    device: input.device,
                    source: input.source,
                    xpath: input.xpath,
                    found: false,
                    name: None,
                    digest: None,
                }),
            }
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Deny an xpath matched by a device or global config blocklist rule.
    ///
    /// Fail-open when no policy is configured, matching this server's
    /// existing command-blocklist semantics.
    fn check_xpath_policy(&self, device: &str, xpath: &str) -> Result<()> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        use mecmcp_policy::{evaluate, normalize_input};
        let normalized = normalize_input(xpath);
        let rules = policy.config_rules_for(device);
        match evaluate(&rules, &normalized) {
            Some(rule) if rule.action == Action::Deny => Err(PanosMcpError::Policy {
                field: "xpath",
                reason: format!(
                    "blocked by {} blocklist rule '{}'",
                    rule.source.as_str(),
                    rule.pattern
                ),
            }),
            _ => Ok(()),
        }
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
    /// Known-CVE version-floor warnings for the reported `sw-version`.
    ///
    /// Never gates the call -- this is advisory text for the human operator,
    /// not a decision. Empty when the version is unknown, unparseable, or at
    /// or above every fix level this server currently tracks.
    pub advisories: Vec<String>,
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

/// Input for `list_panos_entries`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListPanosEntriesInput {
    /// Exact inventory device name.
    pub device: String,
    /// Running or candidate configuration; defaults to running.
    #[serde(default)]
    pub source: ConfigSource,
    /// XPath of the list container, e.g. a rulebase or address-object list.
    pub xpath: String,
    /// Zero-based index of the first entry to return; defaults to 0.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Maximum entries to return; defaults to 100 and cannot exceed 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Result of `list_panos_entries`.
///
/// `entries` holds only the `[offset, offset + limit)` window; `total_entries`
/// counts every complete entry observed in the (possibly `truncated`)
/// response, so a caller can page through a rulebase far larger than any
/// single response is allowed to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ListPanosEntriesOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configuration data source.
    pub source: ConfigSource,
    /// Validated XPath sent to PAN-OS.
    pub xpath: String,
    /// Entries in `[offset, offset + limit)`, each with its own XML and digest.
    pub entries: Vec<ConfigEntry>,
    /// Zero-based index of the first entry requested.
    pub offset: usize,
    /// Maximum entries requested.
    pub limit: usize,
    /// `entries.len()`.
    pub returned: usize,
    /// Complete entries observed in the response, truncated or not.
    pub total_entries: usize,
    /// True when more entries exist beyond this page, or the device response
    /// itself was cut off before every entry could be observed -- "N of M
    /// shown" rather than an outright failure.
    pub truncated: bool,
}

/// Input for `get_panos_entry_digest`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanosEntryDigestInput {
    /// Exact inventory device name.
    pub device: String,
    /// Running or candidate configuration; defaults to running.
    #[serde(default)]
    pub source: ConfigSource,
    /// XPath resolving to exactly one entry, e.g.
    /// `.../rule-base/security/rules/entry[@name='allow-dns']`.
    pub xpath: String,
}

/// Result of `get_panos_entry_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GetPanosEntryDigestOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configuration data source.
    pub source: ConfigSource,
    /// Validated XPath sent to PAN-OS.
    pub xpath: String,
    /// Whether PAN-OS had an entry at this XPath.
    pub found: bool,
    /// The entry's `name` attribute, when found.
    pub name: Option<String>,
    /// `sha256:<hex>` over the entry's exact source XML, when found. Changes
    /// if and only if this one entry changed -- no other part of the
    /// configuration is read to produce it.
    pub digest: Option<String>,
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

/// Turn a failed PAN-OS envelope observed mid-scan into a typed API error.
///
/// The entry scan never buffers a full [`PanosResponse`], so it cannot reuse
/// `PanosResponse::ensure_success` -- this extracts the same `<msg>`/`<line>`
/// text from the raw bytes instead.
fn ensure_scan_success(device: &str, raw: &[u8], scan: &crate::xml::EntryScanResult) -> Result<()> {
    let is_success =
        scan.status.eq_ignore_ascii_case("success") && !matches!(scan.code, Some(1..=18 | 21..));
    if is_success {
        return Ok(());
    }
    let code = scan.code.unwrap_or(-1);
    let message = collect_text_for_elements(raw, &[b"msg", b"line"], 1024)
        .ok()
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| "PAN-OS returned an error without a message".to_owned());
    Err(PanosMcpError::Api {
        device: device.to_owned(),
        code,
        name: panos_api_code_name(code),
        message,
    })
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

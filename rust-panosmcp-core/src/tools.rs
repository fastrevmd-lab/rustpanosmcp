//! Transport-independent PAN-OS service and read-only tool behavior.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    inventory::{DeviceMetadata, Inventory},
    observability::AuditScope,
    xml::{
        DeviceFacts, parse_device_facts, redact_secret_material, validate_read_only_op_command,
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
                    // Canonicalise the operator's pattern to the same quote
                    // style `get_panos_config` canonicalises the candidate
                    // xpath to before matching, so a rule written with `'`
                    // still catches a request spelled with `"` (MEC-528
                    // class 3), then escape the glob metacharacters an XPath
                    // predicate is made of but does not mean as wildcards
                    // (see `escape_xpath_glob_metacharacters`).
                    let rules: Vec<(Action, String)> = blocklist
                        .xpath
                        .iter()
                        .map(|pattern| {
                            let canonical = rust_panosmcp_auth::canonicalize_xpath_quotes(pattern);
                            (Action::Deny, escape_xpath_glob_metacharacters(&canonical))
                        })
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
        audit.succeed();
        Ok(GatherDeviceFactsOutput {
            device: input.device,
            facts,
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
            let redacted = redact_secret_material(&response.xml);
            Ok(XmlToolOutput {
                device: input.device,
                status: response.status,
                code: response.code,
                output: bounded_text(&redacted, limits),
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

            // Check blocklist policy if configured (fail-open: no policy = allow all)
            // We use config_rules_for for xpath matching (not check_config which is for multi-line text)
            if let Some(policy) = &self.policy {
                use mecmcp_policy::{evaluate, normalize_input};
                // Canonicalise quote style before matching, the same way
                // `validate_write_xpath` does for the write path: `'` and `"`
                // are the same XPath predicate to PAN-OS, so an operator's
                // blocklist rule written with one quote style must still
                // catch a request spelled with the other (MEC-528 class 3 --
                // this used to only normalize whitespace, so a rule written
                // as `.../entry[@name='secret']*` never matched a read
                // spelled with double quotes).
                let canonical = rust_panosmcp_auth::canonicalize_xpath_quotes(&xpath);
                let normalized = normalize_input(&canonical);
                let rules = policy.config_rules_for(&input.device);
                match evaluate(&rules, &normalized) {
                    Some(rule) if rule.action == Action::Deny => {
                        return Err(PanosMcpError::Policy {
                            field: "xpath",
                            reason: format!(
                                "blocked by {} blocklist rule '{}'",
                                rule.source.as_str(),
                                rule.pattern
                            ),
                        });
                    }
                    _ => {}
                }
            }

            let limits = OutputLimits::resolve(input.max_bytes, input.max_lines)?;
            let client = self.client(&input.device)?;
            let response = client
                .configuration(
                    input.source == ConfigSource::Candidate,
                    &xpath,
                    cancellation,
                )
                .await?;
            let redacted = redact_secret_material(&response.xml);
            Ok(ConfigToolOutput {
                device: input.device,
                source: input.source,
                xpath,
                status: response.status,
                code: response.code,
                output: bounded_text(&redacted, limits),
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
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

/// Escape glob metacharacters that occur naturally in an XPath predicate but
/// are not the wildcard an operator means when writing a blocklist rule.
///
/// `compile_rules` compiles xpath blocklist patterns as globs (the `globset`
/// crate). Globs treat a bare `[...]` as a character class, so a pattern like
/// `.../entry[@name='secret']*` is not matched literally: `[@name='secret']`
/// is parsed as "one character from the set `@name='secret`", which either
/// fails to compile (e.g. the value contains characters globset reads as an
/// invalid range, silently refusing to enforce the rule at startup) or
/// compiles into a character class the operator never intended, matching a
/// different set of xpaths than the literal predicate they wrote (MEC-528
/// class 3). `*` is left untouched since it is the one wildcard operators
/// are expected to use; `?` is also escaped since XPath has no single-char
/// wildcard of its own but globset would still treat it as one.
fn escape_xpath_glob_metacharacters(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for ch in pattern.chars() {
        if matches!(ch, '[' | ']' | '?' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
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

    /// MEC-528 class 3: an xpath predicate compiled as a raw glob either
    /// fails outright (an invalid character range, as here) or silently
    /// matches something other than the literal predicate the operator
    /// wrote. Escaping the brackets must make the pattern match the literal
    /// text of the predicate and nothing else.
    #[test]
    fn escaping_makes_a_bracketed_predicate_a_literal_match() {
        let pattern = "*/address/entry[@name='secret-object']*";
        // Unescaped, this glob fails to compile: globset reads `t' > 'o` in
        // `[@name='secret-object']` as an invalid descending character range.
        assert!(
            compile_rules(
                &[(Action::Deny, pattern.to_owned())],
                "test",
                RuleSource::Device,
                |_scope, _pattern, error| error,
            )
            .is_err()
        );

        let escaped = escape_xpath_glob_metacharacters(pattern);
        let compiled = compile_rules(
            &[(Action::Deny, escaped)],
            "test",
            RuleSource::Device,
            |_scope, _pattern, error| error,
        )
        .expect("escaped pattern compiles");
        let rules: Vec<_> = compiled.iter().collect();
        assert!(mecmcp_policy::evaluate(
            &rules,
            "/config/devices/entry[@name='fw']/vsys/entry[@name='vsys1']/address/entry[@name='secret-object']"
        )
        .is_some());
        assert!(mecmcp_policy::evaluate(
            &rules,
            "/config/devices/entry[@name='fw']/vsys/entry[@name='vsys1']/address/entry[@name='other-object']"
        )
        .is_none());
    }

    #[test]
    fn escaping_leaves_the_wildcard_asterisk_alone() {
        assert_eq!(
            escape_xpath_glob_metacharacters("*/hostname*"),
            "*/hostname*"
        );
    }
}

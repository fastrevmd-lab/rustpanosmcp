//! Fingerprint-bound, per-device serialized PAN-OS candidate lifecycle.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    observability::AuditScope,
    tools::PanosService,
    xml::{parse_job_id, validate_config_element, validate_write_xpath},
};
use mecmcp_changeset::DeviceTransaction as _;
use quick_xml::escape::escape;
use rust_panosmcp_auth::CallerContext;
use rust_panosmcp_auth::{Grant, MutationAction, MutationGrant};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

// Import shared types - no longer aliased since local types are deleted
pub use mecmcp_changeset::OperationLimits as PublicOperationLimits;
use mecmcp_changeset::{
    ChangeSetRecord, ChangeSetState, ChangesetCoordinator, CoordinatorError, LifecycleState,
    OperationRecord,
};
pub use mecmcp_changeset::{RecoveryDisposition, resolve_persisted_operation};

pub(crate) const MAX_OPERATIONS: usize = 1024;
pub(crate) const MAX_CHANGE_SETS: usize = 1024;
pub(crate) const MAX_CHANGE_SET_ACTIONS: usize = 64;
pub(crate) const MAX_CHANGE_SET_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const APPROVAL_TTL_SECS: u64 = 15 * 60;
const MAX_DIFF_BYTES: usize = 256 * 1024;
const VALIDATE_DEADLINE: Duration = Duration::from_secs(300);
const COMMIT_DEADLINE: Duration = Duration::from_secs(600);

/// Maps `CoordinatorError` from the shared coordinator to this crate's error type.
///
/// Preserves the coordinator's error categories: cancellation errors map to
/// `Cancelled`, persistence failures map to `Configuration`, and policy/state
/// violations map to `Policy`.
pub(crate) fn coord_error(error: CoordinatorError) -> PanosMcpError {
    // Cancellation is signaled by field "device" + message "operation cancelled"
    if error.field() == "device" && error.message() == "operation cancelled" {
        return PanosMcpError::Cancelled;
    }

    // Persistence failures are signaled by field "state"
    if error.field() == "state" {
        return PanosMcpError::Configuration(format!(
            "changeset state persistence failed: {}",
            error.message()
        ));
    }

    // All other coordinator errors are policy/lifecycle refusals
    PanosMcpError::Policy {
        field: error.field(),
        reason: error.message().to_owned(),
    }
}

/// Let `?` carry a coordinator error straight through.
///
/// Most coordinator refusals are policy refusals (digest mismatch, not approved,
/// wrong state), but cancellation and persistence failures have their own categories.
/// The `From` impl delegates to `coord_error` to preserve the distinction.
impl From<CoordinatorError> for PanosMcpError {
    fn from(error: CoordinatorError) -> Self {
        coord_error(error)
    }
}

/// Extracts the primary `StageAction` from a JSON value serialized by this crate.
///
/// The shared coordinator stores `action` as `serde_json::Value`. This function
/// deserializes it back to the local `StageAction` enum.
fn extract_stage_action(value: &serde_json::Value) -> Result<StageAction> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PanosMcpError::Configuration(format!("could not deserialize action: {error}"))
    })
}

/// Serializes a `StageAction` to JSON for storage in the shared coordinator.
fn serialize_stage_action(action: StageAction) -> Result<serde_json::Value> {
    serde_json::to_value(action).map_err(|error| {
        PanosMcpError::Configuration(format!("could not serialize action: {error}"))
    })
}

/// Extracts the primary XPath target from an operation record.
///
/// The `xpath` field is optional in the shared schema (Junos omits it), but PAN-OS
/// operations always carry it. Returns `None` only if the field is missing.
fn extract_xpath(record: &OperationRecord) -> Option<String> {
    record.xpath.clone()
}

/// Converts a `ChangeSetRecord` to the local `ChangeSetOutput` type.
///
/// This is the output projection visible to callers. The record is vendor-neutral
/// and stores actions as JSON; this extracts and deserializes them to the local
/// `ChangeSetAction` type.
fn changeset_record_to_output(record: &ChangeSetRecord) -> Result<ChangeSetOutput> {
    let actions: Vec<ChangeSetAction> = record
        .actions
        .iter()
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                PanosMcpError::Configuration(format!(
                    "could not deserialize change-set action: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ChangeSetOutput {
        change_set_id: record.id.clone(),
        device: record.device.clone(),
        owner: record.owner.clone(),
        digest: record.digest.clone(),
        expected_candidate_fingerprint: record.expected_candidate_fingerprint.clone(),
        actions,
        state: record.state.as_str().to_owned(),
        approval_waiver: record
            .approval
            .as_ref()
            .and_then(|approval| approval.waived.as_ref())
            .map(|waiver| waiver.reason.clone()),
        approver: record
            .approval
            .as_ref()
            .and_then(|a| a.approver.clone())
            .or_else(|| record.approver.clone()),
        expires_at_unix: record.expires_at_unix,
        operation_id: record.operation_id.clone(),
    })
}

/// Candidate configuration action supported by the guarded stage tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StageAction {
    /// Merge the supplied XML element at the XPath.
    Set,
    /// Delete the exact XPath after policy and confirmation checks.
    Delete,
}

impl StageAction {
    pub(crate) const fn api_name(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Delete => "delete",
        }
    }
}

impl From<StageAction> for MutationAction {
    fn from(value: StageAction) -> Self {
        match value {
            StageAction::Set => Self::Set,
            StageAction::Delete => Self::Delete,
        }
    }
}

/// One action in an exact, digest-bound change set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetAction {
    /// Set or delete.
    pub action: StageAction,
    /// Exact XPath within both inventory and token policy.
    pub xpath: String,
    /// One XML element; required for set and forbidden for delete.
    #[serde(default)]
    pub element: Option<String>,
    /// For delete, must equal `DELETE <xpath>` exactly.
    #[serde(default)]
    pub destructive_confirmation: Option<String>,
}

/// Input for planning a multi-action change set without mutating PAN-OS.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateChangeSetInput {
    /// Exact inventory device.
    pub device: String,
    /// Candidate fingerprint to which this plan is bound.
    pub expected_candidate_fingerprint: String,
    /// Ordered actions; all are covered by one digest and approval.
    pub actions: Vec<ChangeSetAction>,
}

/// Input for approving the exact digest of another principal's plan.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveChangeSetInput {
    /// Exact inventory device.
    pub device: String,
    /// Planned change-set identifier.
    pub change_set_id: String,
    /// Exact digest returned by create/get.
    pub expected_digest: String,
}

/// Input for applying a previously approved plan.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyChangeSetInput {
    /// Exact inventory device.
    pub device: String,
    /// Approved change-set identifier.
    pub change_set_id: String,
    /// Exact approved digest.
    pub expected_digest: String,
    /// Candidate fingerprint originally bound into the plan.
    pub expected_candidate_fingerprint: String,
}

/// Input for reading safe change-set state and its exact reviewed actions.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetStatusInput {
    /// Exact inventory device.
    pub device: String,
    /// Change-set identifier.
    pub change_set_id: String,
}

/// Persistent planned/approved/applied change-set metadata.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ChangeSetOutput {
    /// Random change-set identifier.
    pub change_set_id: String,
    /// Exact inventory device.
    pub device: String,
    /// Principal that owns and may apply the plan.
    pub owner: String,
    /// SHA-256 binding owner, device, pre-fingerprint, and ordered actions.
    pub digest: String,
    /// Candidate fingerprint to which the plan is bound.
    pub expected_candidate_fingerprint: String,
    /// Exact ordered actions covered by the digest.
    pub actions: Vec<ChangeSetAction>,
    /// Planned, approved, applied, expired, or failed.
    pub state: String,
    /// Independent approver, when approved.
    pub approver: Option<String>,
    /// Why approval was waived, when it was.
    ///
    /// `None` on an ordinary change set. `Some("lab-mode")` when a
    /// single-operator server approved it without a second principal.
    /// `approver: None` alone cannot carry this — it means both "not yet
    /// approved" and "approved without review" (mecmcp#94).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_waiver: Option<String>,
    /// Approval deadline.
    pub expires_at_unix: u64,
    /// Lifecycle operation created by apply, when available.
    pub operation_id: Option<String>,
}

/// Input for candidate fingerprint retrieval.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateFingerprintInput {
    /// Exact inventory device.
    pub device: String,
}

/// Stable candidate fingerprint.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CandidateFingerprintOutput {
    /// Exact inventory device.
    pub device: String,
    /// SHA-256 over every operator-authorized candidate subtree.
    pub candidate_fingerprint: String,
}

/// Input for a guarded candidate change.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StageConfigInput {
    /// Exact inventory device.
    pub device: String,
    /// Candidate fingerprint observed immediately before staging.
    pub expected_candidate_fingerprint: String,
    /// Set or delete.
    pub action: StageAction,
    /// Exact XPath within an operator-configured root.
    pub xpath: String,
    /// One XML element; required for set and forbidden for delete.
    #[serde(default)]
    pub element: Option<String>,
    /// For delete, must equal `DELETE <xpath>` exactly.
    #[serde(default)]
    pub destructive_confirmation: Option<String>,
}

/// Result of staging one candidate change.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct StageConfigOutput {
    /// Random operation identifier required by later lifecycle calls.
    pub operation_id: String,
    /// Exact inventory device.
    pub device: String,
    /// Candidate fingerprint before mutation.
    pub before_fingerprint: String,
    /// Candidate fingerprint after mutation.
    pub candidate_fingerprint: String,
    /// Whether a PAN-OS configuration lock is being held for this operation.
    pub config_lock_held: bool,
}

/// Input identifying a previously staged operation.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationInput {
    /// Exact inventory device.
    pub device: String,
    /// Operation identifier returned by stage.
    pub operation_id: String,
    /// Candidate fingerprint expected at this lifecycle step.
    pub expected_candidate_fingerprint: String,
}

/// Candidate change summary tied to one operation.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CandidateDiffOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Exact inventory device.
    pub device: String,
    /// Staged action.
    pub action: StageAction,
    /// Target XPath.
    pub xpath: String,
    /// Candidate fingerprint at diff time.
    pub candidate_fingerprint: String,
    /// PAN-OS change-summary XML, bounded independently of the device response cap.
    pub change_summary: String,
    /// Whether the change summary was truncated.
    pub truncated: bool,
}

/// Validation result.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ValidationOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// PAN-OS validation job identifier.
    pub job_id: String,
    /// Terminal result.
    pub succeeded: bool,
    /// Bounded terminal details.
    pub details: Option<String>,
    /// Fingerprint that is now eligible for commit.
    pub candidate_fingerprint: String,
}

/// Commit caller disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitDisposition {
    /// Commit job reached a terminal state before the caller cancelled.
    Reconciled,
    /// Caller cancelled while the detached worker continued reconciliation.
    Detached,
}

/// Commit result or detached acknowledgement.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CommitOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Caller disposition.
    pub disposition: CommitDisposition,
    /// Job identifier when already available.
    pub job_id: Option<String>,
    /// Terminal success when reconciled; absent while detached.
    pub succeeded: Option<bool>,
    /// Bounded terminal details.
    pub details: Option<String>,
}

/// Discard result.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DiscardOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Candidate fingerprint after admin-scoped partial revert.
    pub candidate_fingerprint: String,
}

/// Safe operation state for polling and recovery.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct OperationStatusOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Exact inventory device.
    pub device: String,
    /// Lifecycle state.
    pub state: String,
    /// PAN-OS job identifier when known.
    pub job_id: Option<String>,
    /// Current candidate fingerprint when known.
    pub candidate_fingerprint: String,
    /// Bounded terminal details.
    pub details: Option<String>,
}

/// Input for polling a lifecycle operation without authorizing a new action.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationStatusInput {
    /// Exact inventory device.
    pub device: String,
    /// Operation identifier returned by stage.
    pub operation_id: String,
}

impl PanosService {
    /// Fingerprint every operator-authorized candidate subtree.
    ///
    /// `_cancellation` is accepted and unused. This now reads the fingerprint
    /// through `DeviceTransaction::fingerprint`, whose signature takes no
    /// cancellation token, so a long fingerprint read can no longer be
    /// cancelled mid-flight the way the local helper allowed. The parameter is
    /// kept so the public signature does not change under callers; removing it
    /// is a separate decision, and adding cancellation to the shared trait is
    /// another.
    pub async fn candidate_fingerprint(
        &self,
        input: CandidateFingerprintInput,
        ctx: Option<&CallerContext>,
        _cancellation: CancellationToken,
    ) -> Result<CandidateFingerprintOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_candidate_fingerprint",
                "get-fingerprint",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_candidate_fingerprint",
                "get-fingerprint",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            let client = self.client(&input.device)?;
            require_policy(&client)?;
            let candidate = client.fingerprint().await?;
            Ok(CandidateFingerprintOutput {
                device: input.device,
                candidate_fingerprint: candidate,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Plan and persist an exact multi-action change set without mutating PAN-OS.
    pub async fn create_change_set(
        &self,
        input: CreateChangeSetInput,
        ctx: Option<&CallerContext>,
        owner: &str,
        grant: Option<&MutationGrant>,
        cancellation: CancellationToken,
    ) -> Result<ChangeSetOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "create_panos_change_set",
                "plan",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "create_panos_change_set",
                "plan",
                vec![input.device.clone()],
            ),
        };

        let result = async {
            validate_fingerprint(&input.expected_candidate_fingerprint)?;
            let client = self.client(&input.device)?;
            let policy = require_policy(&client)?;
            validate_change_set_actions(&input.actions, policy, grant)?;
            let current = candidate_fingerprint(&client, cancellation).await?;
            require_fingerprint(&input.expected_candidate_fingerprint, &current)?;
            let now = now_unix()?;
            let id = new_operation_id()?;

            // Serialize actions to JSON for the shared coordinator
            let actions_json: Vec<serde_json::Value> = input
                .actions
                .iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<Vec<_>, serde_json::Error>>()
                .map_err(|error| {
                    PanosMcpError::Configuration(format!("could not serialize actions: {error}"))
                })?;

            let digest = mecmcp_changeset::change_set_digest(
                owner,
                &input.device,
                &input.expected_candidate_fingerprint,
                &actions_json,
            )
            .map_err(|error| {
                PanosMcpError::Configuration(format!("could not compute digest: {error}"))
            })?;

            // Keep policy_signature empty to maintain version 1 file format.
            // Version 2 triggers if policy_signature is non-empty, and the previous
            // binary cannot read version 2 files, preventing rollback. Policy drift
            // is checked on operations, not change-sets, so this is safe.
            let record = ChangeSetRecord {
                id: id.clone(),
                owner: owner.to_owned(),
                device: input.device.clone(),
                expected_candidate_fingerprint: input.expected_candidate_fingerprint,
                actions: actions_json,
                digest: digest.clone(),
                state: ChangeSetState::Planned,
                approver: None,
                approval: None,
                // From the coordinator, not the constant: an operator who sets
                // --approval-timeout-secs would otherwise get their value applied
                // to the coordinator's own expiry checks while change sets kept
                // the compiled-in default, and the two would disagree.
                expires_at_unix: now.saturating_add(self.mutations.approval_ttl().as_secs()),
                operation_id: None,
                policy_signature: String::new(),
                // Same rule as policy_signature above: both of these gate the
                // file to version 2, which the previous binary cannot read.
                // PAN-OS applies to one device per change set, so the
                // single-target shape is the correct one here, not a
                // compatibility compromise — `record.targets()` still answers
                // with [device].
                targets: Vec::new(),
                preview: None,
            };
            self.mutations
                .insert_change_set(record.clone())
                .await
                .map_err(coord_error)?;

            audit.meta("change_set_id", id.clone());
            audit.meta("digest", digest.clone());
            audit.meta("action_count", record.actions.len() as u64);

            // Single-operator servers waive approval here rather than exposing a
            // tool to do it. Starting the service with `--lab-mode` is already the
            // deliberate decision to run without a second reviewer, so a
            // per-change-set waive call would be ceremony protecting nobody — and
            // the digest confirmation it would carry is already enforced by
            // `apply`, which is what touches the device (mecmcp#94).
            //
            // No approver is invented: the record keeps `approver: null` and gains
            // `approval_waiver`, so a waived change stays distinguishable from one
            // a second person reviewed.
            if self.mutations.lab_mode() {
                let waived = self
                    .mutations
                    .waive_approval(id, record.device.clone(), record.owner.clone(), digest)
                    .await
                    .map_err(coord_error)?;
                audit.meta("approval_waiver", "lab-mode");
                let mut output = changeset_record_to_output(&record)?;
                output.state = format!("{:?}", waived.state).to_lowercase();
                output.approver = None;
                output.approval_waiver = Some("lab-mode".to_owned());
                return Ok(output);
            }

            changeset_record_to_output(&record)
        }
        .await;

        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Approve the exact digest of another principal's unexpired plan.
    pub async fn approve_change_set(
        &self,
        input: ApproveChangeSetInput,
        ctx: Option<&CallerContext>,
        approver: &str,
    ) -> Result<ChangeSetOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "approve_panos_change_set",
                "approve",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "approve_panos_change_set",
                "approve",
                vec![input.device.clone()],
            ),
        };

        // Add change_set_id and digest to audit metadata BEFORE any checks
        // so they're emitted even on denial/failure
        audit.meta("change_set_id", input.change_set_id.clone());
        audit.meta("digest", input.expected_digest.clone());

        let result = async {
            // Use shared coordinator's approve_change_set which handles all validation
            let output = self
                .mutations
                .approve_change_set(
                    input.change_set_id.clone(),
                    input.device.clone(),
                    approver.to_owned(),
                    input.expected_digest,
                )
                .await
                .map_err(coord_error)?;

            // Add owner to metadata after successful approval
            audit.meta("owner", output.owner.clone());
            audit.meta("action_count", output.action_count as u64);

            // Fetch the full record to get the actions for our output
            let full_record = self
                .mutations
                .change_set(&output.change_set_id, &output.device)
                .await
                .map_err(coord_error)?;

            changeset_record_to_output(&full_record)
        }
        .await;

        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Return an exact persistent plan for independent review or recovery.
    pub async fn change_set_status(
        &self,
        input: ChangeSetStatusInput,
        ctx: Option<&CallerContext>,
    ) -> Result<ChangeSetOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_change_set",
                "get-change-set",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_change_set",
                "get-change-set",
                vec![input.device.clone()],
            ),
        };
        audit.meta("change_set_id", input.change_set_id.clone());
        let result = async {
            let mut record = self
                .mutations
                .change_set(&input.change_set_id, &input.device)
                .await
                .map_err(coord_error)?;
            if matches!(
                record.state,
                ChangeSetState::Planned | ChangeSetState::Approved
            ) && now_unix()? >= record.expires_at_unix
            {
                record.state = ChangeSetState::Expired;
                self.mutations
                    .update_change_set(record.clone())
                    .await
                    .map_err(coord_error)?;
            }
            changeset_record_to_output(&record)
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Apply an independently approved change set as one guarded lifecycle operation.
    pub async fn apply_change_set(
        &self,
        input: ApplyChangeSetInput,
        ctx: Option<&CallerContext>,
        owner: &str,
        grant: Option<&MutationGrant>,
        cancellation: CancellationToken,
    ) -> Result<StageConfigOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "apply_panos_change_set",
                "apply",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "apply_panos_change_set",
                "apply",
                vec![input.device.clone()],
            ),
        };

        audit.meta("change_set_id", input.change_set_id.clone());
        audit.meta("digest", input.expected_digest.clone());

        validate_digest(&input.expected_digest, "expected_digest")?;
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        let mut change_set = self
            .mutations
            .change_set(&input.change_set_id, &input.device)
            .await?;
        if change_set.owner != owner {
            return Err(policy(
                "change_set_id",
                "only the principal that created the change set may apply it",
            ));
        }
        if change_set.state != ChangeSetState::Approved || change_set.approver.is_none() {
            return Err(policy(
                "change_set_id",
                "change set requires independent approval before apply",
            ));
        }
        if now_unix()? >= change_set.expires_at_unix {
            change_set.state = ChangeSetState::Expired;
            self.mutations.update_change_set(change_set).await?;
            return Err(policy("change_set_id", "approved change set expired"));
        }
        if change_set.digest != input.expected_digest
            || change_set.expected_candidate_fingerprint != input.expected_candidate_fingerprint
        {
            return Err(policy(
                "expected_digest",
                "apply input does not match the exact approved plan",
            ));
        }
        let client = self.client(&input.device)?;
        let inventory_policy = require_policy(&client)?.clone();
        // Records hold vendor-opaque JSON now; policy validation still works on
        // the typed actions, so bring them back before checking.
        let typed_actions: Vec<ChangeSetAction> = change_set
            .actions
            .iter()
            .map(|value| serde_json::from_value(value.clone()))
            .collect::<std::result::Result<Vec<_>, serde_json::Error>>()
            .map_err(|error| {
                PanosMcpError::Configuration(format!(
                    "stored change-set action is unreadable: {error}"
                ))
            })?;
        validate_change_set_actions(&typed_actions, &inventory_policy, grant)?;
        let _guard = self
            .mutations
            .device_guard(&client.mutation_lock_key(), &cancellation)
            .await?;
        if cancellation.is_cancelled() {
            return Err(PanosMcpError::Cancelled);
        }
        change_set = self
            .mutations
            .change_set(&input.change_set_id, &input.device)
            .await?;
        if change_set.owner != owner
            || change_set.state != ChangeSetState::Approved
            || change_set.approver.is_none()
            || change_set.digest != input.expected_digest
            || change_set.expected_candidate_fingerprint != input.expected_candidate_fingerprint
            || now_unix()? >= change_set.expires_at_unix
        {
            return Err(policy(
                "change_set_id",
                "change set is no longer the exact unexpired approved plan",
            ));
        }

        let operation_id = new_operation_id()?;
        let first_value = change_set
            .actions
            .first()
            .expect("validated change set is non-empty");
        let first: ChangeSetAction =
            serde_json::from_value(first_value.clone()).map_err(|error| {
                PanosMcpError::Configuration(format!("could not deserialize first action: {error}"))
            })?;

        let action_json = serialize_stage_action(first.action)?;
        let policy_sig = local_mutation_policy_signature(&inventory_policy);

        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: input.device.clone(),
            endpoint: client.mutation_lock_key(),
            action: action_json,
            xpath: Some(first.xpath.clone()),
            actions: change_set.actions.clone(),
            change_set_id: Some(change_set.id.clone()),
            current: input.expected_candidate_fingerprint.clone(),
            state: LifecycleState::Staging,
            job_id: None,
            details: None,
            config_lock_held: false,
            policy_signature: policy_sig,
            attribution: None,
            rollback_deadline_unix: None,
        };
        self.mutations
            .insert(record.clone())
            .await
            .map_err(coord_error)?;
        let mut config_lock_held = false;
        if inventory_policy.require_config_lock {
            if let Err(error) = acquire_config_lock(&client, &operation_id).await {
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
            config_lock_held = true;
            record.config_lock_held = true;
            if let Err(error) = self
                .mutations
                .update(record.clone())
                .await
                .map_err(coord_error)
            {
                release_config_lock_best_effort(&client).await;
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
        }
        let before = match candidate_fingerprint(&client, CancellationToken::new()).await {
            Ok(value) => value,
            Err(error) => {
                if config_lock_held {
                    release_config_lock_best_effort(&client).await;
                }
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
        };
        if let Err(error) = require_fingerprint(&input.expected_candidate_fingerprint, &before) {
            if config_lock_held {
                release_config_lock_best_effort(&client).await;
            }
            self.mutations.remove(&operation_id).await;
            return Err(error);
        }
        change_set.state = ChangeSetState::Applying;
        change_set.operation_id = Some(operation_id.clone());
        if let Err(error) = self
            .mutations
            .update_change_set(change_set.clone())
            .await
            .map_err(coord_error)
        {
            if config_lock_held {
                release_config_lock_best_effort(&client).await;
            }
            self.mutations.remove(&operation_id).await;
            return Err(error);
        }

        let mut applied = 0_usize;
        let apply_result: Result<()> = async {
            for action_value in &change_set.actions {
                let action: ChangeSetAction = serde_json::from_value(action_value.clone())
                    .map_err(|error| {
                        PanosMcpError::Configuration(format!(
                            "could not deserialize action: {error}"
                        ))
                    })?;
                let mut fields = vec![
                    ("type", "config".to_owned()),
                    ("action", action.action.api_name().to_owned()),
                    ("xpath", action.xpath.clone()),
                ];
                if let Some(element) = &action.element {
                    fields.push(("element", element.clone()));
                }
                client.post_fields(fields, CancellationToken::new()).await?;
                applied += 1;
            }
            Ok(())
        }
        .await;

        if let Err(error) = apply_result {
            let original = error.to_string();
            let reverted = if applied > 0 {
                revert_admin_candidate(&client, &inventory_policy.admin).await
            } else {
                Ok(())
            };
            record.state = if reverted.is_ok() {
                LifecycleState::Discarded
            } else {
                LifecycleState::Indeterminate
            };
            record.details = Some(match &reverted {
                Ok(()) => {
                    format!("apply failed after {applied} actions and was reverted: {original}")
                }
                Err(revert) => format!(
                    "apply failed after {applied} actions: {original}; automatic revert failed: {revert}"
                ),
            });
            if let Ok(current) = candidate_fingerprint(&client, CancellationToken::new()).await {
                record.current = current;
            }
            self.mutations
                .update(record.clone())
                .await
                .map_err(coord_error)?;
            change_set.state = ChangeSetState::Failed;
            change_set.operation_id = Some(operation_id.clone());
            self.mutations
                .update_change_set(change_set)
                .await
                .map_err(coord_error)?;
            if config_lock_held {
                release_config_lock_best_effort(&client).await;
            }
            audit.meta("operation_id", operation_id.clone());
            audit.fail(&error);
            return match reverted {
                Ok(()) => Err(error),
                Err(revert) => Err(PanosMcpError::Configuration(format!(
                    "change-set apply and automatic revert failed: {original}; {revert}"
                ))),
            };
        }

        let after = match candidate_fingerprint(&client, CancellationToken::new()).await {
            Ok(value) => value,
            Err(error) => {
                record.state = LifecycleState::Indeterminate;
                record.details = Some(format!(
                    "all actions were accepted but the resulting fingerprint could not be read: {error}"
                ));
                self.mutations.update(record).await.map_err(coord_error)?;
                change_set.state = ChangeSetState::Failed;
                change_set.operation_id = Some(operation_id.clone());
                self.mutations
                    .update_change_set(change_set)
                    .await
                    .map_err(coord_error)?;
                audit.meta("operation_id", operation_id);
                audit.fail(&error);
                return Err(error);
            }
        };
        record.current = after.clone();
        record.state = LifecycleState::Staged;
        self.mutations.update(record).await?;
        change_set.state = ChangeSetState::Applied;
        change_set.operation_id = Some(operation_id.clone());
        self.mutations.update_change_set(change_set.clone()).await?;

        audit.meta("operation_id", operation_id.clone());
        audit.meta("approver", change_set.approver.unwrap_or_default());
        audit.meta("action_count", change_set.actions.len() as u64);
        audit.succeed();

        Ok(StageConfigOutput {
            operation_id,
            device: input.device,
            before_fingerprint: before,
            candidate_fingerprint: after,
            config_lock_held,
        })
    }

    /// Stage one fingerprint-guarded candidate mutation.
    pub async fn stage_config(
        &self,
        input: StageConfigInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<StageConfigOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "stage_panos_config",
                "stage",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("stage_panos_config", "stage", vec![input.device.clone()]),
        };
        let client = self.client(&input.device)?;
        let policy = require_policy(&client)?.clone();
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        validate_write_xpath(&input.xpath, &policy.allowed_xpath_roots)?;
        validate_stage_payload(&input, policy.allow_delete)?;
        let _guard = self
            .mutations
            .device_guard(&client.mutation_lock_key(), &cancellation)
            .await
            .map_err(coord_error)?;
        if cancellation.is_cancelled() {
            return Err(PanosMcpError::Cancelled);
        }
        let operation_id = new_operation_id()?;

        let action_json = serialize_stage_action(input.action)?;
        let policy_sig = local_mutation_policy_signature(&policy);

        let action_value = serde_json::to_value(&ChangeSetAction {
            action: input.action,
            xpath: input.xpath.clone(),
            element: input.element.clone(),
            destructive_confirmation: input.destructive_confirmation.clone(),
        })
        .map_err(|error| {
            PanosMcpError::Configuration(format!("could not serialize action: {error}"))
        })?;

        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: input.device.clone(),
            endpoint: client.mutation_lock_key(),
            action: action_json,
            xpath: Some(input.xpath.clone()),
            actions: vec![action_value],
            change_set_id: None,
            current: input.expected_candidate_fingerprint.clone(),
            state: LifecycleState::Staging,
            job_id: None,
            details: None,
            config_lock_held: false,
            policy_signature: policy_sig,
            attribution: None,
            rollback_deadline_unix: None,
        };
        self.mutations
            .insert(record.clone())
            .await
            .map_err(coord_error)?;
        let mut config_lock_held = false;
        if policy.require_config_lock {
            if let Err(error) = acquire_config_lock(&client, &operation_id).await {
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
            config_lock_held = true;
            record.config_lock_held = true;
        }
        let result = async {
            let before = candidate_fingerprint(&client, CancellationToken::new()).await?;
            require_fingerprint(&input.expected_candidate_fingerprint, &before)?;
            let mut fields = vec![
                ("type", "config".to_owned()),
                ("action", input.action.api_name().to_owned()),
                ("xpath", input.xpath.clone()),
            ];
            if let Some(element) = &input.element {
                fields.push(("element", element.clone()));
            }
            client.post_fields(fields, CancellationToken::new()).await?;
            let after = candidate_fingerprint(&client, CancellationToken::new()).await?;
            record.current = after.clone();
            record.state = LifecycleState::Staged;
            self.mutations
                .update(record.clone())
                .await
                .map_err(coord_error)?;
            Ok(StageConfigOutput {
                operation_id: operation_id.clone(),
                device: input.device.clone(),
                before_fingerprint: before,
                candidate_fingerprint: after,
                config_lock_held,
            })
        }
        .await;
        if result.is_err() && config_lock_held {
            release_config_lock_best_effort(&client).await;
        }
        if result.is_err() {
            self.mutations.remove(&operation_id).await;
        }
        audit.meta("operation_id", operation_id.clone());
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Return a bounded PAN-OS candidate change summary.
    pub async fn diff_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<CandidateDiffOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "diff_panos_candidate",
                "diff",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("diff_panos_candidate", "diff", vec![input.device.clone()]),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
            validate_fingerprint(&input.expected_candidate_fingerprint)?;
            let record = self
                .mutations
                .record(&input.operation_id, owner, &input.device)
                .await
                .map_err(coord_error)?;
            let client = self.client(&input.device)?;
            let policy = require_policy(&client)?;
            let policy_sig = local_mutation_policy_signature(policy);
            mecmcp_changeset::require_operation_policy(&record, &policy_sig)
                .map_err(|e| crate::mutation::policy(e.field(), e.message()))?;
            let current = candidate_fingerprint(&client, cancellation.clone()).await?;
            mecmcp_changeset::require_operation_fingerprint(
                &record,
                &input.expected_candidate_fingerprint,
                &current,
            )
            .map_err(|e| crate::mutation::policy(e.field(), e.message()))?;
            let response = client
                .post_fields(
                    vec![
                        ("type", "op".to_owned()),
                        (
                            "cmd",
                            "<show><config><list><change-summary/></list></config></show>"
                                .to_owned(),
                        ),
                    ],
                    cancellation,
                )
                .await?;
            let (change_summary, truncated) = truncate_utf8(response.xml, MAX_DIFF_BYTES);
            let action = extract_stage_action(&record.action)?;
            let xpath = extract_xpath(&record).ok_or_else(|| {
                PanosMcpError::Configuration("operation record missing xpath".to_owned())
            })?;
            Ok(CandidateDiffOutput {
                operation_id: record.id,
                device: record.device,
                action,
                xpath,
                candidate_fingerprint: current,
                change_summary,
                truncated,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Validate the exact staged candidate and transition it to commit-eligible.
    pub async fn validate_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ValidationOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "validate_panos_candidate",
                "validate",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "validate_panos_candidate",
                "validate",
                vec![input.device.clone()],
            ),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
            validate_fingerprint(&input.expected_candidate_fingerprint)?;
            let mut record = self
                .mutations
                .record(&input.operation_id, owner, &input.device)
                .await?;
            if record.state != LifecycleState::Staged {
                return Err(policy("operation_id", "operation is not in staged state"));
            }
            let client = self.client(&input.device)?;
            require_operation_policy(&record, &client)?;
            let _guard = self
                .mutations
                .device_guard(&client.mutation_lock_key(), &cancellation)
                .await?;
            let current = candidate_fingerprint(&client, CancellationToken::new()).await?;
            require_operation_fingerprint(&input, &record, &current)?;
            let response = client
                .post_fields(
                    vec![
                        ("type", "op".to_owned()),
                        ("cmd", "<validate><full></full></validate>".to_owned()),
                    ],
                    CancellationToken::new(),
                )
                .await?;
            let job_id = parse_job_id(&response)?;
            record.job_id = Some(job_id.clone());
            record.state = LifecycleState::Validating;
            self.mutations.update(record.clone()).await?;
            let status = match client
                .poll_job(&job_id, VALIDATE_DEADLINE, CancellationToken::new())
                .await
            {
                Ok(status) => status,
                Err(error) => {
                    record.state = LifecycleState::Failed;
                    record.details = Some(error.to_string());
                    self.mutations.update(record.clone()).await?;
                    return Err(error);
                }
            };
            record.details = status.details.clone();
            record.state = if status.succeeded() {
                LifecycleState::Validated
            } else {
                LifecycleState::Failed
            };
            self.mutations.update(record.clone()).await?;
            Ok(ValidationOutput {
                operation_id: record.id,
                job_id,
                succeeded: status.succeeded(),
                details: status.details,
                candidate_fingerprint: current,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Start an admin-scoped partial commit and reconcile it in a detached worker.
    pub async fn commit_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<CommitOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "commit_panos_candidate",
                "commit",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "commit_panos_candidate",
                "commit",
                vec![input.device.clone()],
            ),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        let mut record = self
            .mutations
            .record(&input.operation_id, owner, &input.device)
            .await?;
        if record.state != LifecycleState::Validated {
            return Err(policy(
                "operation_id",
                "operation must validate successfully before commit",
            ));
        }
        let client = self.client(&input.device)?;
        let policy = require_policy(&client)?.clone();
        require_operation_policy(&record, &client)?;
        let current = candidate_fingerprint(&client, CancellationToken::new()).await?;
        require_operation_fingerprint(&input, &record, &current)?;
        record.state = LifecycleState::Committing;
        self.mutations.update(record.clone()).await?;

        let coordinator = self.mutations.clone();
        let owner = owner.to_owned();
        let operation_id = record.id.clone();
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let result = commit_worker(coordinator, client, policy.admin, record, &owner).await;
            let _ = sender.send(result);
        });
        tokio::select! {
            result = receiver => result.map_err(|_| PanosMcpError::Configuration("commit worker stopped without reconciliation".to_owned()))?,
            () = cancellation.cancelled() => Ok(CommitOutput {
                operation_id,
                disposition: CommitDisposition::Detached,
                job_id: None,
                succeeded: None,
                details: Some("commit continues in a detached reconciliation worker; poll operation status".to_owned()),
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

    /// Revert only candidate changes attributed by PAN-OS to the configured admin.
    pub async fn discard_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<DiscardOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "discard_panos_candidate",
                "discard",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "discard_panos_candidate",
                "discard",
                vec![input.device.clone()],
            ),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        let mut record = self
            .mutations
            .record(&input.operation_id, owner, &input.device)
            .await?;
        if matches!(
            record.state,
            LifecycleState::Validating
                | LifecycleState::Committing
                | LifecycleState::Committed
                | LifecycleState::Discarded
                | LifecycleState::Indeterminate
        ) {
            return Err(policy(
                "operation_id",
                "operation cannot be discarded in its current state",
            ));
        }
        let client = self.client(&input.device)?;
        let policy = require_policy(&client)?.clone();
        require_operation_policy(&record, &client)?;
        let _guard = self
            .mutations
            .device_guard(&client.mutation_lock_key(), &cancellation)
            .await?;
        let current = candidate_fingerprint(&client, CancellationToken::new()).await?;
        require_operation_fingerprint(&input, &record, &current)?;
        let command = format!(
            "<revert><config><partial><admin><member>{}</member></admin></partial></config></revert>",
            escape(&policy.admin)
        );
        client
            .post_fields(
                vec![("type", "op".to_owned()), ("cmd", command)],
                CancellationToken::new(),
            )
            .await?;
        let after = candidate_fingerprint(&client, CancellationToken::new()).await?;
        record.current = after.clone();
        if record.config_lock_held {
            if let Err(error) = release_config_lock(&client).await {
                let details = format!(
                    "discard succeeded but PAN-OS configuration lock release failed: {error}; manual job/candidate/lock reconciliation required"
                );
                record.state = LifecycleState::Indeterminate;
                record.details = Some(details.clone());
                self.mutations.update(record.clone()).await?;
                return Err(PanosMcpError::Configuration(details));
            }
            record.config_lock_held = false;
        }
        record.state = LifecycleState::Discarded;
        record.details = None;
        self.mutations.update(record.clone()).await?;
        Ok(DiscardOutput {
            operation_id: record.id,
            candidate_fingerprint: after,
        })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Poll safe in-memory state for a detached or completed operation.
    pub async fn operation_status(
        &self,
        input: OperationStatusInput,
        owner: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<OperationStatusOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_operation",
                "get-operation",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_operation",
                "get-operation",
                vec![input.device.clone()],
            ),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
            let record = self
                .mutations
                .record(&input.operation_id, owner, &input.device)
                .await?;
            Ok(OperationStatusOutput {
                operation_id: record.id,
                device: record.device,
                state: record.state.as_str().to_owned(),
                job_id: record.job_id,
                candidate_fingerprint: record.current,
                details: record.details,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }
}

async fn commit_worker(
    coordinator: Arc<ChangesetCoordinator>,
    client: Arc<PanosClient>,
    admin: String,
    mut record: OperationRecord,
    _owner: &str,
) -> Result<CommitOutput> {
    let guard = coordinator
        .device_guard(&client.mutation_lock_key(), &CancellationToken::new())
        .await?;
    let command = format!(
        "<commit><description>rust-panosmcp {}</description><partial><admin><member>{}</member></admin></partial></commit>",
        escape(&record.id),
        escape(&admin)
    );
    let mut result: Result<CommitOutput> = async {
        let response = client
            .post_fields(
                vec![
                    ("type", "commit".to_owned()),
                    ("action", "partial".to_owned()),
                    ("cmd", command),
                ],
                CancellationToken::new(),
            )
            .await?;
        let job_id = parse_job_id(&response)?;
        record.job_id = Some(job_id.clone());
        coordinator.update(record.clone()).await?;
        let status = client
            .poll_job(&job_id, COMMIT_DEADLINE, CancellationToken::new())
            .await?;
        let current = candidate_fingerprint(&client, CancellationToken::new()).await?;
        record.current = current;
        record.details = status.details.clone();
        record.state = if status.succeeded() {
            LifecycleState::Committing
        } else {
            LifecycleState::Failed
        };
        coordinator.update(record.clone()).await?;
        Ok(CommitOutput {
            operation_id: record.id.clone(),
            disposition: CommitDisposition::Reconciled,
            job_id: Some(job_id),
            succeeded: Some(status.succeeded()),
            details: status.details,
        })
    }
    .await;
    drop(guard);
    let commit_succeeded = result
        .as_ref()
        .is_ok_and(|output| output.succeeded == Some(true));
    if commit_succeeded && record.config_lock_held {
        match release_config_lock(&client).await {
            Ok(()) => {
                record.config_lock_held = false;
                record.state = LifecycleState::Committed;
            }
            Err(error) => {
                let details = format!(
                    "commit succeeded but PAN-OS configuration lock release failed: {error}; manual job/candidate/lock reconciliation required"
                );
                record.state = LifecycleState::Indeterminate;
                record.details = Some(details.clone());
                result = Err(PanosMcpError::Configuration(details));
            }
        }
    } else if commit_succeeded {
        record.state = LifecycleState::Committed;
    } else if let Err(error) = &result {
        record.state = LifecycleState::Indeterminate;
        record.details = Some(error.to_string());
    }
    coordinator.update(record.clone()).await?;
    result
}

fn require_policy(client: &PanosClient) -> Result<&crate::inventory::MutationPolicy> {
    client.mutation_policy().ok_or_else(|| {
        policy(
            "device",
            "candidate mutation is disabled by inventory policy",
        )
    })
}

fn require_operation_policy(record: &OperationRecord, client: &PanosClient) -> Result<()> {
    let current_policy = require_policy(client)?;
    if record.policy_signature == local_mutation_policy_signature(current_policy) {
        Ok(())
    } else {
        Err(policy(
            "operation_id",
            "inventory mutation policy changed after this operation staged; discard or recover manually",
        ))
    }
}

fn local_mutation_policy_signature(policy: &crate::inventory::MutationPolicy) -> String {
    // Use the original PAN-OS encoding (raw bytes + length prefixes) to maintain
    // compatibility with existing persisted operations. Operations created before
    // the migration used this encoding, and changing it would cause false policy
    // drift detection on restart.
    let mut digest = Sha256::new();
    digest.update(policy.admin.as_bytes());
    digest.update([u8::from(policy.allow_delete)]);
    digest.update([u8::from(policy.require_config_lock)]);
    for root in &policy.allowed_xpath_roots {
        digest.update((root.len() as u64).to_be_bytes());
        digest.update(root.as_bytes());
    }
    format!("sha256:{}", bytes_hex(&digest.finalize()))
}

fn validate_change_set_actions(
    actions: &[ChangeSetAction],
    inventory_policy: &crate::inventory::MutationPolicy,
    grant: Option<&MutationGrant>,
) -> Result<()> {
    if actions.is_empty() || actions.len() > MAX_CHANGE_SET_ACTIONS {
        return Err(policy(
            "actions",
            &format!("change set must contain 1-{MAX_CHANGE_SET_ACTIONS} actions"),
        ));
    }
    let encoded = serde_json::to_vec(actions).map_err(|error| {
        PanosMcpError::Configuration(format!("could not encode change set: {error}"))
    })?;
    if encoded.len() > MAX_CHANGE_SET_BYTES {
        return Err(policy(
            "actions",
            &format!("serialized change set exceeds {MAX_CHANGE_SET_BYTES} bytes"),
        ));
    }
    for action in actions {
        validate_write_xpath(&action.xpath, &inventory_policy.allowed_xpath_roots)?;
        let stage = StageConfigInput {
            device: String::new(),
            expected_candidate_fingerprint: String::new(),
            action: action.action,
            xpath: action.xpath.clone(),
            element: action.element.clone(),
            destructive_confirmation: action.destructive_confirmation.clone(),
        };
        validate_stage_payload(&stage, inventory_policy.allow_delete)?;
        if let Some(grant) = grant {
            if !grant.allows_action(action.action.into()) {
                return Err(policy(
                    "action",
                    "action is outside this token's mutation grant",
                ));
            }
            if !grant.allows_xpath(&action.xpath) {
                return Err(policy(
                    "xpath",
                    "XPath is outside this token's mutation grant",
                ));
            }
        }
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(policy(
            field,
            "value must use sha256:<64 lowercase hex> format",
        ));
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(policy(
            field,
            "value must use sha256:<64 lowercase hex> format",
        ))
    }
}

fn validate_stage_payload(input: &StageConfigInput, allow_delete: bool) -> Result<()> {
    match input.action {
        StageAction::Set => {
            let element = input
                .element
                .as_deref()
                .ok_or_else(|| policy("element", "set requires one XML element"))?;
            validate_config_element(element)?;
            if input.destructive_confirmation.is_some() {
                return Err(policy(
                    "destructive_confirmation",
                    "set must not carry delete confirmation",
                ));
            }
        }
        StageAction::Delete => {
            if !allow_delete {
                return Err(policy("action", "delete is disabled by inventory policy"));
            }
            if input.element.is_some() {
                return Err(policy("element", "delete must not carry an XML element"));
            }
            let expected = format!("DELETE {}", input.xpath);
            if input.destructive_confirmation.as_deref() != Some(expected.as_str()) {
                return Err(policy(
                    "destructive_confirmation",
                    "delete requires exact 'DELETE <xpath>' confirmation",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) async fn candidate_fingerprint(
    client: &PanosClient,
    cancellation: CancellationToken,
) -> Result<String> {
    let policy = require_policy(client)?;
    let mut digest = Sha256::new();
    for root in &policy.allowed_xpath_roots {
        if cancellation.is_cancelled() {
            return Err(PanosMcpError::Cancelled);
        }
        let response = client
            .configuration(true, root, cancellation.clone())
            .await?;
        digest.update((root.len() as u64).to_be_bytes());
        digest.update(root.as_bytes());
        digest.update((response.xml.len() as u64).to_be_bytes());
        digest.update(response.xml.as_bytes());
    }
    Ok(format!("sha256:{}", bytes_hex(&digest.finalize())))
}

fn require_fingerprint(expected: &str, actual: &str) -> Result<()> {
    validate_fingerprint(expected)?;
    if expected == actual {
        Ok(())
    } else {
        Err(policy(
            "expected_candidate_fingerprint",
            "candidate changed since the caller observed it",
        ))
    }
}

fn validate_fingerprint(value: &str) -> Result<()> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(policy(
            "expected_candidate_fingerprint",
            "value must use the sha256:<64 lowercase hex> format",
        ));
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(policy(
            "expected_candidate_fingerprint",
            "value must use the sha256:<64 lowercase hex> format",
        ))
    }
}

fn require_operation_fingerprint(
    input: &OperationInput,
    record: &OperationRecord,
    actual: &str,
) -> Result<()> {
    require_fingerprint(&input.expected_candidate_fingerprint, actual)?;
    if record.current == actual {
        Ok(())
    } else {
        Err(policy(
            "operation_id",
            "candidate changed after this operation staged",
        ))
    }
}

async fn acquire_config_lock(client: &PanosClient, operation_id: &str) -> Result<()> {
    let command = format!(
        "<request><config-lock><add><comment>rust-panosmcp {}</comment></add></config-lock></request>",
        escape(operation_id)
    );
    client
        .post_fields(
            vec![("type", "op".to_owned()), ("cmd", command)],
            CancellationToken::new(),
        )
        .await?;
    Ok(())
}

/// True when PAN-OS refused an unlock because nothing was locked.
///
/// PAN-OS reports this as a generic `code=-1` with only the message to
/// distinguish it, so the text is the only signal available. Matched
/// case-insensitively on the stable part of the phrase; the scope name it
/// appends ("for scope vsys1") varies per device.
fn is_already_unlocked(error: &PanosMcpError) -> bool {
    matches!(
        error,
        PanosMcpError::Api { message, .. }
            if message.to_ascii_lowercase().contains("not currently locked")
    )
}

pub(crate) async fn release_config_lock(client: &PanosClient) -> Result<()> {
    let outcome = client
        .post_fields(
            vec![
                ("type", "op".to_owned()),
                (
                    "cmd",
                    "<request><config-lock><remove></remove></config-lock></request>".to_owned(),
                ),
            ],
            CancellationToken::new(),
        )
        .await;

    match outcome {
        Ok(_) => Ok(()),
        // PAN-OS releases a vsys-scoped configuration lock as part of committing,
        // so the explicit release that follows a successful commit finds nothing
        // to remove. The post-condition being asserted is *no lock is held*, and
        // that holds — treating it as failure marked every successful commit
        // `Indeterminate` and, because one unreconciled operation is allowed per
        // endpoint, left the device blocked for the next change set (#75).
        //
        // This deliberately does not swallow other failures: an unreachable
        // device or a refused permission leaves the lock genuinely held, which is
        // exactly what `Indeterminate` is for.
        Err(error) if is_already_unlocked(&error) => {
            tracing::debug!(
                target: "audit",
                device = client.device_name(),
                "PAN-OS configuration lock was already released"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn release_config_lock_best_effort(client: &PanosClient) {
    if let Err(error) = release_config_lock(client).await {
        tracing::error!(target: "audit", device = client.device_name(), %error, "PAN-OS configuration lock release failed");
    }
}

pub(crate) async fn revert_admin_candidate(client: &PanosClient, admin: &str) -> Result<()> {
    let command = format!(
        "<revert><config><partial><admin><member>{}</member></admin></partial></config></revert>",
        escape(admin)
    );
    client
        .post_fields(
            vec![("type", "op".to_owned()), ("cmd", command)],
            CancellationToken::new(),
        )
        .await?;
    Ok(())
}

fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PanosMcpError::Configuration("system clock is before Unix epoch".to_owned()))
}

#[cfg(test)]
fn read_mutation_state(
    path: &std::path::Path,
) -> Result<mecmcp_changeset::persistence::ChangesetState> {
    mecmcp_changeset::persistence::read_state(path, MAX_STATE_BYTES).map_err(|error| {
        PanosMcpError::Configuration(format!("could not read mutation state: {error}"))
    })
}

#[cfg(test)]
fn write_mutation_state(
    path: &std::path::Path,
    state: &mecmcp_changeset::persistence::ChangesetState,
) -> Result<()> {
    mecmcp_changeset::persistence::write_state(path, state, MAX_STATE_BYTES).map_err(|error| {
        PanosMcpError::Configuration(format!("could not write mutation state: {error}"))
    })
}

fn new_operation_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| {
        PanosMcpError::Configuration("operating-system random source failed".to_owned())
    })?;
    Ok(digest_hex(&bytes))
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    bytes_hex(&digest)
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn truncate_utf8(mut value: String, limit: usize) -> (String, bool) {
    if value.len() <= limit {
        return (value, false);
    }
    let mut boundary = limit;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    (value, true)
}

fn policy(field: &'static str, reason: &str) -> PanosMcpError {
    PanosMcpError::Policy {
        field,
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_confirmation_and_element_policy_are_exact() {
        let mut input = StageConfigInput {
            device: "fw".to_owned(),
            expected_candidate_fingerprint: "sha256:x".to_owned(),
            action: StageAction::Delete,
            xpath: "/config/shared/address/entry[@name='x']".to_owned(),
            element: None,
            destructive_confirmation: None,
        };
        assert!(validate_stage_payload(&input, false).is_err());
        assert!(validate_stage_payload(&input, true).is_err());
        input.destructive_confirmation = Some(format!("DELETE {}", input.xpath));
        assert!(validate_stage_payload(&input, true).is_ok());

        input.action = StageAction::Set;
        input.destructive_confirmation = None;
        input.element = Some("<!DOCTYPE entry><entry/>".to_owned());
        assert!(validate_stage_payload(&input, true).is_err());
        input.element =
            Some("<entry name=\"x\"><ip-netmask>192.0.2.1</ip-netmask></entry>".to_owned());
        assert!(validate_stage_payload(&input, true).is_ok());
    }

    #[test]
    fn offline_resolution_requires_indeterminate_state_and_exact_confirmation() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("state.json");
        let id = "a".repeat(64);
        let record = OperationRecord {
            id: id.clone(),
            owner: "writer".to_owned(),
            device: "fw".to_owned(),
            endpoint: "https://fw.example:443".to_owned(),
            // The record now holds vendor-opaque JSON: the discriminator string
            // in `action`, the full object in `actions`, the target in `xpath` —
            // matching what the deployed reader on LXC 608 expects.
            action: serde_json::Value::String("set".to_owned()),
            xpath: Some("/config/shared/address".to_owned()),
            actions: vec![
                serde_json::to_value(ChangeSetAction {
                    action: StageAction::Set,
                    xpath: "/config/shared/address".to_owned(),
                    element: Some("<entry name=\"x\"/>".to_owned()),
                    destructive_confirmation: None,
                })
                .expect("action serializes"),
            ],
            change_set_id: None,
            current: format!("sha256:{}", "b".repeat(64)),
            state: LifecycleState::Staging,
            job_id: Some("123".to_owned()),
            details: None,
            config_lock_held: true,
            policy_signature: "policy".to_owned(),
            attribution: None,
            rollback_deadline_unix: None,
        };
        let mut state = mecmcp_changeset::persistence::ChangesetState::default();
        state.operations.insert(id.clone(), record);
        write_mutation_state(&path, &state).expect("state write");
        drop(
            ChangesetCoordinator::load(
                Some(&path),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(900),
                false,
            )
            .expect("restart recovery"),
        );
        assert_eq!(
            read_mutation_state(&path)
                .expect("recovered state")
                .operations[&id]
                .state,
            LifecycleState::Indeterminate
        );
        assert!(
            resolve_persisted_operation(
                &path,
                &id,
                RecoveryDisposition::Discarded,
                "not enough",
                mecmcp_changeset::OperationLimits::default(),
            )
            .is_err()
        );
        let output = resolve_persisted_operation(
            &path,
            &id,
            RecoveryDisposition::Discarded,
            &format!("RESOLVED {id} AS DISCARDED"),
            mecmcp_changeset::OperationLimits::default(),
        )
        .expect("resolve");
        assert_eq!(output.state, "discarded");
        assert!(!read_mutation_state(&path).expect("reload").operations[&id].config_lock_held);
    }
}

#[cfg(test)]
mod release_lock_tests {
    use super::*;

    fn api_error(message: &str) -> PanosMcpError {
        PanosMcpError::Api {
            device: "fw".to_owned(),
            code: -1,
            name: "unknown",
            message: message.to_owned(),
        }
    }

    /// The exact message observed from PAN-OS 12.1.5 after a commit released the
    /// vsys lock on our behalf (#75).
    #[test]
    fn already_unlocked_is_recognised() {
        assert!(is_already_unlocked(&api_error(
            "Config is not currently locked for scope vsys1"
        )));
        assert!(is_already_unlocked(&api_error(
            "config is NOT CURRENTLY LOCKED for scope shared"
        )));
    }

    /// A release that failed for a reason leaving the lock genuinely held must
    /// still surface. Swallowing these would report a device as unlocked while it
    /// silently blocks every later change.
    #[test]
    fn other_failures_are_not_swallowed() {
        assert!(!is_already_unlocked(&api_error("Permission denied")));
        assert!(!is_already_unlocked(&api_error(
            "Config is locked by another administrator"
        )));
        assert!(!is_already_unlocked(&PanosMcpError::HttpStatus {
            device: "fw".to_owned(),
            status: 503,
        }));
    }
}

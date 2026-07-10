//! Fingerprint-bound, per-device serialized PAN-OS candidate lifecycle.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    observability::AUDIT_TARGET,
    tools::PanosService,
    xml::{parse_job_id, validate_config_element, validate_write_xpath},
};
use quick_xml::escape::escape;
use rust_panosmcp_auth::{MutationAction, MutationGrant};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OwnedMutexGuard, oneshot};
use tokio_util::sync::CancellationToken;

const MAX_OPERATIONS: usize = 1024;
const MAX_CHANGE_SETS: usize = 1024;
const MAX_CHANGE_SET_ACTIONS: usize = 64;
const MAX_CHANGE_SET_BYTES: usize = 1024 * 1024;
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
const APPROVAL_TTL_SECS: u64 = 15 * 60;
const MAX_DIFF_BYTES: usize = 256 * 1024;
const VALIDATE_DEADLINE: Duration = Duration::from_secs(300);
const COMMIT_DEADLINE: Duration = Duration::from_secs(600);

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
    const fn api_name(self) -> &'static str {
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

/// Operator-confirmed terminal outcome after manual PAN-OS reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDisposition {
    /// PAN-OS evidence proves the operation committed.
    Committed,
    /// PAN-OS evidence proves the candidate changes were discarded.
    Discarded,
}

/// Resolve one persisted indeterminate operation after offline manual reconciliation.
pub fn resolve_persisted_operation(
    path: &Path,
    operation_id: &str,
    disposition: RecoveryDisposition,
    confirmation: &str,
) -> Result<OperationStatusOutput> {
    if !path.is_absolute() {
        return Err(PanosMcpError::Configuration(
            "mutation state path must be absolute".to_owned(),
        ));
    }
    validate_operation_id(operation_id)?;
    let word = match disposition {
        RecoveryDisposition::Committed => "COMMITTED",
        RecoveryDisposition::Discarded => "DISCARDED",
    };
    let expected = format!("RESOLVED {operation_id} AS {word}");
    if confirmation != expected {
        return Err(policy(
            "confirmation",
            "offline resolution requires exact 'RESOLVED <operation-id> AS COMMITTED|DISCARDED' confirmation",
        ));
    }
    let mut state = read_mutation_state(path)?;
    let record = state
        .operations
        .get_mut(operation_id)
        .ok_or_else(|| policy("operation_id", "unknown persisted operation"))?;
    if record.state != LifecycleState::Indeterminate {
        return Err(policy(
            "operation_id",
            "only an indeterminate operation can be resolved offline",
        ));
    }
    record.state = match disposition {
        RecoveryDisposition::Committed => LifecycleState::Committed,
        RecoveryDisposition::Discarded => LifecycleState::Discarded,
    };
    record.config_lock_held = false;
    record.details = Some(format!(
        "operator marked {word} after external PAN-OS job/candidate/lock reconciliation"
    ));
    let output = OperationStatusOutput {
        operation_id: record.id.clone(),
        device: record.device.clone(),
        state: record.state.as_str().to_owned(),
        job_id: record.job_id.clone(),
        candidate_fingerprint: record.current.clone(),
        details: record.details.clone(),
    };
    write_mutation_state(path, &state)?;
    Ok(output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleState {
    Staging,
    Staged,
    Validating,
    Validated,
    Committing,
    Committed,
    Discarded,
    Failed,
    Indeterminate,
}

impl LifecycleState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Staged => "staged",
            Self::Validating => "validating",
            Self::Validated => "validated",
            Self::Committing => "committing",
            Self::Committed => "committed",
            Self::Discarded => "discarded",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }

    const fn terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Discarded)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRecord {
    id: String,
    owner: String,
    device: String,
    endpoint: String,
    action: StageAction,
    xpath: String,
    #[serde(default)]
    actions: Vec<ChangeSetAction>,
    #[serde(default)]
    change_set_id: Option<String>,
    current: String,
    state: LifecycleState,
    job_id: Option<String>,
    details: Option<String>,
    config_lock_held: bool,
    policy_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChangeSetState {
    Planned,
    Approved,
    Applying,
    Applied,
    Expired,
    Failed,
}

impl ChangeSetState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Approved => "approved",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeSetRecord {
    id: String,
    owner: String,
    device: String,
    expected_candidate_fingerprint: String,
    actions: Vec<ChangeSetAction>,
    digest: String,
    state: ChangeSetState,
    approver: Option<String>,
    expires_at_unix: u64,
    operation_id: Option<String>,
}

impl From<ChangeSetRecord> for ChangeSetOutput {
    fn from(record: ChangeSetRecord) -> Self {
        Self {
            change_set_id: record.id,
            device: record.device,
            owner: record.owner,
            digest: record.digest,
            expected_candidate_fingerprint: record.expected_candidate_fingerprint,
            actions: record.actions,
            state: record.state.as_str().to_owned(),
            approver: record.approver,
            expires_at_unix: record.expires_at_unix,
            operation_id: record.operation_id,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationState {
    #[serde(default)]
    operations: BTreeMap<String, OperationRecord>,
    #[serde(default)]
    change_sets: BTreeMap<String, ChangeSetRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnDiskMutationState {
    version: u32,
    state: MutationState,
}

/// State shared across service reloads.
#[derive(Debug)]
pub(crate) struct MutationCoordinator {
    state: Mutex<MutationState>,
    endpoint_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    state_path: Option<PathBuf>,
}

impl Default for MutationCoordinator {
    fn default() -> Self {
        Self {
            state: Mutex::new(MutationState::default()),
            endpoint_locks: Mutex::new(BTreeMap::new()),
            state_path: None,
        }
    }
}

impl MutationCoordinator {
    pub(crate) fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if !path.is_absolute() {
            return Err(PanosMcpError::Configuration(
                "mutation state path must be absolute".to_owned(),
            ));
        }
        let mut state = if path.exists() {
            read_mutation_state(path)?
        } else {
            MutationState::default()
        };
        let mut recovered = false;
        for record in state.operations.values_mut() {
            if matches!(
                record.state,
                LifecycleState::Staging | LifecycleState::Validating | LifecycleState::Committing
            ) {
                record.state = LifecycleState::Indeterminate;
                record.details = Some(
                    "server restarted during a non-terminal PAN-OS operation; manual reconciliation required"
                        .to_owned(),
                );
                recovered = true;
            }
        }
        for record in state.change_sets.values_mut() {
            if record.state == ChangeSetState::Applying {
                record.state = ChangeSetState::Failed;
                recovered = true;
            }
        }
        if recovered {
            write_mutation_state(path, &state)?;
        }
        Ok(Self {
            state: Mutex::new(state),
            endpoint_locks: Mutex::new(BTreeMap::new()),
            state_path: Some(path.to_path_buf()),
        })
    }

    async fn device_guard(
        &self,
        endpoint: &str,
        cancellation: &CancellationToken,
    ) -> Result<OwnedMutexGuard<()>> {
        let lock = {
            let mut locks = self.endpoint_locks.lock().await;
            locks
                .entry(endpoint.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        tokio::select! {
            () = cancellation.cancelled() => Err(PanosMcpError::Cancelled),
            guard = lock.lock_owned() => Ok(guard),
        }
    }

    async fn record(
        &self,
        operation_id: &str,
        owner: &str,
        device: &str,
    ) -> Result<OperationRecord> {
        validate_operation_id(operation_id)?;
        let state = self.state.lock().await;
        let record = state
            .operations
            .get(operation_id)
            .ok_or_else(|| policy("operation_id", "unknown operation"))?;
        if record.owner != owner || record.device != device {
            return Err(policy(
                "operation_id",
                "operation is not owned by this principal and device",
            ));
        }
        Ok(record.clone())
    }

    async fn insert(&self, record: OperationRecord) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.operations.len() >= MAX_OPERATIONS {
            state
                .operations
                .retain(|_, record| !record.state.terminal());
        }
        if state.operations.len() >= MAX_OPERATIONS {
            return Err(policy("operation_id", "operation store is full"));
        }
        if state
            .operations
            .values()
            .any(|existing| existing.endpoint == record.endpoint && !existing.state.terminal())
        {
            return Err(policy(
                "operation_id",
                "the PAN-OS endpoint already has an active or unreconciled operation",
            ));
        }
        let id = record.id.clone();
        state.operations.insert(id.clone(), record);
        if let Err(error) = self.persist_locked(&state) {
            state.operations.remove(&id);
            return Err(error);
        }
        Ok(())
    }

    async fn update(&self, record: OperationRecord) -> Result<()> {
        let mut state = self.state.lock().await;
        let id = record.id.clone();
        let previous = state.operations.insert(id.clone(), record);
        if let Err(error) = self.persist_locked(&state) {
            match previous {
                Some(previous) => {
                    state.operations.insert(id, previous);
                }
                None => {
                    state.operations.remove(&id);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    async fn remove(&self, operation_id: &str) {
        let mut state = self.state.lock().await;
        state.operations.remove(operation_id);
        if let Err(error) = self.persist_locked(&state) {
            tracing::error!(target: AUDIT_TARGET, %error, "mutation state persistence failed");
        }
    }

    async fn insert_change_set(&self, record: ChangeSetRecord) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.change_sets.len() >= MAX_CHANGE_SETS {
            state.change_sets.retain(|_, existing| {
                !matches!(
                    existing.state,
                    ChangeSetState::Applied | ChangeSetState::Expired | ChangeSetState::Failed
                )
            });
        }
        if state.change_sets.len() >= MAX_CHANGE_SETS {
            return Err(policy("change_set_id", "change-set store is full"));
        }
        if state.change_sets.values().any(|existing| {
            existing.owner == record.owner
                && existing.device == record.device
                && matches!(
                    existing.state,
                    ChangeSetState::Planned | ChangeSetState::Approved | ChangeSetState::Applying
                )
        }) {
            return Err(policy(
                "change_set_id",
                "this principal already has a pending change set on the device",
            ));
        }
        let id = record.id.clone();
        state.change_sets.insert(id.clone(), record);
        if let Err(error) = self.persist_locked(&state) {
            state.change_sets.remove(&id);
            return Err(error);
        }
        Ok(())
    }

    async fn change_set(&self, id: &str, device: &str) -> Result<ChangeSetRecord> {
        validate_operation_id(id)?;
        let state = self.state.lock().await;
        let record = state
            .change_sets
            .get(id)
            .ok_or_else(|| policy("change_set_id", "unknown change set"))?;
        if record.device != device {
            return Err(policy(
                "change_set_id",
                "change set belongs to another device",
            ));
        }
        Ok(record.clone())
    }

    async fn update_change_set(&self, record: ChangeSetRecord) -> Result<()> {
        let mut state = self.state.lock().await;
        let id = record.id.clone();
        let previous = state.change_sets.insert(id.clone(), record);
        if let Err(error) = self.persist_locked(&state) {
            match previous {
                Some(previous) => {
                    state.change_sets.insert(id, previous);
                }
                None => {
                    state.change_sets.remove(&id);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn persist_locked(&self, state: &MutationState) -> Result<()> {
        if let Some(path) = &self.state_path {
            write_mutation_state(path, state)?;
        }
        Ok(())
    }
}

impl PanosService {
    /// Fingerprint every operator-authorized candidate subtree.
    pub async fn candidate_fingerprint(
        &self,
        input: CandidateFingerprintInput,
        cancellation: CancellationToken,
    ) -> Result<CandidateFingerprintOutput> {
        let client = self.client(&input.device)?;
        require_policy(&client)?;
        let candidate = candidate_fingerprint(&client, cancellation).await?;
        Ok(CandidateFingerprintOutput {
            device: input.device,
            candidate_fingerprint: candidate,
        })
    }

    /// Plan and persist an exact multi-action change set without mutating PAN-OS.
    pub async fn create_change_set(
        &self,
        input: CreateChangeSetInput,
        owner: &str,
        grant: Option<&MutationGrant>,
        cancellation: CancellationToken,
    ) -> Result<ChangeSetOutput> {
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        let client = self.client(&input.device)?;
        let policy = require_policy(&client)?;
        validate_change_set_actions(&input.actions, policy, grant)?;
        let current = candidate_fingerprint(&client, cancellation).await?;
        require_fingerprint(&input.expected_candidate_fingerprint, &current)?;
        let now = now_unix()?;
        let id = new_operation_id()?;
        let digest = change_set_digest(
            owner,
            &input.device,
            &input.expected_candidate_fingerprint,
            &input.actions,
        )?;
        let record = ChangeSetRecord {
            id,
            owner: owner.to_owned(),
            device: input.device,
            expected_candidate_fingerprint: input.expected_candidate_fingerprint,
            actions: input.actions,
            digest,
            state: ChangeSetState::Planned,
            approver: None,
            expires_at_unix: now.saturating_add(APPROVAL_TTL_SECS),
            operation_id: None,
        };
        self.mutations.insert_change_set(record.clone()).await?;
        Ok(record.into())
    }

    /// Approve the exact digest of another principal's unexpired plan.
    pub async fn approve_change_set(
        &self,
        input: ApproveChangeSetInput,
        approver: &str,
    ) -> Result<ChangeSetOutput> {
        validate_digest(&input.expected_digest, "expected_digest")?;
        let mut record = self
            .mutations
            .change_set(&input.change_set_id, &input.device)
            .await?;
        if record.owner == approver {
            return Err(policy(
                "change_set_id",
                "the change-set owner cannot approve their own plan",
            ));
        }
        if record.state != ChangeSetState::Planned {
            return Err(policy(
                "change_set_id",
                "change set is not awaiting approval",
            ));
        }
        if now_unix()? >= record.expires_at_unix {
            record.state = ChangeSetState::Expired;
            self.mutations.update_change_set(record).await?;
            return Err(policy(
                "change_set_id",
                "change-set approval window expired",
            ));
        }
        if record.digest != input.expected_digest {
            return Err(policy(
                "expected_digest",
                "digest does not match the exact stored change set",
            ));
        }
        record.state = ChangeSetState::Approved;
        record.approver = Some(approver.to_owned());
        self.mutations.update_change_set(record.clone()).await?;
        Ok(record.into())
    }

    /// Return an exact persistent plan for independent review or recovery.
    pub async fn change_set_status(&self, input: ChangeSetStatusInput) -> Result<ChangeSetOutput> {
        let mut record = self
            .mutations
            .change_set(&input.change_set_id, &input.device)
            .await?;
        if matches!(
            record.state,
            ChangeSetState::Planned | ChangeSetState::Approved
        ) && now_unix()? >= record.expires_at_unix
        {
            record.state = ChangeSetState::Expired;
            self.mutations.update_change_set(record.clone()).await?;
        }
        Ok(record.into())
    }

    /// Apply an independently approved change set as one guarded lifecycle operation.
    pub async fn apply_change_set(
        &self,
        input: ApplyChangeSetInput,
        owner: &str,
        grant: Option<&MutationGrant>,
        cancellation: CancellationToken,
    ) -> Result<StageConfigOutput> {
        let started = Instant::now();
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
        validate_change_set_actions(&change_set.actions, &inventory_policy, grant)?;
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
        let first = change_set
            .actions
            .first()
            .expect("validated change set is non-empty");
        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: input.device.clone(),
            endpoint: client.mutation_lock_key(),
            action: first.action,
            xpath: first.xpath.clone(),
            actions: change_set.actions.clone(),
            change_set_id: Some(change_set.id.clone()),
            current: input.expected_candidate_fingerprint.clone(),
            state: LifecycleState::Staging,
            job_id: None,
            details: None,
            config_lock_held: false,
            policy_signature: mutation_policy_signature(&inventory_policy),
        };
        self.mutations.insert(record.clone()).await?;
        let mut config_lock_held = false;
        if inventory_policy.require_config_lock {
            if let Err(error) = acquire_config_lock(&client, &operation_id).await {
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
            config_lock_held = true;
            record.config_lock_held = true;
            if let Err(error) = self.mutations.update(record.clone()).await {
                release_config_lock(&client).await;
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
        }
        let before = match candidate_fingerprint(&client, CancellationToken::new()).await {
            Ok(value) => value,
            Err(error) => {
                if config_lock_held {
                    release_config_lock(&client).await;
                }
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
        };
        if let Err(error) = require_fingerprint(&input.expected_candidate_fingerprint, &before) {
            if config_lock_held {
                release_config_lock(&client).await;
            }
            self.mutations.remove(&operation_id).await;
            return Err(error);
        }
        change_set.state = ChangeSetState::Applying;
        change_set.operation_id = Some(operation_id.clone());
        if let Err(error) = self.mutations.update_change_set(change_set.clone()).await {
            if config_lock_held {
                release_config_lock(&client).await;
            }
            self.mutations.remove(&operation_id).await;
            return Err(error);
        }

        let mut applied = 0_usize;
        let apply_result: Result<()> = async {
            for action in &change_set.actions {
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
            self.mutations.update(record.clone()).await?;
            change_set.state = ChangeSetState::Failed;
            change_set.operation_id = Some(operation_id.clone());
            self.mutations.update_change_set(change_set).await?;
            if config_lock_held {
                release_config_lock(&client).await;
            }
            audit(
                AuditEvent {
                    owner,
                    device: &input.device,
                    operation_id: &operation_id,
                    action: "apply_change_set",
                    xpath: &record.xpath,
                },
                false,
                started.elapsed(),
                None,
            );
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
                self.mutations.update(record).await?;
                change_set.state = ChangeSetState::Failed;
                change_set.operation_id = Some(operation_id);
                self.mutations.update_change_set(change_set).await?;
                return Err(error);
            }
        };
        record.current = after.clone();
        record.state = LifecycleState::Staged;
        self.mutations.update(record).await?;
        change_set.state = ChangeSetState::Applied;
        change_set.operation_id = Some(operation_id.clone());
        self.mutations.update_change_set(change_set).await?;
        audit(
            AuditEvent {
                owner,
                device: &input.device,
                operation_id: &operation_id,
                action: "apply_change_set",
                xpath: &input.change_set_id,
            },
            true,
            started.elapsed(),
            None,
        );
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
        cancellation: CancellationToken,
    ) -> Result<StageConfigOutput> {
        let started = Instant::now();
        let client = self.client(&input.device)?;
        let policy = require_policy(&client)?.clone();
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        validate_write_xpath(&input.xpath, &policy.allowed_xpath_roots)?;
        validate_stage_payload(&input, policy.allow_delete)?;
        let _guard = self
            .mutations
            .device_guard(&client.mutation_lock_key(), &cancellation)
            .await?;
        if cancellation.is_cancelled() {
            return Err(PanosMcpError::Cancelled);
        }
        let operation_id = new_operation_id()?;
        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: input.device.clone(),
            endpoint: client.mutation_lock_key(),
            action: input.action,
            xpath: input.xpath.clone(),
            actions: vec![ChangeSetAction {
                action: input.action,
                xpath: input.xpath.clone(),
                element: input.element.clone(),
                destructive_confirmation: input.destructive_confirmation.clone(),
            }],
            change_set_id: None,
            current: input.expected_candidate_fingerprint.clone(),
            state: LifecycleState::Staging,
            job_id: None,
            details: None,
            config_lock_held: false,
            policy_signature: mutation_policy_signature(&policy),
        };
        self.mutations.insert(record.clone()).await?;
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
            self.mutations.update(record.clone()).await?;
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
            release_config_lock(&client).await;
        }
        if result.is_err() {
            self.mutations.remove(&operation_id).await;
        }
        audit(
            AuditEvent {
                owner,
                device: &input.device,
                operation_id: &operation_id,
                action: input.action.api_name(),
                xpath: &input.xpath,
            },
            result.is_ok(),
            started.elapsed(),
            None,
        );
        result
    }

    /// Return a bounded PAN-OS candidate change summary.
    pub async fn diff_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        cancellation: CancellationToken,
    ) -> Result<CandidateDiffOutput> {
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        let record = self
            .mutations
            .record(&input.operation_id, owner, &input.device)
            .await?;
        let client = self.client(&input.device)?;
        require_operation_policy(&record, &client)?;
        let current = candidate_fingerprint(&client, cancellation.clone()).await?;
        require_operation_fingerprint(&input, &record, &current)?;
        let response = client
            .post_fields(
                vec![
                    ("type", "op".to_owned()),
                    (
                        "cmd",
                        "<show><config><list><change-summary/></list></config></show>".to_owned(),
                    ),
                ],
                cancellation,
            )
            .await?;
        let (change_summary, truncated) = truncate_utf8(response.xml, MAX_DIFF_BYTES);
        Ok(CandidateDiffOutput {
            operation_id: record.id,
            device: record.device,
            action: record.action,
            xpath: record.xpath,
            candidate_fingerprint: current,
            change_summary,
            truncated,
        })
    }

    /// Validate the exact staged candidate and transition it to commit-eligible.
    pub async fn validate_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        cancellation: CancellationToken,
    ) -> Result<ValidationOutput> {
        let started = Instant::now();
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
                audit(
                    AuditEvent {
                        owner,
                        device: &record.device,
                        operation_id: &record.id,
                        action: "validate",
                        xpath: &record.xpath,
                    },
                    false,
                    started.elapsed(),
                    Some(&job_id),
                );
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
        audit(
            AuditEvent {
                owner,
                device: &record.device,
                operation_id: &record.id,
                action: "validate",
                xpath: &record.xpath,
            },
            status.succeeded(),
            started.elapsed(),
            Some(&job_id),
        );
        Ok(ValidationOutput {
            operation_id: record.id,
            job_id,
            succeeded: status.succeeded(),
            details: status.details,
            candidate_fingerprint: current,
        })
    }

    /// Start an admin-scoped partial commit and reconcile it in a detached worker.
    pub async fn commit_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        cancellation: CancellationToken,
    ) -> Result<CommitOutput> {
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

    /// Revert only candidate changes attributed by PAN-OS to the configured admin.
    pub async fn discard_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        cancellation: CancellationToken,
    ) -> Result<DiscardOutput> {
        let started = Instant::now();
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
        record.state = LifecycleState::Discarded;
        record.details = None;
        self.mutations.update(record.clone()).await?;
        if record.config_lock_held {
            release_config_lock(&client).await;
        }
        audit(
            AuditEvent {
                owner,
                device: &record.device,
                operation_id: &record.id,
                action: "discard",
                xpath: &record.xpath,
            },
            true,
            started.elapsed(),
            None,
        );
        Ok(DiscardOutput {
            operation_id: record.id,
            candidate_fingerprint: after,
        })
    }

    /// Poll safe in-memory state for a detached or completed operation.
    pub async fn operation_status(
        &self,
        input: OperationStatusInput,
        owner: &str,
    ) -> Result<OperationStatusOutput> {
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
}

async fn commit_worker(
    coordinator: Arc<MutationCoordinator>,
    client: Arc<PanosClient>,
    admin: String,
    mut record: OperationRecord,
    owner: &str,
) -> Result<CommitOutput> {
    let started = Instant::now();
    let guard = coordinator
        .device_guard(&client.mutation_lock_key(), &CancellationToken::new())
        .await?;
    let command = format!(
        "<commit><description>rust-panosmcp {}</description><partial><admin><member>{}</member></admin></partial></commit>",
        escape(&record.id),
        escape(&admin)
    );
    let result: Result<CommitOutput> = async {
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
            LifecycleState::Committed
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
    let release_lock = result
        .as_ref()
        .is_ok_and(|output| output.succeeded == Some(true));
    if record.config_lock_held && release_lock {
        release_config_lock(&client).await;
        record.config_lock_held = false;
    }
    if let Err(error) = &result {
        record.state = LifecycleState::Indeterminate;
        record.details = Some(error.to_string());
    }
    coordinator.update(record.clone()).await?;
    audit(
        AuditEvent {
            owner,
            device: &record.device,
            operation_id: &record.id,
            action: "commit",
            xpath: &record.xpath,
        },
        result
            .as_ref()
            .is_ok_and(|output| output.succeeded == Some(true)),
        started.elapsed(),
        record.job_id.as_deref(),
    );
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
    if record.policy_signature == mutation_policy_signature(current_policy) {
        Ok(())
    } else {
        Err(policy(
            "operation_id",
            "inventory mutation policy changed after this operation staged; discard or recover manually",
        ))
    }
}

fn mutation_policy_signature(policy: &crate::inventory::MutationPolicy) -> String {
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

fn change_set_digest(
    owner: &str,
    device: &str,
    fingerprint: &str,
    actions: &[ChangeSetAction],
) -> Result<String> {
    let canonical =
        serde_json::to_vec(&(owner, device, fingerprint, actions)).map_err(|error| {
            PanosMcpError::Configuration(format!("could not encode change-set digest: {error}"))
        })?;
    Ok(format!("sha256:{}", digest_hex(&canonical)))
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

async fn candidate_fingerprint(
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

fn validate_operation_id(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(policy(
            "operation_id",
            "value must contain exactly 64 hexadecimal characters",
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

async fn release_config_lock(client: &PanosClient) {
    let result = client
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
    if let Err(error) = result {
        tracing::error!(target: AUDIT_TARGET, device = client.device_name(), %error, "PAN-OS configuration lock release failed");
    }
}

async fn revert_admin_candidate(client: &PanosClient, admin: &str) -> Result<()> {
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

fn read_mutation_state(path: &Path) -> Result<MutationState> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        PanosMcpError::Configuration(format!(
            "could not inspect mutation state '{}': {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PanosMcpError::Configuration(
            "mutation state must be a regular non-symlink file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(PanosMcpError::Configuration(
                "mutation state must not permit group/other access".to_owned(),
            ));
        }
        let owner = metadata.uid();
        let effective = rustix::process::geteuid().as_raw();
        if owner != effective && owner != 0 {
            return Err(PanosMcpError::Configuration(format!(
                "mutation state owner uid {owner} is neither effective uid {effective} nor root"
            )));
        }
    }
    if metadata.len() > MAX_STATE_BYTES {
        return Err(PanosMcpError::Configuration(format!(
            "mutation state exceeds {MAX_STATE_BYTES} bytes"
        )));
    }
    let file = fs::File::open(path).map_err(|error| {
        PanosMcpError::Configuration(format!(
            "could not open mutation state '{}': {error}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PanosMcpError::Configuration(format!("could not read mutation state: {error}"))
        })?;
    let on_disk: OnDiskMutationState = serde_json::from_slice(&bytes).map_err(|error| {
        PanosMcpError::Configuration(format!("invalid mutation state JSON: {error}"))
    })?;
    if on_disk.version != 1 {
        return Err(PanosMcpError::Configuration(format!(
            "unsupported mutation state version {}",
            on_disk.version
        )));
    }
    validate_mutation_state(&on_disk.state)?;
    Ok(on_disk.state)
}

fn validate_mutation_state(state: &MutationState) -> Result<()> {
    if state.operations.len() > MAX_OPERATIONS || state.change_sets.len() > MAX_CHANGE_SETS {
        return Err(PanosMcpError::Configuration(
            "mutation state contains too many records".to_owned(),
        ));
    }
    for (id, record) in &state.operations {
        validate_operation_id(id)?;
        if id != &record.id || record.owner.is_empty() || record.device.is_empty() {
            return Err(PanosMcpError::Configuration(
                "mutation state contains an inconsistent operation record".to_owned(),
            ));
        }
        validate_fingerprint(&record.current)?;
        if !record.endpoint.starts_with("https://") || record.actions.is_empty() {
            return Err(PanosMcpError::Configuration(
                "mutation state operation is missing endpoint/action metadata".to_owned(),
            ));
        }
    }
    for (id, record) in &state.change_sets {
        validate_operation_id(id)?;
        if id != &record.id || record.owner.is_empty() || record.device.is_empty() {
            return Err(PanosMcpError::Configuration(
                "mutation state contains an inconsistent change-set record".to_owned(),
            ));
        }
        validate_fingerprint(&record.expected_candidate_fingerprint)?;
        validate_digest(&record.digest, "digest")?;
        if record.actions.is_empty() || record.actions.len() > MAX_CHANGE_SET_ACTIONS {
            return Err(PanosMcpError::Configuration(
                "mutation state change set has an invalid action count".to_owned(),
            ));
        }
        let expected = change_set_digest(
            &record.owner,
            &record.device,
            &record.expected_candidate_fingerprint,
            &record.actions,
        )?;
        if expected != record.digest {
            return Err(PanosMcpError::Configuration(
                "mutation state change-set digest mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

fn write_mutation_state(path: &Path, state: &MutationState) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        PanosMcpError::Configuration("mutation state path has no parent".to_owned())
    })?;
    let payload = serde_json::to_vec_pretty(&OnDiskMutationState {
        version: 1,
        state: MutationState {
            operations: state.operations.clone(),
            change_sets: state.change_sets.clone(),
        },
    })
    .map_err(|error| {
        PanosMcpError::Configuration(format!("could not serialize mutation state: {error}"))
    })?;
    if payload.len() as u64 > MAX_STATE_BYTES {
        return Err(PanosMcpError::Configuration(format!(
            "serialized mutation state exceeds {MAX_STATE_BYTES} bytes"
        )));
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".rust-panosmcp-state-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|error| {
            PanosMcpError::Configuration(format!("could not create mutation state: {error}"))
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                PanosMcpError::Configuration(format!("could not secure mutation state: {error}"))
            })?;
    }
    temporary.write_all(&payload).map_err(|error| {
        PanosMcpError::Configuration(format!("could not write mutation state: {error}"))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        PanosMcpError::Configuration(format!("could not sync mutation state: {error}"))
    })?;
    temporary.persist(path).map_err(|error| {
        PanosMcpError::Configuration(format!("could not replace mutation state: {}", error.error))
    })?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            PanosMcpError::Configuration(format!("could not sync state directory: {error}"))
        })?;
    Ok(())
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

struct AuditEvent<'a> {
    owner: &'a str,
    device: &'a str,
    operation_id: &'a str,
    action: &'a str,
    xpath: &'a str,
}

fn audit(event: AuditEvent<'_>, succeeded: bool, duration: Duration, job_id: Option<&str>) {
    let xpath_fingerprint = format!("sha256:{}", digest_hex(event.xpath.as_bytes()));
    tracing::info!(
        target: AUDIT_TARGET,
        principal = event.owner,
        device = event.device,
        operation_id = event.operation_id,
        action = event.action,
        xpath_fingerprint,
        job_id = job_id.unwrap_or("none"),
        succeeded,
        duration_ms = duration.as_millis(),
        "PAN-OS candidate lifecycle"
    );
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
            action: StageAction::Set,
            xpath: "/config/shared/address".to_owned(),
            actions: vec![ChangeSetAction {
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some("<entry name=\"x\"/>".to_owned()),
                destructive_confirmation: None,
            }],
            change_set_id: None,
            current: format!("sha256:{}", "b".repeat(64)),
            state: LifecycleState::Staging,
            job_id: Some("123".to_owned()),
            details: None,
            config_lock_held: true,
            policy_signature: "policy".to_owned(),
        };
        let mut state = MutationState::default();
        state.operations.insert(id.clone(), record);
        write_mutation_state(&path, &state).expect("state write");
        drop(MutationCoordinator::load(Some(&path)).expect("restart recovery"));
        assert_eq!(
            read_mutation_state(&path)
                .expect("recovered state")
                .operations[&id]
                .state,
            LifecycleState::Indeterminate
        );
        assert!(
            resolve_persisted_operation(&path, &id, RecoveryDisposition::Discarded, "not enough",)
                .is_err()
        );
        let output = resolve_persisted_operation(
            &path,
            &id,
            RecoveryDisposition::Discarded,
            &format!("RESOLVED {id} AS DISCARDED"),
        )
        .expect("resolve");
        assert_eq!(output.state, "discarded");
        assert!(!read_mutation_state(&path).expect("reload").operations[&id].config_lock_held);
    }
}

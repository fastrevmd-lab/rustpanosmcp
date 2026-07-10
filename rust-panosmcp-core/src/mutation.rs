//! Fingerprint-bound, per-device serialized PAN-OS candidate lifecycle.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    observability::AUDIT_TARGET,
    tools::PanosService,
    xml::{parse_job_id, validate_config_element, validate_write_xpath},
};
use quick_xml::escape::escape;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedMutexGuard, oneshot};
use tokio_util::sync::CancellationToken;

const MAX_OPERATIONS: usize = 1024;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
struct OperationRecord {
    id: String,
    owner: String,
    device: String,
    action: StageAction,
    xpath: String,
    current: String,
    state: LifecycleState,
    job_id: Option<String>,
    details: Option<String>,
    config_lock_held: bool,
    policy_signature: String,
}

/// State shared across service reloads.
#[derive(Debug, Default)]
pub(crate) struct MutationCoordinator {
    operations: Mutex<BTreeMap<String, OperationRecord>>,
    device_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
}

impl MutationCoordinator {
    async fn device_guard(
        &self,
        device: &str,
        cancellation: &CancellationToken,
    ) -> Result<OwnedMutexGuard<()>> {
        let lock = {
            let mut locks = self.device_locks.lock().await;
            locks
                .entry(device.to_owned())
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
        let operations = self.operations.lock().await;
        let record = operations
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
        let mut operations = self.operations.lock().await;
        if operations.len() >= MAX_OPERATIONS {
            operations.retain(|_, record| !record.state.terminal());
        }
        if operations.len() >= MAX_OPERATIONS {
            return Err(policy("operation_id", "operation store is full"));
        }
        if operations.values().any(|existing| {
            existing.owner == record.owner
                && existing.device == record.device
                && !existing.state.terminal()
        }) {
            return Err(policy(
                "operation_id",
                "this principal already has an active operation on the device",
            ));
        }
        operations.insert(record.id.clone(), record);
        Ok(())
    }

    async fn update(&self, record: OperationRecord) {
        self.operations
            .lock()
            .await
            .insert(record.id.clone(), record);
    }

    async fn remove(&self, operation_id: &str) {
        self.operations.lock().await.remove(operation_id);
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
            .device_guard(&input.device, &cancellation)
            .await?;
        if cancellation.is_cancelled() {
            return Err(PanosMcpError::Cancelled);
        }
        let operation_id = new_operation_id()?;
        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: input.device.clone(),
            action: input.action,
            xpath: input.xpath.clone(),
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
            self.mutations.update(record.clone()).await;
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
            .device_guard(&input.device, &cancellation)
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
        self.mutations.update(record.clone()).await;
        let status = match client
            .poll_job(&job_id, VALIDATE_DEADLINE, CancellationToken::new())
            .await
        {
            Ok(status) => status,
            Err(error) => {
                record.state = LifecycleState::Failed;
                record.details = Some(error.to_string());
                self.mutations.update(record.clone()).await;
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
        self.mutations.update(record.clone()).await;
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
        self.mutations.update(record.clone()).await;

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
            .device_guard(&input.device, &cancellation)
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
        self.mutations.update(record.clone()).await;
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
        .device_guard(client.device_name(), &CancellationToken::new())
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
        coordinator.update(record.clone()).await;
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
        coordinator.update(record.clone()).await;
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
    coordinator.update(record.clone()).await;
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
}

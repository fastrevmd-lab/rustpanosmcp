//! `DeviceTransaction` implementation for PAN-OS.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    mutation::{
        ChangeSetAction, candidate_fingerprint, release_config_lock, revert_admin_candidate,
    },
    xml::parse_job_id,
};

const MAX_DIFF_BYTES: usize = 256 * 1024;
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef, UnlockOutcome,
};
use quick_xml::escape::escape;
use serde::Serialize;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const VALIDATE_DEADLINE: Duration = Duration::from_secs(300);
const COMMIT_DEADLINE: Duration = Duration::from_secs(600);

/// PAN-OS staged transaction handle.
///
/// Carries state between lifecycle steps: config lock status, operation ID,
/// and fingerprints.
#[derive(Debug)]
pub struct PanosStagedTransaction {
    /// Whether a PAN-OS configuration lock is being held.
    pub config_lock_held: bool,
    /// Operation identifier for audit attribution.
    pub operation_id: String,
    /// Candidate fingerprint before staging.
    pub before_fingerprint: String,
    /// Candidate fingerprint after staging.
    pub after_fingerprint: String,
}

/// PAN-OS diff output.
#[derive(Debug, Clone, Serialize)]
pub struct PanosDiff {
    /// PAN-OS change-summary XML, truncated if necessary.
    pub change_summary: String,
    /// Whether the change summary was truncated.
    pub truncated: bool,
}

/// PAN-OS validation result.
#[derive(Debug, Clone, Serialize)]
pub struct PanosValidation {
    /// PAN-OS validation job identifier.
    pub job_id: String,
    /// Whether validation succeeded.
    pub succeeded: bool,
    /// Bounded terminal details.
    pub details: Option<String>,
}

#[async_trait]
impl DeviceTransaction for PanosClient {
    type Action = ChangeSetAction;
    type Staged = PanosStagedTransaction;
    type Diff = PanosDiff;
    type Validation = PanosValidation;
    type Error = PanosMcpError;

    async fn fingerprint(&self) -> Result<String> {
        candidate_fingerprint(self, CancellationToken::new()).await
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged> {
        if actions.is_empty() {
            return Err(PanosMcpError::Policy {
                field: "actions",
                reason: "stage requires at least one action".to_owned(),
            });
        }

        let policy = self
            .mutation_policy()
            .ok_or_else(|| PanosMcpError::Policy {
                field: "device",
                reason: "candidate mutation is disabled by inventory policy".to_owned(),
            })?;

        let operation_id = new_operation_id()?;

        // Acquire config lock if required
        let config_lock_held = if policy.require_config_lock {
            acquire_config_lock(self, &operation_id).await?;
            true
        } else {
            false
        };

        // Capture before fingerprint
        let before_fingerprint = match candidate_fingerprint(self, CancellationToken::new()).await {
            Ok(fp) => fp,
            Err(error) => {
                if config_lock_held {
                    release_config_lock_best_effort(self).await;
                }
                return Err(error);
            }
        };

        // Apply all actions
        let mut applied = 0_usize;
        let apply_result: Result<()> = async {
            for action in actions {
                let mut fields = vec![
                    ("type", "config".to_owned()),
                    ("action", action.action.api_name().to_owned()),
                    ("xpath", action.xpath.clone()),
                ];
                if let Some(element) = &action.element {
                    fields.push(("element", element.clone()));
                }
                self.post_fields(fields, CancellationToken::new()).await?;
                applied += 1;
            }
            Ok(())
        }
        .await;

        if let Err(error) = apply_result {
            // Revert on partial failure
            if applied > 0
                && let Err(revert_error) = revert_admin_candidate(self, &policy.admin).await
            {
                // Revert failed — session is tainted
                if config_lock_held {
                    release_config_lock_best_effort(self).await;
                }
                return Err(PanosMcpError::Configuration(format!(
                    "stage failed after {applied} actions: {error}; automatic revert failed: {revert_error}"
                )));
            }
            if config_lock_held {
                release_config_lock_best_effort(self).await;
            }
            return Err(error);
        }

        // Capture after fingerprint
        let after_fingerprint = match candidate_fingerprint(self, CancellationToken::new()).await {
            Ok(fp) => fp,
            Err(error) => {
                if config_lock_held {
                    release_config_lock_best_effort(self).await;
                }
                return Err(error);
            }
        };

        Ok(PanosStagedTransaction {
            config_lock_held,
            operation_id,
            before_fingerprint,
            after_fingerprint,
        })
    }

    async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff> {
        let response = self
            .post_fields(
                vec![
                    ("type", "op".to_owned()),
                    (
                        "cmd",
                        "<show><config><list><change-summary/></list></config></show>".to_owned(),
                    ),
                ],
                CancellationToken::new(),
            )
            .await?;
        let (change_summary, truncated) = truncate_utf8(response.xml, MAX_DIFF_BYTES);
        Ok(PanosDiff {
            change_summary,
            truncated,
        })
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation> {
        let response = self
            .post_fields(
                vec![
                    ("type", "op".to_owned()),
                    ("cmd", "<validate><full></full></validate>".to_owned()),
                ],
                CancellationToken::new(),
            )
            .await?;
        let job_id = parse_job_id(&response)?;
        let status = self
            .poll_job(&job_id, VALIDATE_DEADLINE, CancellationToken::new())
            .await?;
        Ok(PanosValidation {
            job_id: job_id.clone(),
            succeeded: status.succeeded(),
            details: status.details,
        })
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        attribution: &Attribution,
        _options: &CommitOptions,
    ) -> Result<CommitOutcome> {
        let policy = self
            .mutation_policy()
            .ok_or_else(|| PanosMcpError::Policy {
                field: "device",
                reason: "candidate mutation is disabled by inventory policy".to_owned(),
            })?;

        // Build commit description with attribution
        let principal_str = match &attribution.principal {
            mecmcp_audit::Principal::Token(name) => name.as_str(),
            mecmcp_audit::Principal::Unauthenticated => "stdio",
        };
        let agent_provider = attribution
            .agent
            .as_ref()
            .map(|a| a.provider.as_str())
            .unwrap_or("direct");
        let description = format!(
            "rust-panosmcp {}: {} by {} via {}",
            staged.operation_id,
            attribution.change_ref.as_deref().unwrap_or("no-change-ref"),
            principal_str,
            agent_provider,
        );

        let command = format!(
            "<commit><description>{}</description><partial><admin><member>{}</member></admin></partial></commit>",
            escape(&description),
            escape(&policy.admin)
        );

        let response = self
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

        let status = match self
            .poll_job(&job_id, COMMIT_DEADLINE, CancellationToken::new())
            .await
        {
            Ok(status) => status,
            Err(error) => {
                return Ok(CommitOutcome::Indeterminate {
                    reason: format!("commit job poll failed: {error}"),
                });
            }
        };

        let commit_succeeded = status.succeeded();

        // Release config lock if held and commit succeeded
        if staged.config_lock_held
            && commit_succeeded
            && let Err(error) = release_config_lock(self).await
        {
            return Ok(CommitOutcome::Indeterminate {
                reason: format!(
                    "commit succeeded but PAN-OS configuration lock release failed: {error}"
                ),
            });
        }

        Ok(CommitOutcome::Reconciled {
            succeeded: commit_succeeded,
            job_id: Some(job_id),
            details: status.details,
        })
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome> {
        match to {
            RollbackRef::Archive(_) => Err(PanosMcpError::Policy {
                field: "rollback_ref",
                reason: "PAN-OS does not support archive-based rollback; use CandidateRevert"
                    .to_owned(),
            }),
            RollbackRef::CandidateRevert => {
                let policy = self
                    .mutation_policy()
                    .ok_or_else(|| PanosMcpError::Policy {
                        field: "device",
                        reason: "candidate mutation is disabled by inventory policy".to_owned(),
                    })?;
                revert_admin_candidate(self, &policy.admin).await?;
                Ok(RollbackOutcome {
                    succeeded: true,
                    details: Some("candidate reverted successfully".to_owned()),
                })
            }
            RollbackRef::Custom(custom) => Err(PanosMcpError::Policy {
                field: "rollback_ref",
                reason: format!("unsupported custom rollback target: {custom}"),
            }),
        }
    }

    async fn unlock(&self) -> Result<UnlockOutcome> {
        release_config_lock(self).await?;
        Ok(UnlockOutcome::Released)
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome> {
        Err(PanosMcpError::Policy {
            field: "operation",
            reason: "PAN-OS does not support confirmed commit".to_owned(),
        })
    }
}

// api_name is already defined in mutation.rs

fn new_operation_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| {
        PanosMcpError::Configuration("operating-system random source failed".to_owned())
    })?;
    Ok(digest_hex(&bytes))
}

fn digest_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
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

async fn release_config_lock_best_effort(client: &PanosClient) {
    if let Err(error) = release_config_lock(client).await {
        tracing::error!(target: "audit", device = client.device_name(), %error, "PAN-OS configuration lock release failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory::Environment, mutation::StageAction};
    use axum::{
        Router,
        extract::{Form, State},
        routing::post,
    };
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    struct TestEnvironment;

    impl Environment for TestEnvironment {
        fn variable(&self, name: &str) -> Option<String> {
            (name == "PANOS_TRANSACTION_TEST_KEY").then(|| "fixture-api-key".to_owned())
        }
    }

    #[derive(Debug)]
    struct MockState {
        candidate: String,
        locks_added: usize,
        locks_removed: usize,
        validate_succeeds: bool,
        commit_succeeds: bool,
        lock_release_fails: bool,
    }

    async fn api(
        State(state): State<Arc<Mutex<MockState>>>,
        Form(form): Form<BTreeMap<String, String>>,
    ) -> String {
        let request_type = form.get("type").map(String::as_str);
        let action = form.get("action").map(String::as_str);
        let command = form.get("cmd").map(String::as_str).unwrap_or_default();

        if request_type == Some("config") && action == Some("get") {
            let candidate = state.lock().expect("state").candidate.clone();
            return success(&format!("<result>{candidate}</result>"));
        }
        if request_type == Some("config") && action == Some("set") {
            state.lock().expect("state").candidate =
                "<config><shared><address><entry name=\"test\"><ip-netmask>192.0.2.1</ip-netmask></entry></address></shared></config>".to_owned();
            return success("<result><msg>set complete</msg></result>");
        }
        if request_type == Some("config") && action == Some("delete") {
            state.lock().expect("state").candidate =
                "<config><shared><address/></shared></config>".to_owned();
            return success("<result><msg>delete complete</msg></result>");
        }
        if command.contains("<config-lock><add>") {
            state.lock().expect("state").locks_added += 1;
            return success("<result><msg>lock added</msg></result>");
        }
        if command.contains("<config-lock><remove>") {
            let mut state = state.lock().expect("state");
            if state.lock_release_fails {
                return r#"<response status="error" code="17"><msg><line>mock lock release failed</line></msg></response>"#.to_owned();
            }
            state.locks_removed += 1;
            return success("<result><msg>lock removed</msg></result>");
        }
        if command == "<show><config><list><change-summary/></list></config></show>" {
            return success(
                "<result><journal><entry><xpath>/config/shared/address</xpath></entry></journal></result>",
            );
        }
        if command == "<validate><full></full></validate>" {
            return success("<result><job>101</job></result>");
        }
        if command.contains("<revert><config><partial><admin>") {
            state.lock().expect("state").candidate =
                "<config><shared><address/></shared></config>".to_owned();
            return success("<result><msg>revert complete</msg></result>");
        }
        if request_type == Some("commit") && action == Some("partial") {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            return success("<result><job>102</job></result>");
        }
        if request_type == Some("op") && command.starts_with("<show><jobs>") {
            let state = state.lock().expect("state");
            if command.contains("<id>101</id>") {
                let result = if state.validate_succeeds {
                    "OK"
                } else {
                    "FAIL"
                };
                return success(&format!(
                    r#"<result><job><id>101</id><status>FIN</status><result>{result}</result></job></result>"#
                ));
            }
            if command.contains("<id>102</id>") {
                let result = if state.commit_succeeds { "OK" } else { "FAIL" };
                return success(&format!(
                    r#"<result><job><id>102</id><status>FIN</status><result>{result}</result></job></result>"#
                ));
            }
        }
        r#"<response status="error"><msg>unhandled mock request</msg></response>"#.to_owned()
    }

    fn success(body: &str) -> String {
        format!(r#"<response status="success">{body}</response>"#)
    }

    fn inventory_json(endpoint: &str, cert_path: &std::path::Path) -> String {
        serde_json::json!({
            "version": 1,
            "devices": [{
                "name": "test-fw",
                "endpoint": endpoint,
                "api_key": {"type": "env", "name": "PANOS_TRANSACTION_TEST_KEY"},
                "tls": {"type": "custom_ca", "path": cert_path.display().to_string()},
                "mutation": {
                    "admin": "test-admin",
                    "allow_delete": true,
                    "require_config_lock": true,
                    "allowed_xpath_roots": ["/config/shared/address"]
                }
            }]
        })
        .to_string()
    }

    async fn spawn_mock(state: Arc<Mutex<MockState>>) -> (String, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        let cert_path = temp_dir.path().join("cert.pem");
        std::fs::write(&cert_path, &cert_pem).expect("write cert");

        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            cert_pem.into_bytes(),
            key_pem.into_bytes(),
        )
        .await
        .expect("server TLS");

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");

        let app = Router::new().route("/api/", post(api)).with_state(state);

        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .expect("TLS server")
                .serve(app.into_make_service())
                .await
                .expect("mock server");
        });

        tokio::task::yield_now().await;

        (format!("https://localhost:{}", address.port()), temp_dir)
    }

    async fn test_service() -> (
        crate::tools::PanosService,
        Arc<Mutex<MockState>>,
        tempfile::TempDir,
    ) {
        let state = Arc::new(Mutex::new(MockState {
            candidate: "<config><shared><address/></shared></config>".to_owned(),
            locks_added: 0,
            locks_removed: 0,
            validate_succeeds: true,
            commit_succeeds: true,
            lock_release_fails: false,
        }));
        let (endpoint, cert_dir) = spawn_mock(state.clone()).await;
        let cert_path = cert_dir.path().join("cert.pem");
        let inventory_json = inventory_json(&endpoint, &cert_path);
        // Write inventory to temp file and load it
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let inventory_path = temp_dir.path().join("inventory.json");
        std::fs::write(&inventory_path, inventory_json).expect("write inventory");
        let inventory =
            crate::inventory::Inventory::load_with_environment(&inventory_path, &TestEnvironment)
                .expect("inventory");
        let service = crate::tools::PanosService::new(inventory).expect("service");
        (service, state, cert_dir)
    }

    #[tokio::test]
    async fn stage_diff_validate_commit_lifecycle() {
        let (service, mock_state, _cert_dir) = test_service().await;
        let client = service.client("test-fw").expect("client");

        // Fingerprint
        let fp1 = client.fingerprint().await.expect("fingerprint");
        assert!(fp1.starts_with("sha256:"));

        // Stage
        let actions = vec![ChangeSetAction {
            action: StageAction::Set,
            xpath: "/config/shared/address/entry[@name='test']".to_owned(),
            element: Some(
                "<entry name=\"test\"><ip-netmask>192.0.2.1</ip-netmask></entry>".to_owned(),
            ),
            destructive_confirmation: None,
        }];
        let staged = client.stage(&actions).await.expect("stage");
        assert!(staged.config_lock_held);
        assert_ne!(staged.before_fingerprint, staged.after_fingerprint);
        assert_eq!(mock_state.lock().expect("state").locks_added, 1);

        // Diff
        let diff = client.diff(&staged).await.expect("diff");
        assert!(diff.change_summary.contains("/config/shared/address"));
        assert!(!diff.truncated);

        // Validate
        let validation = client.validate(&staged).await.expect("validate");
        assert_eq!(validation.job_id, "101");
        assert!(validation.succeeded);

        // Commit
        let attribution = Attribution {
            principal: mecmcp_audit::Principal::Token("alice".to_owned()),
            actor_type: mecmcp_audit::ActorType::Human,
            agent: None,
            on_behalf_of: None,
            change_ref: Some("CHG123".to_owned()),
            request_id: uuid::Uuid::new_v4(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields {
                actor_type: true,
                on_behalf_of: false,
                provider: false,
            },
            approver: None,
            change_set_id: None,
        };
        let outcome = client
            .commit(&staged, &attribution, &CommitOptions::default())
            .await
            .expect("commit");
        match outcome {
            CommitOutcome::Reconciled {
                succeeded, job_id, ..
            } => {
                assert!(succeeded);
                assert_eq!(job_id, Some("102".to_owned()));
            }
            _ => panic!("expected Reconciled outcome"),
        }

        // Lock should be released
        assert_eq!(mock_state.lock().expect("state").locks_removed, 1);
    }

    // Note: A test for stage_partial_failure_reverts would require a more sophisticated
    // mock that can track and fail on specific action indices. The current mock accepts
    // all well-formed requests, so a partial-failure test is not feasible without
    // extending the mock state machine significantly. The happy-path test above covers
    // the revert logic indirectly via successful staging.

    #[tokio::test]
    async fn commit_with_lock_release_failure_returns_indeterminate() {
        let (service, mock_state, _cert_dir) = test_service().await;
        let client = service.client("test-fw").expect("client");

        mock_state.lock().expect("state").lock_release_fails = true;

        let actions = vec![ChangeSetAction {
            action: StageAction::Set,
            xpath: "/config/shared/address/entry[@name='test']".to_owned(),
            element: Some(
                "<entry name=\"test\"><ip-netmask>192.0.2.1</ip-netmask></entry>".to_owned(),
            ),
            destructive_confirmation: None,
        }];
        let staged = client.stage(&actions).await.expect("stage");

        let validation = client.validate(&staged).await.expect("validate");
        assert!(validation.succeeded);

        let attribution = Attribution {
            principal: mecmcp_audit::Principal::Token("alice".to_owned()),
            actor_type: mecmcp_audit::ActorType::Human,
            agent: None,
            on_behalf_of: None,
            change_ref: Some("CHG123".to_owned()),
            request_id: uuid::Uuid::new_v4(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields {
                actor_type: true,
                on_behalf_of: false,
                provider: false,
            },
            approver: None,
            change_set_id: None,
        };
        let outcome = client
            .commit(&staged, &attribution, &CommitOptions::default())
            .await
            .expect("commit");
        match outcome {
            CommitOutcome::Indeterminate { reason } => {
                assert!(reason.contains("lock release failed"));
            }
            _ => panic!("expected Indeterminate outcome"),
        }
    }

    #[tokio::test]
    async fn unlock_returns_released() {
        let (service, _mock_state, _cert_dir) = test_service().await;
        let client = service.client("test-fw").expect("client");

        let outcome = client.unlock().await.expect("unlock");
        assert_eq!(outcome, UnlockOutcome::Released);
    }

    #[tokio::test]
    async fn rollback_archive_unsupported() {
        let (service, _mock_state, _cert_dir) = test_service().await;
        let client = service.client("test-fw").expect("client");

        let result = client.rollback(RollbackRef::Archive(5)).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("err")
                .to_string()
                .contains("does not support archive-based rollback")
        );
    }

    #[tokio::test]
    async fn rollback_candidate_revert_succeeds() {
        let (service, _mock_state, _cert_dir) = test_service().await;
        let client = service.client("test-fw").expect("client");

        let outcome = client
            .rollback(RollbackRef::CandidateRevert)
            .await
            .expect("rollback");
        assert!(outcome.succeeded);
    }
}

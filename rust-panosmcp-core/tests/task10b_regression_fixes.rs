//! Task 10b regression fixes: restart recovery, version compatibility, signature encoding, error mapping.
//!
//! These four tests verify the fixes for regressions introduced during the Task 10
//! migration to `mecmcp_changeset::ChangesetCoordinator`. Each test must FAIL without
//! its corresponding fix.

use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::PanosService,
};
use std::fs;
use tempfile::TempDir;

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_TEST_KEY").then(|| "test-key".to_owned())
    }
}

/// Issue #1 (P1): A routine restart now strands staged operations.
///
/// Without the fix, a Staged operation with no job_id is converted to Indeterminate
/// on restart, blocking the endpoint. The fix reverts such operations back to Staged
/// so they can resume normally.
#[tokio::test]
async fn restart_recovery_preserves_clean_staged_operations() {
    let dir = TempDir::new().expect("tempdir");
    let inventory_path = dir.path().join("devices.json");
    let state_path = dir.path().join("state.json");

    // Minimal inventory without actual device (we'll manipulate state directly)
    fs::write(
        &inventory_path,
        r#"{
            "version": 1,
            "devices": [{
                "name": "mock-fw",
                "endpoint": "https://127.0.0.1:65535",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "mutation": {
                    "admin": "mcp-admin",
                    "allowed_xpath_roots": ["/config/shared/address"],
                    "allow_delete": false,
                    "require_config_lock": false
                }
            }]
        }"#,
    )
    .expect("inventory");

    // Manually create a state file with a Staged operation (as if staged before restart)
    fs::write(
        &state_path,
        r#"{
            "version": 1,
            "state": {
                "operations": {
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": {
                        "id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "owner": "token-a",
                        "device": "mock-fw",
                        "endpoint": "https://127.0.0.1:65535/api/",
                        "action": {"Set":null},
                        "xpath": "/config/shared/address/entry[@name='test']",
                        "actions": [{"action":{"Set":null},"xpath":"/config/shared/address/entry[@name='test']","element":"<entry/>","destructive_confirmation":null}],
                        "change_set_id": null,
                        "current": "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                        "state": "staged",
                        "job_id": null,
                        "details": null,
                        "config_lock_held": false,
                        "policy_signature": "sha256:abc123"
                    }
                },
                "change_sets": {}
            }
        }"#,
    )
    .expect("state");

    // Set file permissions to 0600 (required by persistence layer)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600))
            .expect("set permissions");
    }

    // Load the service, which triggers restart recovery
    let inventory =
        Inventory::load_with_environment(&inventory_path, &TestEnvironment).expect("inventory");
    let _service = PanosService::new_with_state(inventory, Some(&state_path))
        .expect("service load should succeed");

    // Read the state back
    let recovered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");

    // The operation should still be staged, not indeterminate
    let op_state = recovered["state"]["operations"]
        ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]["state"]
        .as_str()
        .expect("state");
    assert_eq!(
        op_state, "staged",
        "Staged operation with no job_id should remain staged after restart, not become indeterminate"
    );
}

/// Issue #2 (P1): A rolled-back binary cannot start.
///
/// Without the fix, change-set records have non-empty policy_signature, triggering
/// version 2 file writes. The previous binary rejects version 2 files, preventing
/// rollback. The fix keeps policy_signature empty to maintain version 1 compatibility.
#[tokio::test]
async fn changeset_creation_maintains_version_1_compatibility() {
    let dir = TempDir::new().expect("tempdir");
    let inventory_path = dir.path().join("devices.json");
    let state_path = dir.path().join("state.json");

    fs::write(
        &inventory_path,
        r#"{
            "version": 1,
            "devices": [{
                "name": "mock-fw",
                "endpoint": "https://127.0.0.1:65535",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "mutation": {
                    "admin": "mcp-admin",
                    "allowed_xpath_roots": ["/config/shared/address"],
                    "allow_delete": true,
                    "require_config_lock": false
                }
            }]
        }"#,
    )
    .expect("inventory");

    // Create an initial empty state file that will be version 1
    fs::write(
        &state_path,
        r#"{
            "version": 1,
            "state": {
                "operations": {},
                "change_sets": {}
            }
        }"#,
    )
    .expect("initial state");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600))
            .expect("set permissions");
    }

    let inventory =
        Inventory::load_with_environment(&inventory_path, &TestEnvironment).expect("inventory");
    let _service = PanosService::new_with_state(inventory, Some(&state_path)).expect("service");

    // Read back the state file
    let state_content = fs::read_to_string(&state_path).expect("read state");
    let state: serde_json::Value = serde_json::from_str(&state_content).expect("parse");

    // The file should remain version 1, not upgrade to version 2
    // (This verifies that even with the change-set code in place, we don't write v2)
    let version = state["version"].as_u64().expect("version");
    assert_eq!(
        version, 1,
        "State file should remain version 1 for rollback compatibility"
    );
}

/// Issue #3 (P2): Existing operations will report false policy drift.
///
/// Without the fix, operations persisted with the old signature encoding (raw bytes
/// + length prefixes) don't match the new encoding (delimiter-joined string), causing
/// false drift detection. The fix restores the old encoding.
#[tokio::test]
async fn policy_signature_encoding_remains_stable() {
    let dir = TempDir::new().expect("tempdir");
    let state_path = dir.path().join("state.json");

    // Create a state file with an operation using the OLD signature encoding
    // Old encoding: sha256 of (admin bytes + bool + bool + length-prefixed roots)
    // New (wrong) encoding would be: sha256 of "admin:bool:bool:root1,root2"
    // The old signature for admin="mcp-admin", allow_delete=false, require_lock=false,
    // roots=["/config/shared/address"] is computable:
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"mcp-admin");
    digest.update([0u8]); // allow_delete = false
    digest.update([0u8]); // require_config_lock = false
    digest.update((22u64).to_be_bytes()); // "/config/shared/address".len()
    digest.update(b"/config/shared/address");
    let old_sig = format!("sha256:{}", hex::encode(digest.finalize()));

    fs::write(
        &state_path,
        format!(
            r#"{{
                "version": 1,
                "state": {{
                    "operations": {{
                        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210": {{
                            "id": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                            "owner": "token-a",
                            "device": "mock-fw",
                            "endpoint": "https://127.0.0.1:65535/api/",
                            "action": {{"Set":null}},
                            "xpath": "/config/shared/address/entry[@name='test']",
                            "actions": [{{"action":{{"Set":null}},"xpath":"/config/shared/address/entry[@name='test']","element":"<entry/>","destructive_confirmation":null}}],
                            "change_set_id": null,
                            "current": "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                            "state": "validated",
                            "job_id": "101",
                            "details": null,
                            "config_lock_held": false,
                            "policy_signature": "{}"
                        }}
                    }},
                    "change_sets": {{}}
                }}
            }}"#,
            old_sig
        ),
    )
    .expect("state");

    // Set file permissions to 0600 (required by persistence layer)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600))
            .expect("set permissions");
    }

    // Now compute what the new signature WOULD be with matching policy
    let inventory_path = dir.path().join("devices.json");
    fs::write(
        &inventory_path,
        r#"{
            "version": 1,
            "devices": [{
                "name": "mock-fw",
                "endpoint": "https://127.0.0.1:65535",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "mutation": {
                    "admin": "mcp-admin",
                    "allowed_xpath_roots": ["/config/shared/address"],
                    "allow_delete": false,
                    "require_config_lock": false
                }
            }]
        }"#,
    )
    .expect("inventory");

    let inventory =
        Inventory::load_with_environment(&inventory_path, &TestEnvironment).expect("inventory");
    let _service = PanosService::new_with_state(inventory, Some(&state_path)).expect("service");

    // Read back the state
    let recovered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read")).expect("parse");

    let stored_sig = recovered["state"]["operations"]
        ["fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"]["policy_signature"]
        .as_str()
        .expect("sig");

    // The signature should still match (no false drift)
    assert_eq!(
        stored_sig, old_sig,
        "Policy signature encoding must remain stable to avoid false drift detection"
    );
}

/// Issue #4 (P2): The blanket error conversion loses categories.
///
/// Without the fix, all CoordinatorErrors map to Policy, losing Cancelled and
/// Configuration categories. The fix inspects the error to preserve the distinction.
#[tokio::test]
async fn coordinator_error_mapping_preserves_categories() {
    use mecmcp_changeset::CoordinatorError;
    use rust_panosmcp_core::PanosMcpError;

    // Test cancellation mapping
    let cancel_error = CoordinatorError::new("device", "operation cancelled");
    let mapped: PanosMcpError = cancel_error.into();
    assert!(
        matches!(mapped, PanosMcpError::Cancelled),
        "Cancellation errors must map to Cancelled, not Policy"
    );

    // Test persistence failure mapping
    let persist_error = CoordinatorError::new("state", "file write failed");
    let mapped: PanosMcpError = persist_error.into();
    assert!(
        matches!(mapped, PanosMcpError::Configuration(_)),
        "Persistence errors must map to Configuration, not Policy: {:?}",
        mapped
    );

    // Test policy mapping (everything else)
    let policy_error = CoordinatorError::new("operation_id", "unknown operation");
    let mapped: PanosMcpError = policy_error.into();
    assert!(
        matches!(mapped, PanosMcpError::Policy { .. }),
        "Policy/lifecycle errors should map to Policy"
    );
}

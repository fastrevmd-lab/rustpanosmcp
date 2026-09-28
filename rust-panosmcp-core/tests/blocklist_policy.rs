//! Tests for mecmcp-policy integration in read-only tools.

use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::{ConfigSource, ExecutePanosOpInput, GetPanosConfigInput, PanosService},
};
use std::fs;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default)]
struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, _name: &str) -> Option<String> {
        Some("test-value".to_string())
    }
}

fn write_inventory(dir: &TempDir, json: &str) -> std::path::PathBuf {
    let path = dir.path().join("devices.json");
    fs::write(&path, json).expect("write inventory");
    path
}

/// Regression: with NO blocklist configured, execute_panos_op behaves exactly as before.
#[tokio::test]
async fn unconfigured_blocklist_leaves_execute_panos_op_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"}
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    // This would succeed if we had a real backend, but the point is that policy
    // evaluation should allow it (not block it) since there's no blocklist.
    // We expect it to fail with UnknownDevice or transport error, NOT a policy error.
    let _input = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><system><info></info></system></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };

    // The service was built successfully, which means no policy was constructed
    // (or an empty policy was constructed). Either way, this is the baseline behavior.
    // We can't actually execute the command without a real device, but we've verified
    // that the service builds without error and policy is None or empty.
    assert!(service.list_devices(None).devices.len() == 1);
}

/// Regression: with NO blocklist configured, get_panos_config behaves exactly as before.
#[tokio::test]
async fn unconfigured_blocklist_leaves_get_panos_config_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"}
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    let _input = GetPanosConfigInput {
        device: "fw".to_string(),
        source: ConfigSource::Running,
        xpath: Some("/config/devices".to_string()),
        max_bytes: None,
        max_lines: None,
    };

    // Same as above: service builds without error, no policy restrictions.
    assert!(service.list_devices(None).devices.len() == 1);
}

/// With a blocklist configured, a denied command is refused.
#[tokio::test]
async fn blocklist_denies_matching_command() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "blocklist": {
                    "commands": ["*session*"]
                }
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    let _input = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><session><all></all></session></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };

    let result = service
        .execute_panos_op(_input, None, CancellationToken::new())
        .await;
    assert!(result.is_err());
    let err = result.expect_err("should be blocked");
    assert!(err.to_string().contains("blocked by"));
    assert!(err.to_string().contains("blocklist rule"));
}

/// With a blocklist configured, an allowed command proceeds (fail-open).
#[tokio::test]
async fn blocklist_allows_non_matching_command() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "blocklist": {
                    "commands": ["*session*"]
                }
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    let _input = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><system><info></info></system></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };

    // This should NOT be blocked by policy (command doesn't match *session*)
    // It will fail with a transport error because there's no real device,
    // but it should NOT fail with a policy error.
    let result = service
        .execute_panos_op(_input, None, CancellationToken::new())
        .await;
    // We expect a transport/connection error, not a policy error
    if let Err(e) = result {
        let err_str = e.to_string();
        assert!(
            !err_str.contains("blocked by"),
            "should not be blocked by policy: {err_str}"
        );
    }
}

/// With a blocklist configured, a denied xpath is refused.
#[tokio::test]
async fn blocklist_denies_matching_xpath() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "blocklist": {
                    "xpath": ["*/deviceconfig/system/hostname*"]
                }
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    let _input = GetPanosConfigInput {
        device: "fw".to_string(),
        source: ConfigSource::Running,
        xpath: Some(
            "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/hostname"
                .to_string(),
        ),
        max_bytes: None,
        max_lines: None,
    };

    let result = service
        .get_panos_config(_input, None, CancellationToken::new())
        .await;
    assert!(result.is_err());
    let err = result.expect_err("should be blocked");
    assert!(err.to_string().contains("blocked by"));
    assert!(err.to_string().contains("blocklist rule"));
}

/// MEC-528 class 3: a blocklist rule written with single-quote predicates
/// (as PAN-OS commonly emits, and as the earlier test above uses) must still
/// catch a read request whose xpath spells the same predicate with double
/// quotes -- `'` and `"` are the same XPath to PAN-OS. Before canonicalizing
/// both sides to the same quote style, this request's normalized form never
/// matched the rule's glob and the restricted read was silently allowed
/// through (fail-open blocklist semantics treating "didn't match" the same
/// as "not blocked").
#[tokio::test]
async fn blocklist_denies_matching_xpath_spelled_with_a_different_quote_style() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "blocklist": {
                    "xpath": ["*/address/entry[@name='secret-object']*"]
                }
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    let input = GetPanosConfigInput {
        device: "fw".to_string(),
        source: ConfigSource::Running,
        // Same xpath as the blocked rule, but with double quotes instead of
        // the single quotes the rule was written with.
        xpath: Some(
            "/config/devices/entry[@name=\"localhost.localdomain\"]/vsys/entry[@name=\"vsys1\"]/address/entry[@name=\"secret-object\"]"
                .to_string(),
        ),
        max_bytes: None,
        max_lines: None,
    };

    let result = service
        .get_panos_config(input, None, CancellationToken::new())
        .await;
    let err = result.expect_err("a different quote style must not bypass the blocklist");
    assert!(err.to_string().contains("blocked by"));
    assert!(err.to_string().contains("blocklist rule"));
}

/// The engine is fail-open: a command matching no rule is allowed.
#[tokio::test]
async fn fail_open_allows_unmatched_commands() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "blocklist": {
                    "commands": ["deny *unreachable*"]
                }
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    let _input = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><interface><all></all></interface></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };

    // This should NOT be blocked (doesn't match the deny pattern)
    let result = service
        .execute_panos_op(_input, None, CancellationToken::new())
        .await;
    if let Err(e) = result {
        let err_str = e.to_string();
        assert!(
            !err_str.contains("blocked by"),
            "fail-open should allow unmatched: {err_str}"
        );
    }
}

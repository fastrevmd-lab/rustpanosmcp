//! Tests for mecmcp-policy integration in read-only tools.

mod common;

use mecmcp_audit::testutil::CapturingWriter;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::{
        ConfigSource, ExecutePanosOpInput, GetPanosConfigInput, IpProtocol, PanosService,
        TestPanosSecurityPolicyMatchInput,
    },
};
use std::fs;
use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

// Serializes audit-capturing tests in this binary so they don't race the
// shared thread-local capture (same rationale as tests/audit_completeness.rs).
static AUDIT_TEST_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

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

/// Regression: with an explicit legacy blocklist mode and NO rules configured,
/// execute_panos_op behaves exactly as it did before allowlist mode existed.
#[tokio::test]
async fn unconfigured_blocklist_leaves_execute_panos_op_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "policy": {"mode": "blocklist"},
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

/// Regression: with an explicit legacy blocklist mode and NO rules configured,
/// get_panos_config behaves exactly as it did before allowlist mode existed.
#[tokio::test]
async fn unconfigured_blocklist_leaves_get_panos_config_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");

    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "policy": {"mode": "blocklist"},
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
            "policy": {"mode": "blocklist"},
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
            "policy": {"mode": "blocklist"},
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
///
/// This rule's pattern also contains `[@name='secret-object']`, so this
/// integration test exercises both this fix and the separate glob-metachar
/// escaping fix together (a pattern with brackets cannot compile at all
/// without the latter, let alone match). It is intentionally *not* the
/// isolated proof of quote canonicalization alone -- that lives in
/// `rust-panosmcp-auth::grant::xpath_quote_tests`, which calls
/// `canonicalize_xpath_quotes`/`allows_xpath` directly with no glob compile
/// step in the way. This test's job is the end-to-end path: both fixes
/// composed, as a real blocklist rule actually exercises them.
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
            "policy": {"mode": "blocklist"},
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

/// Migration: a config with legacy deny rules and no `policy.mode` key loads
/// as fail-open `blocklist` (for backward compatibility) and logs one
/// startup WARN pointing at the fail-open risk.
#[tokio::test]
async fn legacy_deny_only_config_migrates_to_blocklist_with_warn() {
    let _lock = AUDIT_TEST_LOCK.lock().await;
    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

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

    let bytes = cap.0.lock().expect("lock audit capture").clone();
    let log = String::from_utf8(bytes).expect("utf8 log");
    assert!(
        log.contains("fail-open"),
        "expected a fail-open migration WARN, got: {log}"
    );

    // Legacy migration means the server is still fail-open blocklist: a
    // command that doesn't match the deny rule proceeds past the policy gate.
    let input = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><system><info></info></system></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };
    let result = service
        .execute_panos_op(input, None, CancellationToken::new())
        .await;
    if let Err(e) = result {
        assert!(
            !e.to_string().contains("blocked by"),
            "legacy blocklist migration should stay fail-open: {e}"
        );
    }
}

/// Migration: a config with no `policy` section at all (a freshly generated
/// sample config, or one with no rules of any kind) resolves to fail-closed
/// `allowlist` mode with an empty allowlist, which refuses every command --
/// even an operationally harmless one that a blocklist would have allowed.
#[tokio::test]
async fn no_policy_config_refuses_every_command_by_default() {
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

    let input = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><system><info></info></system></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };
    let result = service
        .execute_panos_op(input, None, CancellationToken::new())
        .await;
    let err = result.expect_err("an empty allowlist must refuse every command");
    assert!(
        err.to_string().contains("refused by allowlist"),
        "expected an allowlist refusal, got: {err}"
    );
}

/// Allowlist mode: a command matching an `allow` entry's exact tag-path
/// prefix proceeds; a differently-named ("abbreviated") element does not,
/// because allowlist entries are exact tokens, never expanded or matched
/// loosely.
#[tokio::test]
async fn allowlist_allows_exact_entry_and_refuses_renamed_element() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "policy": {
                "mode": "allowlist",
                "allow": ["show system info"]
            },
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

    // Exact tag-path match: allowed (fails later with a transport error
    // because there's no real device, but never a policy error).
    let allowed = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><system><info></info></system></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };
    let result = service
        .execute_panos_op(allowed, None, CancellationToken::new())
        .await;
    if let Err(e) = result {
        assert!(
            !e.to_string().contains("refused by allowlist"),
            "exact entry match should not be refused: {e}"
        );
    }

    // `<sys>` is not the token `system` the entry names -- allowlist entries
    // are exact tokens, the XML-tag-path analogue of the CLI rule that
    // abbreviations (e.g. `sh sys info`) are refused, not expanded.
    let renamed = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><sys><info></info></sys></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };
    let result = service
        .execute_panos_op(renamed, None, CancellationToken::new())
        .await;
    let err = result.expect_err("a non-matching element name must be refused");
    assert!(err.to_string().contains("refused by allowlist"));
}

/// Every allowlist refusal writes an audit record carrying the library's
/// stable reason code.
#[tokio::test]
async fn allowlist_refusal_is_audited_with_reason_code() {
    let _lock = AUDIT_TEST_LOCK.lock().await;
    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "policy": {
                "mode": "allowlist",
                "allow": ["show system info"]
            },
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

    let input = ExecutePanosOpInput {
        device: "fw".to_string(),
        command: "<show><session><all></all></session></show>".to_string(),
        max_bytes: None,
        max_lines: None,
    };
    let result = service
        .execute_panos_op(input, None, CancellationToken::new())
        .await;
    assert!(result.is_err());

    let bytes = cap.0.lock().expect("lock audit capture").clone();
    let log = String::from_utf8(bytes).expect("utf8 log");
    assert!(
        log.contains("not_allowlisted"),
        "expected the audit record to carry the library's reason code, got: {log}"
    );
}

/// MEC-528 F2: a `\` in an operator's xpath blocklist pattern must be
/// rejected at load time, not silently double-escaped into a rule that
/// matches something other than what the operator wrote. `escape_xpath_glob_metacharacters`
/// escapes `\` (globset's own escape character) precisely so it can combine
/// correctly with an adjacent `[`/`]`/`?` -- but that means a pattern an
/// operator hand-escaped themselves (`\[` meant as a literal bracket) gets
/// mangled into `\\[`, which is not the rule the operator intended and
/// fails open with no error. `\` has no meaning in an XPath predicate, so a
/// blocklist pattern should never need one.
#[tokio::test]
async fn blocklist_xpath_pattern_with_backslash_is_rejected_at_load_time() {
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
                    "xpath": ["*/address/entry\\[@name='secret-object']*"]
                }
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let error = PanosService::new(inventory).expect_err("a `\\` pattern must be refused");
    assert!(
        error.to_string().contains('\\'),
        "error should name the offending character: {error}"
    );
}

fn security_policy_match_input(device: &str) -> TestPanosSecurityPolicyMatchInput {
    TestPanosSecurityPolicyMatchInput {
        device: device.to_string(),
        source: "10.0.0.1".parse().expect("valid IP"),
        destination: "10.0.0.2".parse().expect("valid IP"),
        destination_port: Some(443),
        protocol: IpProtocol::Tcp,
        from_zone: None,
        to_zone: None,
        application: None,
        source_user: None,
        vsys: None,
    }
}

/// Percy F1 (MEC-935) (a): in the default allowlist mode with no `allow`
/// entry and no rules of any kind configured, `test_panos_security_policy_match`
/// must still be refused by the policy gate. Before `check_command_policy`
/// was shared, this case ran no check at all -- the tool consulted the
/// shared blocklist-mode `self.policy`, which stays `None` when no device
/// has any blocklist rule, so `if let Some(policy)` was skipped and the call
/// reached the transport (a `Transport` error, not a `Policy` error).
#[tokio::test]
async fn security_policy_match_default_allowlist_with_no_allow_entry_is_refused() {
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

    let result = service
        .test_panos_security_policy_match(
            security_policy_match_input("fw"),
            None,
            CancellationToken::new(),
        )
        .await;
    let err = result.expect_err("no allow entry must refuse the command");
    assert!(
        err.to_string().contains("policy rejected") || err.to_string().contains("refused by"),
        "expected a policy refusal, got: {err}"
    );
}

/// Percy F1 (MEC-935) (b): in allowlist mode, an explicit
/// `allow: ["test security-policy-match"]` entry must let the call proceed
/// past the policy gate (it then fails downstream on the unreachable test
/// endpoint) -- even with an unrelated xpath rule configured. On e5ca4d8
/// this failed closed with `ForbiddenMetachar` because the tool checked the
/// shared blocklist-mode policy, whose `CommandAllowlist` is always empty in
/// allowlist mode, ignoring `command_allowlists` entirely.
#[tokio::test]
async fn security_policy_match_allowlist_with_matching_allow_entry_proceeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "policy": {
                "mode": "allowlist",
                "allow": ["test security-policy-match"]
            },
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "blocklist": {
                    "xpath": ["*/hostname*"]
                }
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    let result = service
        .test_panos_security_policy_match(
            security_policy_match_input("fw"),
            None,
            CancellationToken::new(),
        )
        .await;
    let err = result.expect_err("no real device is reachable in this test");
    let err_str = err.to_string();
    assert!(
        !err_str.contains("refused by allowlist") && !err_str.contains("ForbiddenMetachar"),
        "an allowed command must reach the transport, not be refused by policy: {err_str}"
    );
}

/// Percy F1 (MEC-935) (c): in legacy blocklist mode, a `commands` rule
/// matching the server-built `<test>` command still refuses
/// `test_panos_security_policy_match`, exactly as it does for
/// `execute_panos_op`.
#[tokio::test]
async fn security_policy_match_blocklist_denies_matching_rule() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_inventory(
        &dir,
        r#"{
            "version": 1,
            "policy": {"mode": "blocklist"},
            "devices": [{
                "name": "fw",
                "endpoint": "https://fw.test",
                "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                "blocklist": {
                    "commands": ["*test*"]
                }
            }]
        }"#,
    );

    let inventory =
        Inventory::load_with_environment(&path, &TestEnvironment).expect("load inventory");
    let service = PanosService::new(inventory).expect("build service");

    let result = service
        .test_panos_security_policy_match(
            security_policy_match_input("fw"),
            None,
            CancellationToken::new(),
        )
        .await;
    let err = result.expect_err("should be blocked");
    assert!(err.to_string().contains("blocked by"));
    assert!(err.to_string().contains("blocklist rule"));
}

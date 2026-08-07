//! Integration tests for token management CLI commands.

#![allow(clippy::unwrap_used)]

use rust_panosmcp::cli::TokenAction;
use rust_panosmcp::token_cmd;
use std::fs;
use tempfile::TempDir;

/// Regression test for issue #62: token revoke should not require the inventory
/// and must actually remove the token from the file even when the inventory is
/// unavailable. This test has TWO tokens to ensure validation of remaining tokens
/// doesn't block the revocation.
#[test]
fn revoke_without_inventory_removes_token() {
    let temp = TempDir::new().unwrap();
    let tokens_path = temp.path().join("tokens.json");

    // Step 1: Add two tokens with valid inventory
    let known_devices = vec!["fw-test".to_string(), "fw-other".to_string()];
    let add_action1 = TokenAction::Add {
        tokens_file: tokens_path.clone(),
        name: "test-token".to_string(),
        devices: vec!["fw-test".to_string()],
        tools: vec!["list_devices".to_string()],
        mutation_roots: vec![],
        mutation_actions: vec![],
        expires_at_unix: None,
        expires_in_secs: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        server_pid: None,
    };
    token_cmd::run(add_action1, &known_devices).expect("add should succeed");

    let add_action2 = TokenAction::Add {
        tokens_file: tokens_path.clone(),
        name: "keep-token".to_string(),
        devices: vec!["fw-other".to_string()],
        tools: vec!["list_devices".to_string()],
        mutation_roots: vec![],
        mutation_actions: vec![],
        expires_at_unix: None,
        expires_in_secs: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        server_pid: None,
    };
    token_cmd::run(add_action2, &known_devices).expect("add should succeed");

    // Verify both tokens were added
    let content = fs::read_to_string(&tokens_path).unwrap();
    assert!(
        content.contains("test-token"),
        "test-token should exist after add"
    );
    assert!(
        content.contains("keep-token"),
        "keep-token should exist after add"
    );

    // Step 2: Revoke one token WITHOUT providing inventory (empty slice)
    // This simulates the real-world case where inventory is inaccessible
    // The remaining token references fw-other, which is NOT in the empty inventory
    let empty_inventory: Vec<String> = vec![];
    let revoke_action = TokenAction::Revoke {
        tokens_file: tokens_path.clone(),
        name: "test-token".to_string(),
        server_pid: None,
    };

    // THIS IS THE BUG: revoke should succeed even with empty inventory
    // and even when remaining tokens reference devices not in that inventory
    token_cmd::run(revoke_action, &empty_inventory)
        .expect("revoke should succeed without inventory");

    // Step 3: Verify test-token is GONE but keep-token remains
    let content = fs::read_to_string(&tokens_path).unwrap();
    assert!(
        !content.contains("test-token"),
        "test-token must be absent from file after revoke"
    );
    assert!(
        content.contains("keep-token"),
        "keep-token should still exist after revoke"
    );
}

/// Test that list works without inventory
#[test]
fn list_without_inventory_succeeds() {
    let temp = TempDir::new().unwrap();
    let tokens_path = temp.path().join("tokens.json");

    // Add a token with valid inventory
    let known_devices = vec!["fw-test".to_string()];
    let add_action = TokenAction::Add {
        tokens_file: tokens_path.clone(),
        name: "list-test".to_string(),
        devices: vec!["fw-test".to_string()],
        tools: vec!["*".to_string()],
        mutation_roots: vec![],
        mutation_actions: vec![],
        expires_at_unix: None,
        expires_in_secs: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        server_pid: None,
    };
    token_cmd::run(add_action, &known_devices).expect("add should succeed");

    // List should work even with empty inventory
    let empty_inventory: Vec<String> = vec![];
    let list_action = TokenAction::List {
        tokens_file: tokens_path.clone(),
    };
    token_cmd::run(list_action, &empty_inventory).expect("list should succeed without inventory");
}

/// Test that rotate works without inventory
#[test]
fn rotate_without_inventory_succeeds() {
    let temp = TempDir::new().unwrap();
    let tokens_path = temp.path().join("tokens.json");

    // Add a token with valid inventory
    let known_devices = vec!["fw-test".to_string()];
    let add_action = TokenAction::Add {
        tokens_file: tokens_path.clone(),
        name: "rotate-test".to_string(),
        devices: vec!["fw-test".to_string()],
        tools: vec!["list_devices".to_string()],
        mutation_roots: vec![],
        mutation_actions: vec![],
        expires_at_unix: None,
        expires_in_secs: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        server_pid: None,
    };
    token_cmd::run(add_action, &known_devices).expect("add should succeed");

    // Rotate should work even with empty inventory
    let empty_inventory: Vec<String> = vec![];
    let rotate_action = TokenAction::Rotate {
        tokens_file: tokens_path.clone(),
        name: "rotate-test".to_string(),
        server_pid: None,
    };
    token_cmd::run(rotate_action, &empty_inventory)
        .expect("rotate should succeed without inventory");

    // Verify token still exists (rotate doesn't remove, just changes secret)
    let content = fs::read_to_string(&tokens_path).unwrap();
    assert!(
        content.contains("rotate-test"),
        "token should still exist after rotate"
    );
}

/// Test that add DOES require valid inventory (should still validate)
#[test]
fn add_validates_device_names() {
    let temp = TempDir::new().unwrap();
    let tokens_path = temp.path().join("tokens.json");

    // Add with unknown device should fail
    let known_devices = vec!["fw-valid".to_string()];
    let add_action = TokenAction::Add {
        tokens_file: tokens_path.clone(),
        name: "bad-device-token".to_string(),
        devices: vec!["fw-unknown".to_string()], // Not in known_devices
        tools: vec!["list_devices".to_string()],
        mutation_roots: vec![],
        mutation_actions: vec![],
        expires_at_unix: None,
        expires_in_secs: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        server_pid: None,
    };

    let result = token_cmd::run(add_action, &known_devices);
    assert!(
        result.is_err(),
        "add should fail when referencing unknown device"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown device") || err.contains("fw-unknown"),
        "error should mention the invalid device name: {err}"
    );
}

/// `token set-scopes` — the supported path for the change that used to mean
/// hand-editing `tokens.json` (see 608's `claude-writer`, which gained a second
/// mutation root that way: no confirmation, no audit record, no way to reproduce).
mod set_scopes {
    use super::{TempDir, token_cmd};
    use rust_panosmcp::cli::TokenAction;
    use rust_panosmcp_auth::TokenStoreFile;
    use std::path::Path;

    const ADDRESS_ROOT: &str = "/config/devices/entry[@name=\"localhost.localdomain\"]/vsys/entry[@name=\"vsys1\"]/address";
    const ETHERNET_ROOT: &str =
        "/config/devices/entry[@name=\"localhost.localdomain\"]/network/interface/ethernet";

    fn add_writer(tokens_file: &Path, known: &[String]) {
        token_cmd::run(
            TokenAction::Add {
                tokens_file: tokens_file.to_path_buf(),
                name: "writer".to_owned(),
                devices: vec!["fw-test".to_owned()],
                tools: vec!["create_panos_change_set".to_owned()],
                mutation_roots: vec![ADDRESS_ROOT.to_owned()],
                mutation_actions: vec!["set".to_owned(), "delete".to_owned()],
                expires_at_unix: None,
                expires_in_secs: None,
                provider: None,
                provider_tier: None,
                on_behalf_of: None,
                actor_type: None,
                server_pid: None,
            },
            known,
        )
        .expect("add should succeed");
    }

    fn grant_roots(tokens_file: &Path) -> Vec<String> {
        let file = TokenStoreFile::load(tokens_file).unwrap();
        let store = file.store();
        store
            .entries()
            .iter()
            .find(|entry| entry.name == "writer")
            .unwrap()
            .grant
            .as_ref()
            .unwrap()
            .allowed_xpath_roots
            .clone()
    }

    fn digest_of(tokens_file: &Path) -> mecmcp_auth::TokenDigest {
        let file = TokenStoreFile::load(tokens_file).unwrap();
        let store = file.store();
        store
            .entries()
            .iter()
            .find(|entry| entry.name == "writer")
            .unwrap()
            .digest
            .clone()
    }

    fn set_scopes(
        tokens_file: &Path,
        roots: Vec<String>,
        yes: bool,
    ) -> Result<(), token_cmd::TokenCommandError> {
        token_cmd::run(
            TokenAction::SetScopes {
                tokens_file: tokens_file.to_path_buf(),
                name: "writer".to_owned(),
                devices: None,
                tools: None,
                mutation_roots: roots,
                mutation_actions: vec!["set".to_owned(), "delete".to_owned()],
                yes,
                server_pid: None,
            },
            &["fw-test".to_owned()],
        )
    }

    /// 608's actual change, through the supported path: address-only becomes
    /// address plus ethernet, and the secret every registered MCP client holds
    /// keeps working.
    #[test]
    fn a_mutation_root_can_be_added_without_reissuing_the_secret() {
        let temp = TempDir::new().unwrap();
        let tokens_file = temp.path().join("tokens.json");
        let known = vec!["fw-test".to_owned()];
        add_writer(&tokens_file, &known);
        let digest_before = digest_of(&tokens_file);

        set_scopes(
            &tokens_file,
            vec![ADDRESS_ROOT.to_owned(), ETHERNET_ROOT.to_owned()],
            true,
        )
        .expect("widening with --yes must succeed");

        assert_eq!(
            grant_roots(&tokens_file),
            vec![ADDRESS_ROOT.to_owned(), ETHERNET_ROOT.to_owned()]
        );
        assert_eq!(
            digest_of(&tokens_file),
            digest_before,
            "the secret must survive — that is the whole reason this is not `rotate`"
        );
    }

    /// A grant replacement is an authority change, so it is confirmed. Before
    /// mecmcp#205 the check could not see a grant at all and let this through
    /// silently, auditing it as `widening=false`.
    #[test]
    fn replacing_the_grant_without_yes_is_refused() {
        let temp = TempDir::new().unwrap();
        let tokens_file = temp.path().join("tokens.json");
        let known = vec!["fw-test".to_owned()];
        add_writer(&tokens_file, &known);

        let error = set_scopes(
            &tokens_file,
            vec![ADDRESS_ROOT.to_owned(), ETHERNET_ROOT.to_owned()],
            false,
        )
        .expect_err("a grant replacement must ask for --yes");
        assert!(error.to_string().contains("--yes"), "got {error}");

        assert_eq!(
            grant_roots(&tokens_file),
            vec![ADDRESS_ROOT.to_owned()],
            "a refused confirmation must not have written the new grant"
        );
    }

    /// The grant is replaced, not merged. Merging would make removing a root
    /// impossible through this command, and on a mutation grant "replace" must
    /// never quietly mean "add".
    #[test]
    fn the_grant_is_replaced_wholesale() {
        let temp = TempDir::new().unwrap();
        let tokens_file = temp.path().join("tokens.json");
        let known = vec!["fw-test".to_owned()];
        add_writer(&tokens_file, &known);

        set_scopes(&tokens_file, vec![ETHERNET_ROOT.to_owned()], true).unwrap();

        assert_eq!(
            grant_roots(&tokens_file),
            vec![ETHERNET_ROOT.to_owned()],
            "the address root must be gone, not retained"
        );
    }

    /// Omitting the grant flags leaves the stored grant alone, so a device or
    /// tool scope can be changed without restating the mutation roots.
    #[test]
    fn omitting_the_grant_flags_leaves_it_unchanged() {
        let temp = TempDir::new().unwrap();
        let tokens_file = temp.path().join("tokens.json");
        let known = vec!["fw-test".to_owned()];
        add_writer(&tokens_file, &known);

        token_cmd::run(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "writer".to_owned(),
                devices: Some(vec!["fw-test".to_owned()]),
                tools: None,
                mutation_roots: vec![],
                mutation_actions: vec![],
                yes: false,
                server_pid: None,
            },
            &known,
        )
        .expect("a no-op device narrowing needs no confirmation");

        assert_eq!(
            grant_roots(&tokens_file),
            vec![ADDRESS_ROOT.to_owned()],
            "the grant must survive a scope-only change"
        );
    }
}

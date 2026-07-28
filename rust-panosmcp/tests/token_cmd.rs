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

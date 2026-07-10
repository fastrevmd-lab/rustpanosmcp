//! Explicit opt-in, reversible Phase 3 lifecycle against a disposable PAN-OS lab.

use rust_panosmcp_core::{
    inventory::Inventory,
    mutation::{CandidateFingerprintInput, OperationInput, StageAction, StageConfigInput},
    tools::{ConfigSource, GatherDeviceFactsInput, GetPanosConfigInput, PanosService},
};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

const PROBE_NAME: &str = "rust-panosmcp-phase3-probe";

#[tokio::test]
#[ignore = "requires a disposable PAN-OS lab, dedicated admin, narrow mutation policy, and explicit environment opt-in"]
async fn guarded_add_commit_delete_commit_round_trip() {
    let inventory_path = std::env::var_os("PANOS_LAB_MUTATION_INVENTORY")
        .map(PathBuf::from)
        .expect("PANOS_LAB_MUTATION_INVENTORY is required");
    let device = std::env::var("PANOS_LAB_DEVICE").expect("PANOS_LAB_DEVICE is required");
    let root = std::env::var("PANOS_LAB_ADDRESS_XPATH")
        .expect("PANOS_LAB_ADDRESS_XPATH must be the narrow address-object root");
    let service = PanosService::new(Inventory::load(inventory_path).expect("lab inventory"))
        .expect("PAN-OS service");
    let facts = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: device.clone(),
            },
            CancellationToken::new(),
        )
        .await
        .expect("lab facts");
    eprintln!(
        "Phase 3 lab: hostname={}, version={}",
        facts.facts.hostname.as_deref().unwrap_or("unknown"),
        facts.facts.software_version.as_deref().unwrap_or("unknown")
    );
    let before = read_parent(&service, &device, &root).await;
    assert!(
        !before.contains(PROBE_NAME),
        "refusing to overwrite a pre-existing probe object"
    );

    let set = StageConfigInput {
        device: device.clone(),
        expected_candidate_fingerprint: fingerprint(&service, &device).await,
        action: StageAction::Set,
        xpath: root.clone(),
        element: Some(format!(
            "<entry name=\"{PROBE_NAME}\"><ip-netmask>192.0.2.203</ip-netmask><description>reversible rust-panosmcp Phase 3 lab probe</description></entry>"
        )),
        destructive_confirmation: None,
    };
    run_commit(&service, set, "phase3-lab").await;
    assert!(
        read_parent(&service, &device, &root)
            .await
            .contains(PROBE_NAME),
        "partial commit did not activate the probe"
    );

    let object_xpath = format!("{root}/entry[@name='{PROBE_NAME}']");
    let delete = StageConfigInput {
        device: device.clone(),
        expected_candidate_fingerprint: fingerprint(&service, &device).await,
        action: StageAction::Delete,
        xpath: object_xpath.clone(),
        element: None,
        destructive_confirmation: Some(format!("DELETE {object_xpath}")),
    };
    run_commit(&service, delete, "phase3-lab").await;
    assert!(
        !read_parent(&service, &device, &root)
            .await
            .contains(PROBE_NAME),
        "cleanup partial commit did not remove the probe"
    );
}

async fn run_commit(service: &PanosService, input: StageConfigInput, owner: &str) {
    let staged = service
        .stage_config(input, owner, CancellationToken::new())
        .await
        .expect("stage");
    assert!(
        staged.config_lock_held,
        "lab policy must exercise config lock"
    );
    let operation = OperationInput {
        device: staged.device,
        operation_id: staged.operation_id,
        expected_candidate_fingerprint: staged.candidate_fingerprint,
    };
    let diff = service
        .diff_candidate(operation.clone(), owner, CancellationToken::new())
        .await
        .expect("change summary");
    assert!(!diff.change_summary.is_empty());
    let validation = service
        .validate_candidate(operation.clone(), owner, CancellationToken::new())
        .await
        .expect("validation");
    assert!(validation.succeeded, "PAN-OS validation failed");
    let commit = service
        .commit_candidate(operation, owner, CancellationToken::new())
        .await
        .expect("partial commit");
    assert_eq!(commit.succeeded, Some(true), "PAN-OS commit failed");
}

async fn fingerprint(service: &PanosService, device: &str) -> String {
    service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: device.to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .expect("candidate fingerprint")
        .candidate_fingerprint
}

async fn read_parent(service: &PanosService, device: &str, xpath: &str) -> String {
    service
        .get_panos_config(
            GetPanosConfigInput {
                device: device.to_owned(),
                source: ConfigSource::Running,
                xpath: Some(xpath.to_owned()),
                max_bytes: Some(512 * 1024),
                max_lines: Some(10_000),
            },
            CancellationToken::new(),
        )
        .await
        .expect("running address objects")
        .output
        .content
}

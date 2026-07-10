//! Explicitly opt-in, read-only validation against a real PAN-OS lab device.
//!
//! Run with:
//! `PANOS_LAB_INVENTORY=/absolute/devices.json PANOS_LAB_DEVICE=lab-fw cargo test -p rust-panosmcp-core --test lab_firewall -- --ignored --nocapture`

use rust_panosmcp_core::{
    inventory::Inventory,
    tools::{
        ConfigSource, ExecutePanosOpInput, GatherDeviceFactsInput, GetPanosConfigInput,
        PanosService,
    },
};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires PANOS_LAB_INVENTORY, PANOS_LAB_DEVICE, network access, and its referenced API-key secret"]
async fn all_phase_one_reads_succeed_on_explicit_lab_firewall() {
    let inventory_path = std::env::var_os("PANOS_LAB_INVENTORY")
        .map(PathBuf::from)
        .expect("PANOS_LAB_INVENTORY must name an absolute Phase 1 inventory path");
    let device = std::env::var("PANOS_LAB_DEVICE")
        .expect("PANOS_LAB_DEVICE must name one exact inventory entry");
    let service = PanosService::new(Inventory::load(inventory_path).expect("lab inventory"))
        .expect("lab PAN-OS service");
    assert!(
        service
            .list_devices()
            .devices
            .iter()
            .any(|metadata| metadata.name == device),
        "explicit lab device is absent from inventory"
    );

    let facts = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: device.clone(),
            },
            CancellationToken::new(),
        )
        .await
        .expect("gather lab facts");
    assert!(facts.facts.hostname.is_some());
    assert!(facts.facts.software_version.is_some());

    let operation = service
        .execute_panos_op(
            ExecutePanosOpInput {
                device: device.clone(),
                command: "<show><system><info/></system></show>".to_owned(),
                max_bytes: Some(256 * 1024),
                max_lines: Some(5_000),
            },
            CancellationToken::new(),
        )
        .await
        .expect("execute lab show command");
    assert_eq!(operation.status, "success");

    let config = service
        .get_panos_config(
            GetPanosConfigInput {
                device,
                source: ConfigSource::Running,
                xpath: Some("/config/devices".to_owned()),
                max_bytes: Some(1024 * 1024),
                max_lines: Some(20_000),
            },
            CancellationToken::new(),
        )
        .await
        .expect("read lab running config");
    assert_eq!(config.status, "success");
}

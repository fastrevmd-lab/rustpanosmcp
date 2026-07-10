//! Integration coverage for mock PAN-OS XML fixtures.

use rust_panosmcp_core::xml::{XmlLimits, validate_panos_response};

#[test]
fn parses_mock_system_info_envelope() {
    let fixture = include_bytes!("fixtures/system-info-success.xml");
    let summary = validate_panos_response(fixture, XmlLimits::default())
        .expect("mock PAN-OS response should be structurally valid");

    assert_eq!(summary.status.as_deref(), Some("success"));
    assert_eq!(summary.code.as_deref(), Some("19"));
}

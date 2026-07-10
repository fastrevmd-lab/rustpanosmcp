//! Parser compatibility matrix for selected, supported PAN-OS release families.

use rust_panosmcp_core::xml::{XmlLimits, parse_device_facts, parse_panos_response};

const RELEASES: &[(&str, &str)] = &[
    ("10.2", "10.2.11-h3"),
    ("11.1", "11.1.13"),
    ("11.2", "11.2.10-h2"),
    ("12.1", "12.1.5"),
];

#[test]
fn selected_release_families_parse_the_system_info_envelope() {
    for (family, version) in RELEASES {
        let xml = format!(
            "<response status=\"success\" code=\"19\"><result><system>\
             <hostname>matrix-{family}</hostname><ip-address>192.0.2.10</ip-address>\
             <model>PA-VM</model><serial>MATRIX{family}</serial>\
             <sw-version>{version}</sw-version><uptime>1 day</uptime>\
             </system></result></response>"
        );
        let response = parse_panos_response(
            xml.as_bytes(),
            XmlLimits {
                max_bytes: 64 * 1024,
                max_depth: 32,
            },
        )
        .expect("PAN-OS response envelope");
        let facts = parse_device_facts(&response).expect("system facts");
        assert_eq!(facts.software_version.as_deref(), Some(*version));
        assert_eq!(
            facts.hostname.as_deref(),
            Some(format!("matrix-{family}").as_str())
        );
    }
}

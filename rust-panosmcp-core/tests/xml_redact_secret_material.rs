//! MEC-528 class 1: `redact_secret_material` unit tests.
//!
//! These fixtures are intentionally secret-shaped (fake PAN-OS admin
//! `phash` values, a fake PEM private-key block) so the redaction logic is
//! exercised against realistic PAN-OS output. Both fixture strings are
//! covered by an explicit `.gitleaks.toml` allowlist entry for this file.

use rust_panosmcp_core::xml::redact_secret_material;

/// MEC-528 class 1: `<show><config><running/></config></show>` and
/// `get_panos_config` on `/config/mgt-config/users` both echo back the
/// admin `<phash>` verbatim without this redaction.
#[test]
fn redacts_type_hashes_but_keeps_surrounding_config() {
    let xml = concat!(
        "<result><config><mgt-config><users><entry name=\"admin\">",
        "<phash>$9$abcXYZ012.def/GHI$rest.of.hash</phash>",
        "</entry></users></mgt-config></config></result>"
    );
    let redacted = redact_secret_material(xml);
    assert!(!redacted.contains("$9$"), "phash leaked: {redacted}");
    assert!(redacted.contains("<phash>[REDACTED-HASH]</phash>"));
    assert!(
        redacted.contains("name=\"admin\""),
        "unrelated content dropped"
    );
}

/// A type-8 hash (SHA256, older PAN-OS) must be redacted the same way.
#[test]
fn redacts_type_eight_hash() {
    let xml = r#"<phash>$8$saltvalue$hashvalue</phash>"#;
    assert_eq!(
        redact_secret_material(xml),
        "<phash>[REDACTED-HASH]</phash>"
    );
}

/// MEC-528 class 1: reading a certificate xpath returns the private key
/// PEM block verbatim without this redaction.
#[test]
fn redacts_pem_private_key_block_entirely() {
    let xml = concat!(
        "<result><certificate><private-key>",
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "MIIBOgIBAAJBAK...redacted-body...==\n",
        "-----END RSA PRIVATE KEY-----",
        "</private-key></certificate></result>"
    );
    let redacted = redact_secret_material(xml);
    assert!(!redacted.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!redacted.contains("MIIBOgIBAAJBAK"));
    assert!(redacted.contains("<private-key>[REDACTED-PRIVATE-KEY]</private-key>"));
}

/// A public key or certificate body (not a private key) must survive
/// untouched -- only `PRIVATE KEY` PEM labels are redacted.
#[test]
fn does_not_redact_public_certificate_pem() {
    let xml = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBOgIBAAJBAK...cert-body...==\n",
        "-----END CERTIFICATE-----"
    );
    assert_eq!(redact_secret_material(xml), xml);
}

/// A dollar sign that is not a type-8/9 hash prefix must survive.
#[test]
fn does_not_redact_unrelated_dollar_signs() {
    let xml = "<description>Cost is $9 per unit, budget $8.50</description>";
    assert_eq!(redact_secret_material(xml), xml);
}

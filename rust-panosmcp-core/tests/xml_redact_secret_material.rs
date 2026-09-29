//! MEC-528 classes 1 and F3: `redact_secret_material` unit tests.
//!
//! These fixtures are intentionally secret-shaped (fake PAN-OS admin
//! `phash`/master-key values, a fake PEM private-key block) so the redaction
//! logic is exercised against realistic PAN-OS output. All fixture strings
//! are covered by an explicit `.gitleaks.toml` allowlist entry for this
//! file.

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
    assert!(redacted.contains("<phash>[REDACTED-SECRET]</phash>"));
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
        "<phash>[REDACTED-SECRET]</phash>"
    );
}

/// MEC-528 F3: a PAN-OS admin `<phash>` on current releases is `$1$...`
/// (MD5) or `$5$`/`$6$` (SHA-256/512), not only the `$8$`/`$9$` Junos/Cisco
/// shapes the redaction used to recognise. All three leaked unredacted
/// before this fix widened the crypt-token match from a hardcoded `8`/`9`
/// to any short alphanumeric algorithm id.
#[test]
fn redacts_pan_os_crypt_hash_formats() {
    for phash in [
        "$1$abcdefgh$rest.of.the.md5.hash",
        "$5$rounds=5000$saltvalue$rest.of.the.sha256.hash",
        "$6$saltvalue$rest.of.the.sha512.hash",
    ] {
        let xml = format!("<phash>{phash}</phash>");
        let redacted = redact_secret_material(&xml);
        assert!(!redacted.contains('$'), "hash leaked: {redacted}");
        assert_eq!(redacted, "<phash>[REDACTED-SECRET]</phash>");
    }
}

/// MEC-528 F3: a stored PAN-OS secret (an IKE PSK, a bind password, an
/// SNMPv3 key) is a master-key-encrypted blob starting `-AQ==`, not a hash
/// and not PEM. This format leaked unredacted through both the phash and
/// PEM passes before this fix added a dedicated pass for it.
#[test]
fn redacts_master_key_blob_format() {
    let xml = "<key>-AQ==abcdefghijklmnopqrstuvwxyz0123456789+/==</key>";
    let redacted = redact_secret_material(xml);
    assert!(
        !redacted.contains("-AQ=="),
        "master-key blob leaked: {redacted}"
    );
    assert_eq!(redacted, "<key>[REDACTED-SECRET]</key>");
}

/// MEC-528 F3: a master-key blob inside a certificate `<private-key>`
/// element (not every private key on the wire is PEM) must be redacted too.
#[test]
fn redacts_master_key_blob_in_private_key_element() {
    let xml = "<private-key>-AQ==certificatekeymaterialrest==</private-key>";
    let redacted = redact_secret_material(xml);
    assert!(!redacted.contains("-AQ=="));
    assert_eq!(redacted, "<private-key>[REDACTED-SECRET]</private-key>");
}

/// MEC-528 F3: the structural pass blanks a named secret element's text
/// regardless of its shape -- an SNMP community string or a PSK typed
/// directly into a config has no fixed shape a value-based pass could
/// recognise, but the element name (`community`, `secret`, `password`, ...)
/// is a stable signal.
#[test]
fn redacts_free_text_secrets_by_element_name() {
    for (element, value) in [
        ("community", "public-but-not-really-a-secret-string"),
        ("secret", "correct-horse-battery-staple"),
        ("password", "hunter2"),
        ("bind-password", "ldap-bind-secret"),
        ("auth-password", "ike-auth-secret"),
        ("priv-password", "snmpv3-priv-secret"),
        ("passphrase", "vpn-passphrase-value"),
    ] {
        let xml = format!("<{element}>{value}</{element}>");
        let redacted = redact_secret_material(&xml);
        assert!(
            !redacted.contains(value),
            "free-text secret leaked for <{element}>: {redacted}"
        );
        assert_eq!(
            redacted,
            format!("<{element}>[REDACTED-SECRET]</{element}>")
        );
    }
}

/// A `<key>` element that is not shaped like a secret at all (no crypt
/// prefix, no master-key marker) is still blanked -- the element name alone
/// is the signal, deliberately, since a value with no recognisable shape is
/// exactly what a value-based pass cannot catch.
#[test]
fn redacts_unshaped_key_element_by_name() {
    let xml = "<key>plain-unshaped-secret-value</key>";
    assert_eq!(redact_secret_material(xml), "<key>[REDACTED-SECRET]</key>");
}

/// A secret element name must not swallow its siblings' text.
#[test]
fn structural_redaction_does_not_touch_sibling_elements() {
    let xml =
        "<entry name=\"admin\"><phash>$9$a$b</phash><permissions>superuser</permissions></entry>";
    let redacted = redact_secret_material(xml);
    assert!(redacted.contains("<permissions>superuser</permissions>"));
    assert!(redacted.contains("<phash>[REDACTED-SECRET]</phash>"));
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
    assert!(redacted.contains("<private-key>[REDACTED-SECRET]</private-key>"));
}

/// A PEM private-key block outside any named secret element (e.g. an
/// op-command diagnostic that happens to quote one) must still be redacted
/// by the value-shape pass.
#[test]
fn redacts_pem_private_key_outside_a_named_element() {
    let xml = concat!(
        "<line>certificate export failed: ",
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "MIIBOgIBAAJBAK...redacted-body...==\n",
        "-----END RSA PRIVATE KEY-----",
        "</line>"
    );
    let redacted = redact_secret_material(xml);
    assert!(!redacted.contains("BEGIN RSA PRIVATE KEY"));
    assert!(redacted.contains("[REDACTED-PRIVATE-KEY]"));
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

/// A dollar sign that is not a crypt-hash prefix must survive.
#[test]
fn does_not_redact_unrelated_dollar_signs() {
    let xml = "<description>Cost is $9 per unit, budget $8.50</description>";
    assert_eq!(redact_secret_material(xml), xml);
}

//! Boundary helper for scrubbing device-sourced XML before it reaches a tool
//! result.
//!
//! PAN-OS's own read APIs return exactly what an operator would see over the
//! GUI or CLI -- `phash` values, IPsec/IKE pre-shared keys, RADIUS/LDAP
//! server secrets, and the SNMP community string all come back inline in
//! config and op-command XML. This server hands that XML to a model with no
//! duty of confidentiality, so every place a device's raw XML becomes part
//! of a tool's return value must pass through here first.
//!
//! `redact_device_xml` is deliberately the *only* function this module
//! exports: callers pass the exact XML string they are about to embed in a
//! result, at the point it is about to leave the device-facing layer,
//! rather than earlier (before the caller has the whole document) or later
//! (after it has already been serialized into a `BoundedText` or a JSON
//! tool result, where a truncated or already-escaped copy is harder to
//! redact correctly).

/// Redact secret-shaped values out of a raw PAN-OS XML document.
///
/// Tries [`mecmcp_redact::redact_xml_str`] first -- the structured pass that
/// understands element and attribute names, not just line shapes. PAN-OS
/// responses are well-formed XML, so this succeeds in the overwhelmingly
/// common case.
///
/// Falls back to [`mecmcp_redact::redact_text`] (which always succeeds) when
/// the input does not parse as XML -- an unusual, but not impossible, device
/// response (a stray control character, a non-UTF-8 byte PAN-OS itself
/// mangled). The contract this module exists to hold is "never return raw
/// device XML," not "always use the XML-aware pass," so a parse failure
/// must never become a reason to skip redaction altogether.
#[must_use]
pub(crate) fn redact_device_xml(xml: &str) -> String {
    mecmcp_redact::redact_xml_str(xml).unwrap_or_else(|_| mecmcp_redact::redact_text(xml))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_xml_is_redacted_structurally() {
        let xml =
            r#"<response status="success"><result><phash>FAKEphash123</phash></result></response>"#;
        let out = redact_device_xml(xml);
        assert!(!out.contains("FAKEphash123"), "got: {out}");
        assert!(out.contains("<result>"), "structure must survive: {out}");
    }

    #[test]
    fn malformed_input_still_gets_the_text_fallback() {
        let malformed = "<unclosed><phash>FAKEphash456</phash>";
        let out = redact_device_xml(malformed);
        assert!(
            !out.contains("FAKEphash456"),
            "a parse failure must not skip redaction: {out}"
        );
    }
}

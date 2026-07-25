//! Tracing and audit initialization via mecmcp-audit.

pub use mecmcp_audit::{
    Attribution, AuditConfig, AuditFormat, AuditRedaction, AuditScope, Principal, RedactError,
    init_tracing,
};

/// Initialize tracing with the given audit configuration.
///
/// This is a convenience wrapper that maps Result to bool for backward compatibility.
/// Returns `true` on success, `false` if initialization fails (e.g., journald unavailable).
pub fn init_with_config(cfg: &AuditConfig) -> bool {
    init_tracing(cfg).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_with_defaults_succeeds() {
        let cfg = AuditConfig {
            format: AuditFormat::Text,
            audit_log_file: None,
            redaction: None,
            journald: false,
        };
        assert!(init_with_config(&cfg));
    }
}

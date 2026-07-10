//! Tracing conventions for binaries and future structured audit events.

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Dedicated target for security-relevant audit events.
pub const AUDIT_TARGET: &str = "rust_panosmcp::audit";

/// Install the default stderr tracing subscriber.
///
/// `RUST_LOG` controls filtering. If it is absent or invalid, an `info`
/// default is used. Repeated initialization is harmless, which keeps test and
/// embedding scenarios straightforward.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr));
    let _already_initialized = subscriber.try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_target_is_stable() {
        assert_eq!(AUDIT_TARGET, "rust_panosmcp::audit");
    }
}

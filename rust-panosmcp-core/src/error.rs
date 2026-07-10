//! Stable error categories shared by future PAN-OS tools.

/// Result alias for core operations.
pub type Result<T> = std::result::Result<T, PanosMcpError>;

/// Stable top-level error categories.
///
/// Variants must describe failures without embedding credentials or complete
/// device responses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PanosMcpError {
    /// Startup or operator configuration is invalid.
    #[error("configuration error: {0}")]
    Configuration(String),
    /// Caller-controlled input exceeded an explicit limit.
    #[error("input '{field}' exceeds the {limit}-byte limit")]
    InputTooLarge {
        /// Logical input field.
        field: &'static str,
        /// Maximum accepted bytes.
        limit: usize,
    },
    /// PAN-OS returned or the caller supplied invalid XML.
    #[error("XML error: {0}")]
    Xml(String),
    /// An operation exceeded its caller-visible deadline.
    #[error("operation '{operation}' timed out")]
    Timeout {
        /// Stable operation identifier.
        operation: &'static str,
    },
    /// MCP cancellation was observed.
    #[error("operation cancelled")]
    Cancelled,
}

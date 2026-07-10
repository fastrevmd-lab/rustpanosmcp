//! Stable error categories shared by PAN-OS tools.

use std::path::PathBuf;

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
    /// Device inventory schema or values are invalid.
    #[error("inventory error: {0}")]
    Inventory(String),
    /// A configured secret source is absent or invalid.
    #[error("secret error: {0}")]
    Secret(String),
    /// A configured file failed an ownership, mode, type, or size check.
    #[error("{purpose} file '{}' is unsafe: {reason}", path.display())]
    FileSecurity {
        /// Stable file purpose without file content.
        purpose: &'static str,
        /// Operator-configured path.
        path: PathBuf,
        /// Non-secret refusal reason.
        reason: String,
    },
    /// A configured file could not be read.
    #[error("failed to read {purpose} file '{}': {error}", path.display())]
    FileIo {
        /// Stable file purpose without file content.
        purpose: &'static str,
        /// Operator-configured path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        error: std::io::Error,
    },
    /// No exact inventory entry exists for the supplied name.
    #[error("unknown device '{0}'")]
    UnknownDevice(String),
    /// TLS client construction or verification failed.
    #[error("TLS configuration error for device '{device}': {reason}")]
    Tls {
        /// Safe inventory device name.
        device: String,
        /// Non-secret failure description.
        reason: String,
    },
    /// HTTP transport failed before a PAN-OS response was available.
    #[error("PAN-OS transport error for device '{device}': {reason}")]
    Transport {
        /// Safe inventory device name.
        device: String,
        /// Sanitized failure category.
        reason: String,
    },
    /// PAN-OS returned a non-success HTTP status.
    #[error("PAN-OS HTTP status {status} for device '{device}'")]
    HttpStatus {
        /// Safe inventory device name.
        device: String,
        /// Numeric HTTP status.
        status: u16,
    },
    /// PAN-OS returned a typed XML API error response.
    #[error("PAN-OS API error for device '{device}': code={code} ({name}): {message}")]
    Api {
        /// Safe inventory device name.
        device: String,
        /// Numeric PAN-OS XML API code.
        code: i32,
        /// Stable mapped code name.
        name: &'static str,
        /// Bounded device-supplied message.
        message: String,
    },
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
    /// PAN-OS returned more response data than the device hard cap.
    #[error("PAN-OS response for device '{device}' exceeds the {limit}-byte limit")]
    ResponseTooLarge {
        /// Safe inventory device name.
        device: String,
        /// Configured hard cap.
        limit: usize,
    },
    /// Caller input violates a command, XPath, or lifecycle policy.
    #[error("policy rejected {field}: {reason}")]
    Policy {
        /// Stable input field.
        field: &'static str,
        /// Non-secret refusal reason.
        reason: String,
    },
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

//! Authentication, digest-only token persistence, and authorization scopes.

pub mod bearer;
pub mod file;
pub mod secret;
pub mod store;
pub mod token;

pub use bearer::{BearerHeaderError, parse_bearer_header};
pub use file::{TokenStoreFile, TokenStoreFileError};
pub use secret::SecretString;
pub use store::{CallerContext, ScopeSet, TokenEntry, TokenStore};
pub use token::{TokenDigest, TokenError, TokenSecret};

/// Exact Phase 2 tool registry used to validate token scopes.
pub const KNOWN_TOOLS: &[&str] = &[
    "execute_panos_op",
    "gather_device_facts",
    "get_panos_config",
    "list_devices",
];

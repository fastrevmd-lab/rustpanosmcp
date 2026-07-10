//! Authentication, digest-only token persistence, and authorization scopes.

pub mod bearer;
pub mod file;
pub mod secret;
pub mod store;
pub mod token;

pub use bearer::{BearerHeaderError, parse_bearer_header};
pub use file::{TokenStoreFile, TokenStoreFileError};
pub use secret::SecretString;
pub use store::{CallerContext, MutationAction, MutationGrant, ScopeSet, TokenEntry, TokenStore};
pub use token::{TokenDigest, TokenError, TokenSecret};

/// Exact Phase 2 tool registry used to validate token scopes.
pub const KNOWN_TOOLS: &[&str] = &[
    "apply_panos_change_set",
    "approve_panos_change_set",
    "commit_panos_candidate",
    "create_panos_change_set",
    "diff_panos_candidate",
    "discard_panos_candidate",
    "execute_panos_op",
    "gather_device_facts",
    "get_candidate_fingerprint",
    "get_panos_change_set",
    "get_panos_config",
    "get_panos_operation",
    "list_devices",
    "stage_panos_config",
    "validate_panos_candidate",
];

/// Tools that always require an explicit token allowlist entry.
pub const MUTATION_TOOLS: &[&str] = &[
    "commit_panos_candidate",
    "apply_panos_change_set",
    "approve_panos_change_set",
    "create_panos_change_set",
    "diff_panos_candidate",
    "discard_panos_candidate",
    "get_candidate_fingerprint",
    "get_panos_change_set",
    "get_panos_operation",
    "stage_panos_config",
    "validate_panos_candidate",
];

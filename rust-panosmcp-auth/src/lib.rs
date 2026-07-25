//! PAN-OS authorization vocabulary over the shared mecmcp auth core.

pub mod bearer;
pub mod secret;
mod grant;

pub use bearer::{BearerHeaderError, parse_bearer_header};
pub use grant::{MutationAction, MutationGrant};
pub use secret::SecretString;

// Shared core, re-exported so downstream `use rust_panosmcp_auth::…` paths
// keep working unchanged.
pub use mecmcp_auth::{
    CallerCtx, FileError as TokenStoreFileError, Grant, ScopeSet, StoreError,
    TokenDigest, TokenEntry as SharedTokenEntry, TokenError, TokenSecret, TokenStore as SharedStore,
    TokenStoreFile as SharedFile, file::KnownNames, write_atomic,
};

/// PAN-OS token entry: the shared entry specialised to the PAN-OS grant.
pub type TokenEntry = SharedTokenEntry<MutationGrant>;
/// PAN-OS token store.
pub type TokenStore = SharedStore<MutationGrant>;
/// PAN-OS token file.
pub type TokenStoreFile = SharedFile<MutationGrant>;
/// PAN-OS caller context with mutation grant.
pub type CallerContext = CallerCtx<MutationGrant>;

/// Exact tool registry used to validate token scopes.
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

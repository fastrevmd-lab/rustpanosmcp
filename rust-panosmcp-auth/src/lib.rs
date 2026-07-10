//! Authentication primitives shared by the MCP transports.
//!
//! Token persistence and authorization scopes arrive in Phase 2. Phase 0
//! establishes the secret-redaction and bearer-header parsing invariants that
//! those components will build upon.

mod bearer;
mod secret;

pub use bearer::{BearerHeaderError, parse_bearer_header};
pub use secret::SecretString;

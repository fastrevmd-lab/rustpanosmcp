//! Transport-independent PAN-OS client and tool foundations.

pub mod error;
pub mod observability;
pub mod xml;

pub use error::{PanosMcpError, Result};

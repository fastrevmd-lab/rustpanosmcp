//! Redacted, zeroizing storage for short-lived credentials.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned secret that is redacted from `Debug` and `Display` and zeroized
/// when dropped.
///
/// This type intentionally does not implement `Clone` or serialization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap an owned secret value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Expose the secret to the smallest possible call scope.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting_never_reveals_the_secret() {
        let secret = SecretString::new("pan-api-key-value".to_owned());

        assert_eq!(secret.to_string(), "[REDACTED]");
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
        assert!(!secret.to_string().contains(secret.expose_secret()));
        assert!(!format!("{secret:?}").contains(secret.expose_secret()));
    }
}

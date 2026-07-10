//! Bearer-token minting, versioned digests, and constant-time verification.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SECRET_BYTES: usize = 32;
const ENCODED_SECRET_BYTES: usize = 43;
const DIGEST_PREFIX: &str = "sha256:";

/// Error while minting or decoding token material.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The operating-system CSPRNG failed.
    #[error("operating-system random source failed")]
    Random,
    /// A stored token digest is malformed.
    #[error("invalid token digest: {0}")]
    InvalidDigest(String),
}

/// Fresh bearer secret printed only by add/rotate commands.
///
/// This type deliberately implements neither `Clone`, `Debug`, `Display`, nor
/// serialization. Its owned bytes are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TokenSecret(String);

impl TokenSecret {
    /// Mint 256 random bits and return the plaintext plus its stored digest.
    pub fn mint() -> Result<(Self, TokenDigest), TokenError> {
        let mut random = [0_u8; SECRET_BYTES];
        getrandom::fill(&mut random).map_err(|_| TokenError::Random)?;
        let encoded = URL_SAFE_NO_PAD.encode(random);
        random.zeroize();
        let digest = TokenDigest::from_secret(&encoded);
        Ok((Self(encoded), digest))
    }

    /// Expose the plaintext to the token CLI's single stdout write.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

/// Versioned SHA-256 digest stored in `tokens.json`.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenDigest(String);

impl std::fmt::Debug for TokenDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TokenDigest(sha256:[DIGEST])")
    }
}

impl TokenDigest {
    /// Hash one candidate bearer secret.
    #[must_use]
    pub fn from_secret(secret: &str) -> Self {
        let digest = Sha256::digest(secret.as_bytes());
        Self(format!("{DIGEST_PREFIX}{}", URL_SAFE_NO_PAD.encode(digest)))
    }

    /// Parse and validate a stored versioned digest.
    pub fn parse(value: String) -> Result<Self, TokenError> {
        let encoded = value.strip_prefix(DIGEST_PREFIX).ok_or_else(|| {
            TokenError::InvalidDigest(format!("missing '{DIGEST_PREFIX}' prefix"))
        })?;
        if encoded.len() != ENCODED_SECRET_BYTES {
            return Err(TokenError::InvalidDigest(format!(
                "digest payload must contain {ENCODED_SECRET_BYTES} base64url characters"
            )));
        }
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            TokenError::InvalidDigest("payload is not unpadded base64url".to_owned())
        })?;
        if decoded.len() != SECRET_BYTES {
            return Err(TokenError::InvalidDigest(
                "payload does not decode to a SHA-256 digest".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// Constant-time verification of a candidate plaintext.
    #[must_use]
    pub fn verify(&self, candidate: &str) -> bool {
        let candidate = Self::from_secret(candidate);
        self.constant_time_eq(&candidate)
    }

    /// Compare two already-derived digests without short-circuiting.
    pub(crate) fn constant_time_eq(&self, candidate: &Self) -> bool {
        bool::from(self.0.as_bytes().ct_eq(candidate.0.as_bytes()))
    }

    /// Versioned encoded digest for persistence diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for TokenDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for TokenDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_secret_is_256_bit_unpadded_base64url() {
        let (secret, digest) = TokenSecret::mint().expect("CSPRNG");
        assert_eq!(secret.expose_secret().len(), ENCODED_SECRET_BYTES);
        assert!(
            secret
                .expose_secret()
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') })
        );
        assert!(digest.verify(secret.expose_secret()));
    }

    #[test]
    fn digest_round_trip_and_wrong_secret_refusal() {
        let (secret, digest) = TokenSecret::mint().expect("CSPRNG");
        let encoded = serde_json::to_string(&digest).expect("serialize digest");
        assert!(!encoded.contains(secret.expose_secret()));
        let decoded: TokenDigest = serde_json::from_str(&encoded).expect("digest round trip");
        assert_eq!(decoded, digest);
        assert!(!decoded.verify("definitely-not-the-token"));
    }

    #[test]
    fn malformed_digests_are_refused() {
        for invalid in [
            "plaintext",
            "sha256:short",
            "sha256:+++++++++++++++++++++++++++++++++++++++++++",
        ] {
            assert!(TokenDigest::parse(invalid.to_owned()).is_err());
        }
    }
}

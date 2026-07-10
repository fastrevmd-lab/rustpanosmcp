//! Strict, allocation-free parsing for HTTP bearer credentials.

/// Maximum accepted `Authorization` header length.
///
/// This is deliberately generous enough for future OAuth access tokens while
/// placing a hard ceiling on attacker-controlled input.
const MAX_AUTHORIZATION_HEADER_BYTES: usize = 4096;

/// A bearer-header parsing failure.
///
/// Variants never retain or display the presented credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BearerHeaderError {
    /// The header exceeds the configured hard limit.
    #[error("authorization header is too large")]
    TooLarge,
    /// The header is not valid visible ASCII.
    #[error("authorization header contains invalid characters")]
    InvalidCharacters,
    /// The authorization scheme is absent or is not Bearer.
    #[error("authorization header must use the Bearer scheme")]
    WrongScheme,
    /// No credential follows the Bearer scheme.
    #[error("bearer credential is empty")]
    Empty,
    /// Whitespace appears inside the credential.
    #[error("bearer credential contains whitespace")]
    EmbeddedWhitespace,
}

/// Parse an HTTP `Authorization: Bearer …` value without allocating.
///
/// The scheme is case-insensitive. Leading and trailing spaces around the
/// credential are tolerated, while embedded whitespace and control bytes are
/// rejected. Errors never include the supplied value.
pub fn parse_bearer_header(value: &str) -> Result<&str, BearerHeaderError> {
    if value.len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return Err(BearerHeaderError::TooLarge);
    }
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (byte.is_ascii() && !byte.is_ascii_control()))
    {
        return Err(BearerHeaderError::InvalidCharacters);
    }

    let Some(separator) = value.find(|character: char| character.is_ascii_whitespace()) else {
        return Err(BearerHeaderError::WrongScheme);
    };
    let (scheme, remainder) = value.split_at(separator);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(BearerHeaderError::WrongScheme);
    }

    let credential = remainder.trim_matches(|character: char| character.is_ascii_whitespace());
    if credential.is_empty() {
        return Err(BearerHeaderError::Empty);
    }
    if credential
        .chars()
        .any(|character| character.is_ascii_whitespace())
    {
        return Err(BearerHeaderError::EmbeddedWhitespace);
    }

    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_case_insensitive_scheme() {
        assert_eq!(parse_bearer_header("bEaReR token-123"), Ok("token-123"));
    }

    #[test]
    fn tolerates_outer_horizontal_whitespace() {
        assert_eq!(
            parse_bearer_header("Bearer\t  token-123 \t"),
            Ok("token-123")
        );
    }

    #[test]
    fn rejects_embedded_whitespace() {
        assert_eq!(
            parse_bearer_header("Bearer one two"),
            Err(BearerHeaderError::EmbeddedWhitespace)
        );
    }

    #[test]
    fn errors_do_not_echo_the_credential() {
        let sensitive = "must-not-appear";
        let error = parse_bearer_header(&format!("Basic {sensitive}"))
            .expect_err("Basic authentication must be refused");
        assert!(!error.to_string().contains(sensitive));
        assert!(!format!("{error:?}").contains(sensitive));
    }
}

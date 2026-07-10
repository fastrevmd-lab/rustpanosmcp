//! Fail-closed validation for combinations of remote-server arguments.

use crate::cli::{Cli, Transport};
use std::{net::IpAddr, path::Path};

const MIN_BODY_BYTES: usize = 1024;
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
const MAX_RATE_PER_MINUTE: u32 = 100_000;

/// A CLI combination with no safe unambiguous interpretation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CliRefusal {
    /// Remote transport needs authentication.
    #[error("Streamable HTTP requires --tokens-file, or --allow-no-auth on loopback")]
    AuthRequired,
    /// Auth may not be both configured and disabled.
    #[error("--tokens-file and --allow-no-auth are mutually exclusive")]
    AuthConflict,
    /// No-auth listeners are loopback-only.
    #[error("--allow-no-auth refuses non-loopback bind '{host}'")]
    NoAuthOffLoopback {
        /// Refused bind value.
        host: String,
    },
    /// Off-loopback plaintext is an explicit proxy-only exception.
    #[error("non-loopback plaintext bind '{host}' requires --allow-insecure-bind or TLS")]
    InsecureBindRequired {
        /// Refused bind value.
        host: String,
    },
    /// Certificate and key form one atomic setting.
    #[error("--tls-cert and --tls-key must be set together")]
    TlsPairIncomplete,
    /// Bind address must not involve DNS resolution.
    #[error("--host must be a numeric IPv4 or IPv6 address, got '{host}'")]
    NonNumericHost {
        /// Refused bind value.
        host: String,
    },
    /// Off-loopback hosts must be explicit DNS-rebinding policy entries.
    #[error("non-loopback Streamable HTTP requires at least one --allowed-host")]
    AllowedHostRequired,
    /// Off-loopback browser callers must have explicit CSRF origin policy.
    #[error("non-loopback Streamable HTTP requires at least one --allowed-origin")]
    AllowedOriginRequired,
    /// One Host allowlist entry is malformed.
    #[error("invalid --allowed-host authority '{value}'")]
    InvalidAllowedHost {
        /// Refused value.
        value: String,
    },
    /// One Origin allowlist entry is malformed or is not an HTTP(S) origin.
    #[error("invalid --allowed-origin URL '{value}'")]
    InvalidAllowedOrigin {
        /// Refused value.
        value: String,
    },
    /// Sensitive files are anchored to absolute operator paths.
    #[error("{flag} path must be absolute")]
    AbsolutePathRequired {
        /// Flag whose value was relative.
        flag: &'static str,
    },
    /// Bounded denial-of-service setting failed.
    #[error("--request-body-limit must be between {MIN_BODY_BYTES} and {MAX_BODY_BYTES} bytes")]
    BodyLimit,
    /// A rate setting failed.
    #[error("{flag} must be between 1 and {MAX_RATE_PER_MINUTE}")]
    RateLimit {
        /// Flag whose value was outside the bound.
        flag: &'static str,
    },
}

/// Validate all serve arguments before inventory, secrets, sockets, or TLS load.
pub fn validate(cli: &Cli) -> Result<(), CliRefusal> {
    if cli.transport == Transport::Stdio {
        return Ok(());
    }

    let host: IpAddr = cli.host.parse().map_err(|_| CliRefusal::NonNumericHost {
        host: cli.host.clone(),
    })?;
    let loopback = host.is_loopback();
    let tls = match (cli.tls_cert.as_ref(), cli.tls_key.as_ref()) {
        (Some(cert), Some(key)) => {
            require_absolute(cert, "--tls-cert")?;
            require_absolute(key, "--tls-key")?;
            true
        }
        (None, None) => false,
        _ => return Err(CliRefusal::TlsPairIncomplete),
    };

    match (&cli.tokens_file, cli.allow_no_auth) {
        (None, false) => return Err(CliRefusal::AuthRequired),
        (Some(_), true) => return Err(CliRefusal::AuthConflict),
        (None, true) if !loopback => {
            return Err(CliRefusal::NoAuthOffLoopback {
                host: cli.host.clone(),
            });
        }
        (Some(path), false) => require_absolute(path, "--tokens-file")?,
        _ => {}
    }
    if !loopback && !tls && !cli.allow_insecure_bind {
        return Err(CliRefusal::InsecureBindRequired {
            host: cli.host.clone(),
        });
    }
    if !loopback && cli.allowed_host.is_empty() {
        return Err(CliRefusal::AllowedHostRequired);
    }
    if !loopback && cli.allowed_origin.is_empty() {
        return Err(CliRefusal::AllowedOriginRequired);
    }
    for value in &cli.allowed_host {
        validate_allowed_host(value)?;
    }
    for value in &cli.allowed_origin {
        validate_allowed_origin(value)?;
    }
    if !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&cli.request_body_limit) {
        return Err(CliRefusal::BodyLimit);
    }
    validate_rate(cli.ip_rate_per_minute, "--ip-rate-per-minute")?;
    validate_rate(cli.token_rate_per_minute, "--token-rate-per-minute")?;
    Ok(())
}

fn validate_allowed_host(value: &str) -> Result<(), CliRefusal> {
    if value.is_empty()
        || value.len() > 255
        || value.trim() != value
        || value.contains('@')
        || http::uri::Authority::try_from(value).is_err()
    {
        return Err(CliRefusal::InvalidAllowedHost {
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_allowed_origin(value: &str) -> Result<(), CliRefusal> {
    let valid = value
        .parse::<http::Uri>()
        .ok()
        .filter(|uri| matches!(uri.scheme_str(), Some("http" | "https")))
        .filter(|uri| {
            uri.authority()
                .is_some_and(|authority| !authority.as_str().contains('@'))
        })
        .is_some_and(|uri| uri.query().is_none() && (uri.path().is_empty() || uri.path() == "/"));
    if !valid || value.len() > 2048 {
        return Err(CliRefusal::InvalidAllowedOrigin {
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn require_absolute(path: &Path, flag: &'static str) -> Result<(), CliRefusal> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(CliRefusal::AbsolutePathRequired { flag })
    }
}

fn validate_rate(value: u32, flag: &'static str) -> Result<(), CliRefusal> {
    if (1..=MAX_RATE_PER_MINUTE).contains(&value) {
        Ok(())
    } else {
        Err(CliRefusal::RateLimit { flag })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("rust-panosmcp").chain(args.iter().copied()))
    }

    #[test]
    fn stdio_remains_local_and_valid() {
        assert!(validate(&parse(&[])).is_ok());
    }

    #[test]
    fn http_requires_exactly_one_auth_mode() {
        assert_eq!(
            validate(&parse(&["-t", "streamable-http"])),
            Err(CliRefusal::AuthRequired)
        );
        assert_eq!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--allow-no-auth"
            ])),
            Err(CliRefusal::AuthConflict)
        );
        assert!(validate(&parse(&["-t", "streamable-http", "--allow-no-auth"])).is_ok());
    }

    #[test]
    fn host_must_be_numeric_and_no_auth_must_be_loopback() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--allow-no-auth",
                "-H",
                "localhost"
            ])),
            Err(CliRefusal::NonNumericHost { .. })
        ));
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--allow-no-auth",
                "-H",
                "0.0.0.0"
            ])),
            Err(CliRefusal::NoAuthOffLoopback { .. })
        ));
    }

    #[test]
    fn off_loopback_requires_transport_host_and_origin_controls() {
        let base = [
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/tokens.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
        ];
        assert_eq!(
            validate(&parse(&base)),
            Err(CliRefusal::AllowedHostRequired)
        );
        let mut with_host = base.to_vec();
        with_host.extend(["--allowed-host", "mcp.example.test"]);
        assert_eq!(
            validate(&parse(&with_host)),
            Err(CliRefusal::AllowedOriginRequired)
        );
        with_host.extend(["--allowed-origin", "https://client.example.test"]);
        assert!(validate(&parse(&with_host)).is_ok());
    }

    #[test]
    fn tls_pair_absolute_paths_and_limits_are_strict() {
        assert_eq!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--tls-cert",
                "/tmp/cert.pem"
            ])),
            Err(CliRefusal::TlsPairIncomplete)
        );
        assert_eq!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--request-body-limit",
                "1"
            ])),
            Err(CliRefusal::BodyLimit)
        );
    }

    #[test]
    fn malformed_host_and_origin_policy_is_refused() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--allowed-host",
                "https://wrong-shape"
            ])),
            Err(CliRefusal::InvalidAllowedHost { .. })
        ));
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--allowed-origin",
                "ftp://client.example.test"
            ])),
            Err(CliRefusal::InvalidAllowedOrigin { .. })
        ));
    }
}

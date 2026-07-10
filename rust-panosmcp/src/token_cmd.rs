//! Digest-only token-store command implementation.

use crate::cli::TokenAction;
use rust_panosmcp_auth::{ScopeSet, TokenStoreFile, TokenStoreFileError};
use std::io::Write;

/// Token command failure.
#[derive(Debug, thiserror::Error)]
pub enum TokenCommandError {
    /// Store persistence or validation failed.
    #[error(transparent)]
    Store(#[from] TokenStoreFileError),
    /// Scope syntax was ambiguous.
    #[error("invalid {field} scope: {message}")]
    Scope {
        /// Scope field.
        field: &'static str,
        /// Safe diagnostic.
        message: String,
    },
    /// Output or signal failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Execute one token management command.
pub fn run(action: TokenAction, known_devices: &[String]) -> Result<(), TokenCommandError> {
    match action {
        TokenAction::Add {
            tokens_file,
            name,
            devices,
            tools,
            server_pid,
        } => {
            let devices = parse_scope(devices, "devices")?;
            let tools = parse_scope(tools, "tools")?;
            let secret = TokenStoreFile::add(&tokens_file, &name, devices, tools, known_devices)?;
            writeln!(std::io::stdout().lock(), "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
        }
        TokenAction::List { tokens_file } => {
            let store = TokenStoreFile::load(&tokens_file, known_devices)?;
            let mut output = std::io::stdout().lock();
            writeln!(output, "NAME\tDEVICES\tTOOLS\tCREATED_UNIX")?;
            for entry in store.entries() {
                writeln!(
                    output,
                    "{}\t{}\t{}\t{}",
                    entry.name,
                    entry.devices.summary(),
                    entry.tools.summary(),
                    entry.created_at_unix
                )?;
            }
        }
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let removed = TokenStoreFile::revoke(&tokens_file, &name, known_devices)?;
            if removed {
                eprintln!("revoked '{name}'");
                signal_reload(server_pid)?;
            } else {
                eprintln!("token '{name}' did not exist");
            }
        }
        TokenAction::Rotate {
            tokens_file,
            name,
            server_pid,
        } => {
            let secret = TokenStoreFile::rotate(&tokens_file, &name, known_devices)?;
            writeln!(std::io::stdout().lock(), "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
        }
    }
    Ok(())
}

fn parse_scope(values: Vec<String>, field: &'static str) -> Result<ScopeSet, TokenCommandError> {
    if values.is_empty() {
        return Err(TokenCommandError::Scope {
            field,
            message: "at least one exact name or '*' is required".to_owned(),
        });
    }
    if values.iter().any(|value| value == "*") {
        if values.len() == 1 {
            return Ok(ScopeSet::Wildcard);
        }
        return Err(TokenCommandError::Scope {
            field,
            message: "'*' cannot be mixed with exact names".to_owned(),
        });
    }
    Ok(ScopeSet::Allowlist(values))
}

#[cfg(unix)]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    let Some(raw) = pid else {
        return Ok(());
    };
    let pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "server PID must be positive",
        )
    })?;
    rustix::process::kill_process(pid, rustix::process::Signal::HUP)
        .map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(not(unix))]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    if pid.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SIGHUP reload is available only on Unix",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_is_exclusive() {
        assert!(matches!(
            parse_scope(vec!["*".to_owned()], "tools"),
            Ok(ScopeSet::Wildcard)
        ));
        assert!(parse_scope(vec!["*".to_owned(), "list_devices".to_owned()], "tools").is_err());
        assert!(parse_scope(Vec::new(), "tools").is_err());
    }
}

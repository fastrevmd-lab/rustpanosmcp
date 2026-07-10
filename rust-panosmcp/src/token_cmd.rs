//! Digest-only token-store command implementation.

use crate::cli::TokenAction;
use rust_panosmcp_auth::{
    MutationAction, MutationGrant, ScopeSet, TokenStoreFile, TokenStoreFileError,
};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

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
            mutation_roots,
            mutation_actions,
            expires_at_unix,
            expires_in_secs,
            server_pid,
        } => {
            let devices = parse_scope(devices, "devices")?;
            let tools = parse_scope(tools, "tools")?;
            let mutation = parse_mutation_grant(mutation_roots, mutation_actions)?;
            let expires_at_unix = resolve_expiry(expires_at_unix, expires_in_secs)?;
            let secret = TokenStoreFile::add_with_options(
                &tokens_file,
                &name,
                devices,
                tools,
                expires_at_unix,
                mutation,
                known_devices,
            )?;
            writeln!(std::io::stdout().lock(), "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
        }
        TokenAction::List { tokens_file } => {
            let store = TokenStoreFile::load(&tokens_file, known_devices)?;
            let mut output = std::io::stdout().lock();
            writeln!(
                output,
                "NAME\tDEVICES\tTOOLS\tMUTATION\tCREATED_UNIX\tEXPIRES_UNIX"
            )?;
            for entry in store.entries() {
                let mutation = entry.mutation.as_ref().map_or_else(
                    || "-".to_owned(),
                    |grant| {
                        let actions = grant
                            .actions
                            .iter()
                            .map(|action| match action {
                                MutationAction::Set => "set",
                                MutationAction::Delete => "delete",
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("{}:{}", actions, grant.allowed_xpath_roots.join("|"))
                    },
                );
                writeln!(
                    output,
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    entry.name,
                    entry.devices.summary(),
                    entry.tools.summary(),
                    mutation,
                    entry.created_at_unix,
                    entry
                        .expires_at_unix
                        .map_or_else(|| "-".to_owned(), |value| value.to_string())
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

fn parse_mutation_grant(
    roots: Vec<String>,
    actions: Vec<String>,
) -> Result<Option<MutationGrant>, TokenCommandError> {
    if roots.is_empty() && actions.is_empty() {
        return Ok(None);
    }
    if roots.is_empty() || actions.is_empty() {
        return Err(TokenCommandError::Scope {
            field: "mutation",
            message: "--mutation-root and --mutation-actions must be supplied together".to_owned(),
        });
    }
    let actions = actions
        .into_iter()
        .map(|action| match action.as_str() {
            "set" => Ok(MutationAction::Set),
            "delete" => Ok(MutationAction::Delete),
            _ => Err(TokenCommandError::Scope {
                field: "mutation_actions",
                message: "only 'set' and 'delete' are supported".to_owned(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(MutationGrant {
        allowed_xpath_roots: roots,
        actions,
    }))
}

fn resolve_expiry(
    absolute: Option<u64>,
    lifetime: Option<u64>,
) -> Result<Option<u64>, TokenCommandError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TokenCommandError::Scope {
            field: "expiry",
            message: "system clock is before Unix epoch".to_owned(),
        })?
        .as_secs();
    let expiry = match (absolute, lifetime) {
        (Some(value), None) => Some(value),
        (None, Some(value)) => Some(now.checked_add(value).ok_or(TokenCommandError::Scope {
            field: "expiry",
            message: "expiry overflows Unix time".to_owned(),
        })?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting expiry options"),
    };
    if expiry.is_some_and(|value| value <= now) {
        return Err(TokenCommandError::Scope {
            field: "expiry",
            message: "token expiry must be in the future".to_owned(),
        });
    }
    Ok(expiry)
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

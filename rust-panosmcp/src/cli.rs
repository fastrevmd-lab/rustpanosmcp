//! Command-line surface for serving MCP and managing bearer tokens.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Supported MCP transports.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Transport {
    /// Local child-process transport with no listening socket.
    Stdio,
    /// MCP Streamable HTTP transport.
    StreamableHttp,
}

/// Process arguments.
#[derive(Debug, Parser)]
#[command(version, about = "Secure, async MCP server for PAN-OS firewalls")]
pub struct Cli {
    /// Optional token-management operation.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Validated JSON device inventory.
    #[arg(short = 'f', long, default_value = "devices.json", global = true)]
    pub device_mapping: PathBuf,

    /// MCP transport.
    #[arg(short = 't', long, value_enum, default_value = "stdio")]
    pub transport: Transport,

    /// Numeric bind address for Streamable HTTP.
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// TCP port for Streamable HTTP.
    #[arg(short = 'p', long, default_value_t = 30031)]
    pub port: u16,

    /// Absolute digest-only bearer-token file path.
    #[arg(long)]
    pub tokens_file: Option<PathBuf>,

    /// Absolute PEM certificate path; requires `--tls-key`.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Absolute PEM private-key path; requires `--tls-cert`.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Disable bearer auth for a loopback-only development listener.
    #[arg(long)]
    pub allow_no_auth: bool,

    /// Permit a non-loopback plaintext listener behind a trusted TLS proxy.
    #[arg(long)]
    pub allow_insecure_bind: bool,

    /// Additional accepted HTTP Host authority. Repeat for multiple values.
    #[arg(long)]
    pub allowed_host: Vec<String>,

    /// Accepted browser Origin URL. Repeat for multiple values.
    #[arg(long)]
    pub allowed_origin: Vec<String>,

    /// Per-source-IP requests allowed per rolling minute window.
    #[arg(long, default_value_t = 120)]
    pub ip_rate_per_minute: u32,

    /// Per-authenticated-token requests allowed per rolling minute window.
    #[arg(long, default_value_t = 240)]
    pub token_rate_per_minute: u32,

    /// Maximum Streamable HTTP request body in bytes.
    #[arg(long, default_value_t = 1024 * 1024)]
    pub request_body_limit: usize,
}

/// Top-level management commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage the digest-only bearer-token store.
    Token {
        /// Token action.
        #[command(subcommand)]
        action: TokenAction,
    },
}

/// Token-store action.
#[derive(Debug, Subcommand)]
pub enum TokenAction {
    /// Mint a token, store only its digest, and print the secret once.
    Add {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Stable audit name for the token.
        #[arg(long)]
        name: String,
        /// Comma-separated exact device names or `*`.
        #[arg(long, value_delimiter = ',', required = true)]
        devices: Vec<String>,
        /// Comma-separated exact MCP tool names or `*`.
        #[arg(long, value_delimiter = ',', required = true)]
        tools: Vec<String>,
        /// Send SIGHUP to this positive process ID after success.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List token names and scopes without secrets or digests.
    List {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Revoke a named token.
    Revoke {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this positive process ID after success.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Replace a token secret while preserving its scopes.
    Rotate {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this positive process ID after success.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_serve_defaults() {
        let cli = Cli::parse_from(["rust-panosmcp"]);
        assert_eq!(cli.transport, Transport::Stdio);
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 30031);
        assert_eq!(cli.request_body_limit, 1024 * 1024);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_token_add_scopes() {
        let cli = Cli::parse_from([
            "rust-panosmcp",
            "token",
            "add",
            "--tokens-file",
            "/tmp/tokens.json",
            "--name",
            "reader",
            "--devices",
            "fw-a,fw-b",
            "--tools",
            "list_devices,get_panos_config",
        ]);
        let Some(Command::Token {
            action: TokenAction::Add { devices, tools, .. },
        }) = cli.command
        else {
            panic!("token add expected");
        };
        assert_eq!(devices, ["fw-a", "fw-b"]);
        assert_eq!(tools, ["list_devices", "get_panos_config"]);
    }
}

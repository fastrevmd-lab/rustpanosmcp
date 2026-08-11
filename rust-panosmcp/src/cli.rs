//! Command-line surface for serving MCP and managing bearer tokens.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Supported MCP transports.
pub use mecmcp_runtime::cli::Transport;

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

    /// Absolute private JSON file for persistent change-set and operation state.
    #[arg(long)]
    pub state_file: Option<PathBuf>,

    /// Run without two-person control: change sets are approved on creation.
    ///
    /// For single-operator environments — a lab with one engineer — where
    /// requiring a second principal makes change sets unusable rather than
    /// safer.
    ///
    /// No approver is invented. A waived change set records `approver: null`
    /// with `approval_waiver: "lab-mode"`, so it stays distinguishable from one
    /// a second person actually reviewed.
    ///
    /// Spelled identically on every mecmcp server (mecmcp#94).
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Seconds a change-set approval stays valid before it expires.
    ///
    /// Spelled identically on every mecmcp server (mecmcp#94).
    #[arg(long = "approval-timeout-secs", default_value_t = 900)]
    pub approval_timeout_secs: u64,

    /// Allow destructive operations on devices owned by a management plane.
    ///
    /// By default, this server refuses `commit_panos_candidate` on devices whose
    /// `config_authority` is not `local` or `unknown`, because writes to
    /// plane-owned devices are overwritten at the next push from the owning
    /// management plane (Panorama, Strata Cloud Manager).
    ///
    /// Set this flag to permit those operations with a warning instead of refusal.
    /// The warning and config_authority are recorded in audit events.
    ///
    /// **Break-glass only**: enabling this defeats the durability check that #102
    /// was created to provide. Leave it off unless you have a specific need to push
    /// config to plane-owned devices (e.g., emergency local override).
    ///
    /// Defaults to false (refuse). Spelled identically on every mecmcp server.
    #[arg(long = "allow-plane-owned-writes")]
    pub allow_plane_owned_writes: bool,

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

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_inflight_requests_per_token: usize,

    /// Max concurrent in-flight requests per target device. 0 = unlimited.
    #[arg(long, default_value_t = 4)]
    pub max_inflight_requests_per_target: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, default_value_t = 128)]
    pub max_sessions: usize,

    /// Max concurrent MCP sessions per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_sessions_per_token: usize,

    /// Expose unauthenticated Prometheus metrics at /metrics (streamable-http only).
    #[arg(long)]
    pub enable_metrics: bool,

    /// Audit log format: `text` or `json`.
    #[arg(long, default_value = "text")]
    pub audit_format: String,

    /// Optional dedicated JSON audit log file path.
    #[arg(long)]
    pub audit_log_file: Option<PathBuf>,

    /// Enable journald audit sink for `target="audit"` events.
    #[arg(long)]
    pub audit_journald: bool,

    /// Optional per-field redaction policy (e.g., `devices=hmac,host=drop`).
    #[arg(long)]
    pub audit_redact: Option<String>,

    /// HMAC key file for audit redaction (required if audit-redact requests hmac).
    #[arg(long)]
    pub audit_hmac_key_file: Option<PathBuf>,
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
    /// Perform offline recovery on the private mutation-state file.
    State {
        /// State recovery action.
        #[command(subcommand)]
        action: StateAction,
    },
}

/// Offline persistent-state recovery action.
#[derive(Debug, Subcommand)]
pub enum StateAction {
    /// Mark an indeterminate operation terminal after manual PAN-OS reconciliation.
    Resolve {
        /// Absolute private mutation-state path.
        #[arg(long)]
        state_file: PathBuf,
        /// Exact persisted operation identifier.
        #[arg(long)]
        operation_id: String,
        /// Externally verified terminal outcome.
        #[arg(long, value_enum)]
        disposition: StateDisposition,
        /// Exact `RESOLVED <id> AS COMMITTED|DISCARDED` confirmation.
        #[arg(long)]
        confirmation: String,
    },
}

/// Manually verified PAN-OS terminal outcome.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum StateDisposition {
    /// The PAN-OS job/config proves commit completed.
    Committed,
    /// The candidate was reverted/discarded and locks were removed.
    Discarded,
}

/// Token-store action.
///
/// `Add` is much wider than the other variants (280 bytes against 56) because
/// it carries every mintable attribute. The lint guards against large values
/// being moved repeatedly; this one is parsed once at startup and destructured
/// immediately, so boxing would buy an allocation and a layer of indirection to
/// optimise a single stack move that never repeats.
#[allow(clippy::large_enum_variant)]
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
        /// Token-specific writable XPath root. Repeat for multiple roots.
        #[arg(long = "mutation-root", requires = "mutation_actions")]
        mutation_roots: Vec<String>,
        /// Comma-separated token-specific actions (`set`, `delete`).
        #[arg(long, value_delimiter = ',', requires = "mutation_roots")]
        mutation_actions: Vec<String>,
        /// Absolute Unix timestamp after which the token is rejected.
        #[arg(long, conflicts_with = "expires_in_secs")]
        expires_at_unix: Option<u64>,
        /// Lifetime from token creation, in seconds.
        #[arg(long, conflicts_with = "expires_at_unix")]
        expires_in_secs: Option<u64>,
        /// Provider name (e.g., "anthropic", "ollama"). Optional.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Required if provider is set.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Optional.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Optional.
        #[arg(long)]
        actor_type: Option<String>,
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
    /// Replace a token's scopes or mutation grant, keeping its secret.
    ///
    /// The secret is what a registered MCP client holds, so changing a scope
    /// used to mean either `rotate` — which reissues the secret and breaks every
    /// client — or hand-editing `tokens.json`. That hand edit is how 608's
    /// `claude-writer` gained its second mutation root: outside any supported
    /// path, with no confirmation and no audit record.
    ///
    /// Omitting a field leaves it unchanged. A widening needs `--yes`.
    SetScopes {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Comma-separated exact device names or `*`. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Comma-separated exact MCP tool names or `*`. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// Token-specific writable XPath root. Repeat for multiple roots.
        ///
        /// The grant is replaced wholesale, not merged: naming one root drops
        /// any others. Merging would make it impossible to *remove* a root
        /// through this command, and a mutation grant is the one scope where
        /// "I meant to replace it" must not silently mean "I added to it".
        #[arg(long = "mutation-root", requires = "mutation_actions")]
        mutation_roots: Vec<String>,
        /// Comma-separated token-specific actions (`set`, `delete`).
        #[arg(long, value_delimiter = ',', requires = "mutation_roots")]
        mutation_actions: Vec<String>,
        /// Apply a widening without the interactive confirmation.
        #[arg(long)]
        yes: bool,
        /// Send SIGHUP to this positive process ID after success.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `token add` must accept the provenance flags and hand them to the token
    /// store. They were passed as a literal `None` per field, which compiles
    /// cleanly and silently strips the caller's identity from every token.
    ///
    /// The same defect on the Junos side rendered every commit-log entry as
    /// `(unknown) on-behalf-of=self` (rustjunosmcp#233). Nothing here caught it
    /// either, so assert on the parse.
    #[test]
    fn token_add_carries_the_provenance_flags() {
        let cli = Cli::parse_from([
            "rust-panosmcp",
            "token",
            "add",
            "--tokens-file",
            "/tmp/t.json",
            "--name",
            "svc",
            "--devices",
            "fw",
            "--tools",
            "*",
            "--provider",
            "anthropic",
            "--provider-tier",
            "private",
            "--on-behalf-of",
            "mharman",
            "--actor-type",
            "agent",
        ]);

        let Some(Command::Token {
            action:
                TokenAction::Add {
                    provider,
                    provider_tier,
                    on_behalf_of,
                    actor_type,
                    ..
                },
        }) = cli.command
        else {
            panic!("expected `token add` to parse");
        };

        assert_eq!(provider.as_deref(), Some("anthropic"));
        assert_eq!(provider_tier.as_deref(), Some("private"));
        assert_eq!(on_behalf_of.as_deref(), Some("mharman"));
        assert_eq!(actor_type.as_deref(), Some("agent"));
    }

    #[test]
    fn secure_serve_defaults() {
        let cli = Cli::parse_from(["rust-panosmcp"]);
        assert_eq!(cli.transport, Transport::Stdio);
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 30031);
        assert_eq!(cli.request_body_limit, 1024 * 1024);
        assert_eq!(cli.max_inflight_requests, 64);
        assert_eq!(cli.max_inflight_requests_per_token, 16);
        assert_eq!(cli.max_inflight_requests_per_target, 4);
        assert_eq!(cli.max_sessions, 128);
        assert_eq!(cli.max_sessions_per_token, 16);
        assert!(!cli.enable_metrics);
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

    #[test]
    fn parses_v02_mutation_grant_and_expiry() {
        let cli = Cli::parse_from([
            "rust-panosmcp",
            "token",
            "add",
            "--tokens-file",
            "/tmp/tokens.json",
            "--name",
            "writer",
            "--devices",
            "fw-a",
            "--tools",
            "create_panos_change_set,apply_panos_change_set",
            "--mutation-root",
            "/config/shared/address",
            "--mutation-actions",
            "set,delete",
            "--expires-in-secs",
            "3600",
        ]);
        let Some(Command::Token {
            action:
                TokenAction::Add {
                    mutation_roots,
                    mutation_actions,
                    expires_in_secs,
                    ..
                },
        }) = cli.command
        else {
            panic!("token add expected");
        };
        assert_eq!(mutation_roots, ["/config/shared/address"]);
        assert_eq!(mutation_actions, ["set", "delete"]);
        assert_eq!(expires_in_secs, Some(3600));
    }
}

//! In-memory token metadata and least-privilege scope evaluation.

use crate::token::TokenDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum supported entries keeps constant-time linear lookup bounded.
pub const MAX_TOKENS: usize = 1024;
/// Maximum names in one explicit scope.
pub const MAX_SCOPE_NAMES: usize = 256;
/// Maximum token-specific XPath roots.
pub const MAX_MUTATION_ROOTS: usize = 64;

/// Token-specific write authority, intersected with the inventory policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationGrant {
    /// Exact XPath subtrees this token may modify.
    pub allowed_xpath_roots: Vec<String>,
    /// Candidate actions this token may plan and apply.
    pub actions: Vec<MutationAction>,
}

impl MutationGrant {
    /// Whether this grant permits an action.
    #[must_use]
    pub fn allows_action(&self, action: MutationAction) -> bool {
        self.actions.contains(&action)
    }

    /// Whether the XPath is equal to or below a granted root.
    #[must_use]
    pub fn allows_xpath(&self, xpath: &str) -> bool {
        self.allowed_xpath_roots.iter().any(|root| {
            xpath == root
                || xpath
                    .strip_prefix(root)
                    .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with('['))
        })
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.allowed_xpath_roots.is_empty()
            || self.allowed_xpath_roots.len() > MAX_MUTATION_ROOTS
        {
            return Err(StoreError::Invalid(format!(
                "mutation grant must contain 1-{MAX_MUTATION_ROOTS} XPath roots"
            )));
        }
        if self.actions.is_empty() {
            return Err(StoreError::Invalid(
                "mutation grant must permit at least one action".to_owned(),
            ));
        }
        let mut roots = BTreeSet::new();
        for root in &self.allowed_xpath_roots {
            if root.len() > 4096 || !root.starts_with("/config/") || root.contains('\0') {
                return Err(StoreError::Invalid(
                    "mutation grant XPath roots must be bounded absolute /config subtrees"
                        .to_owned(),
                ));
            }
            if !roots.insert(root) {
                return Err(StoreError::Invalid(format!(
                    "duplicate mutation XPath root '{root}'"
                )));
            }
        }
        let actions: BTreeSet<_> = self.actions.iter().copied().collect();
        if actions.len() != self.actions.len() {
            return Err(StoreError::Invalid(
                "mutation grant contains duplicate actions".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Candidate actions that can be delegated to a bearer token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationAction {
    /// Merge an XML element.
    Set,
    /// Delete an exact XPath.
    Delete,
}

/// Wildcard or literal allowlist for device/tool names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSet {
    /// Permit every name known to the server.
    Wildcard,
    /// Permit only exact listed names.
    Allowlist(Vec<String>),
}

impl ScopeSet {
    /// Whether an exact name is allowed.
    #[must_use]
    pub fn allows(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Allowlist(names) => names.iter().any(|allowed| allowed == name),
        }
    }

    /// Whether an MCP tool is allowed, with write tools excluded from wildcard.
    #[must_use]
    pub fn allows_tool(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => !crate::MUTATION_TOOLS.contains(&name),
            Self::Allowlist(names) => names.iter().any(|allowed| allowed == name),
        }
    }

    /// Whether this scope permits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Allowlist(names) if names.is_empty())
    }

    /// Validate count, names, duplicates, and wildcard spelling.
    pub fn validate(&self, field: &'static str) -> Result<(), StoreError> {
        let Self::Allowlist(names) = self else {
            return Ok(());
        };
        if names.len() > MAX_SCOPE_NAMES {
            return Err(StoreError::Invalid(format!(
                "{field} scope contains more than {MAX_SCOPE_NAMES} names"
            )));
        }
        let mut seen = BTreeSet::new();
        for name in names {
            validate_name(field, name)?;
            if name == "*" {
                return Err(StoreError::Invalid(format!(
                    "{field} scope may use '*' only as the sole list entry"
                )));
            }
            if !seen.insert(name) {
                return Err(StoreError::Invalid(format!(
                    "duplicate name '{name}' in {field} scope"
                )));
            }
        }
        Ok(())
    }

    /// Stable comma-separated metadata representation.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Wildcard => "*".to_owned(),
            Self::Allowlist(names) => names.join(","),
        }
    }
}

impl Serialize for ScopeSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let names: Vec<&str> = match self {
            Self::Wildcard => vec!["*"],
            Self::Allowlist(names) => names.iter().map(String::as_str).collect(),
        };
        names.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let names = Vec::<String>::deserialize(deserializer)?;
        if names.len() == 1 && names[0] == "*" {
            Ok(Self::Wildcard)
        } else {
            Ok(Self::Allowlist(names))
        }
    }
}

/// One digest-only token entry persisted on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEntry {
    /// Operator-facing non-secret token name.
    pub name: String,
    /// Versioned token digest, never plaintext.
    pub digest: TokenDigest,
    /// Exact device scope.
    pub devices: ScopeSet,
    /// Exact MCP tool scope.
    pub tools: ScopeSet,
    /// Creation or last-rotation Unix timestamp.
    pub created_at_unix: u64,
    /// Optional absolute expiry; expired secrets never authenticate.
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
    /// Optional token-specific write authority for v0.2 change sets.
    #[serde(default)]
    pub mutation: Option<MutationGrant>,
}

/// Authenticated request identity copied into HTTP request extensions.
#[derive(Debug, Clone)]
pub struct CallerContext {
    /// Non-secret token name for audit attribution and rate limiting.
    pub token_name: String,
    /// Exact device authorization.
    pub devices: ScopeSet,
    /// Exact tool authorization.
    pub tools: ScopeSet,
    /// Token-specific write authority.
    pub mutation: Option<MutationGrant>,
}

impl From<&TokenEntry> for CallerContext {
    fn from(entry: &TokenEntry) -> Self {
        Self {
            token_name: entry.name.clone(),
            devices: entry.devices.clone(),
            tools: entry.tools.clone(),
            mutation: entry.mutation.clone(),
        }
    }
}

/// Immutable token store swapped atomically on reload.
#[derive(Debug, Clone, Default)]
pub struct TokenStore {
    entries: Vec<TokenEntry>,
}

impl TokenStore {
    /// Validate unique names and bounded entries.
    pub fn new(entries: Vec<TokenEntry>) -> Result<Self, StoreError> {
        if entries.len() > MAX_TOKENS {
            return Err(StoreError::Invalid(format!(
                "token store contains more than {MAX_TOKENS} entries"
            )));
        }
        let mut names = BTreeSet::new();
        for entry in &entries {
            validate_name("token", &entry.name)?;
            entry.devices.validate("devices")?;
            entry.tools.validate("tools")?;
            if entry
                .expires_at_unix
                .is_some_and(|expiry| expiry <= entry.created_at_unix)
            {
                return Err(StoreError::Invalid(
                    "token expiry must be later than its creation time".to_owned(),
                ));
            }
            if let Some(grant) = &entry.mutation {
                grant.validate()?;
            }
            if !names.insert(entry.name.as_str()) {
                return Err(StoreError::Invalid(format!(
                    "duplicate token name '{}'",
                    entry.name
                )));
            }
        }
        Ok(Self { entries })
    }

    /// Verify a candidate against every digest before returning a match.
    #[must_use]
    pub fn authenticate(&self, candidate: &str) -> Option<&TokenEntry> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(u64::MAX, |duration| duration.as_secs());
        self.authenticate_at(candidate, now)
    }

    /// Verify a candidate at a supplied time, allowing deterministic expiry tests.
    #[must_use]
    pub fn authenticate_at(&self, candidate: &str, now_unix: u64) -> Option<&TokenEntry> {
        // Hash once so the bounded full traversal performs only cheap
        // constant-time digest comparisons, even at MAX_TOKENS.
        let candidate = TokenDigest::from_secret(candidate);
        let mut matched = None;
        for entry in &self.entries {
            let current = entry.expires_at_unix.is_none_or(|expiry| now_unix < expiry);
            if entry.digest.constant_time_eq(&candidate) && current && matched.is_none() {
                matched = Some(entry);
            }
        }
        matched
    }

    /// Stable token entries for persistence and metadata listing.
    #[must_use]
    pub fn entries(&self) -> &[TokenEntry] {
        &self.entries
    }

    /// Number of configured tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no tokens exist.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Token metadata validation failure.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Schema or semantic validation failure.
    #[error("{0}")]
    Invalid(String),
}

/// Validate operator-controlled token/scope identifiers.
pub fn validate_name(field: &'static str, name: &str) -> Result<(), StoreError> {
    if name.is_empty() || name.len() > 64 {
        return Err(StoreError::Invalid(format!(
            "{field} name must contain 1-64 bytes"
        )));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(StoreError::Invalid(format!(
            "{field} name contains unsupported characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, secret: &str) -> TokenEntry {
        TokenEntry {
            name: name.to_owned(),
            digest: TokenDigest::from_secret(secret),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at_unix: 1,
            expires_at_unix: None,
            mutation: None,
        }
    }

    #[test]
    fn scopes_are_exact_and_wildcard_is_canonical() {
        let exact = ScopeSet::Allowlist(vec!["fw-1".to_owned()]);
        assert!(exact.allows("fw-1"));
        assert!(!exact.allows("FW-1"));
        assert!(ScopeSet::Wildcard.allows("anything"));
        assert!(ScopeSet::Wildcard.allows_tool("list_devices"));
        assert!(!ScopeSet::Wildcard.allows_tool("commit_panos_candidate"));
        assert!(
            ScopeSet::Allowlist(vec!["commit_panos_candidate".to_owned()])
                .allows_tool("commit_panos_candidate")
        );
        assert!(
            ScopeSet::Allowlist(vec!["*".to_owned(), "fw-1".to_owned()])
                .validate("devices")
                .is_err()
        );
    }

    #[test]
    fn store_authenticates_only_correct_secret() {
        let store = TokenStore::new(vec![entry("one", "secret-one"), entry("two", "secret-two")])
            .expect("store");
        assert_eq!(
            store
                .authenticate("secret-two")
                .map(|entry| entry.name.as_str()),
            Some("two")
        );
        assert!(store.authenticate("unknown").is_none());
    }

    #[test]
    fn store_refuses_duplicates_and_excessive_names() {
        assert!(TokenStore::new(vec![entry("same", "a"), entry("same", "b")]).is_err());
        assert!(validate_name("token", &"x".repeat(65)).is_err());
    }

    #[test]
    fn expiry_and_mutation_grants_are_fail_closed() {
        let mut expiring = entry("writer", "secret");
        expiring.expires_at_unix = Some(10);
        expiring.mutation = Some(MutationGrant {
            allowed_xpath_roots: vec!["/config/shared/address".to_owned()],
            actions: vec![MutationAction::Set],
        });
        let store = TokenStore::new(vec![expiring]).expect("valid grant");
        assert!(store.authenticate_at("secret", 9).is_some());
        assert!(store.authenticate_at("secret", 10).is_none());
        let grant = store.entries()[0].mutation.as_ref().expect("grant");
        assert!(grant.allows_xpath("/config/shared/address/entry[@name='x']"));
        assert!(!grant.allows_xpath("/config/shared/address-group"));
        assert!(grant.allows_action(MutationAction::Set));
        assert!(!grant.allows_action(MutationAction::Delete));
    }
}

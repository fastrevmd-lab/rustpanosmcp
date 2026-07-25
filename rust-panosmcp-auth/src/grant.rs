//! PAN-OS mutation grants and action vocabulary.

use mecmcp_auth::{Grant, GrantError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
}

impl Grant for MutationGrant {
    type Action = MutationAction;

    fn allows_action(&self, action: Self::Action) -> bool {
        self.actions.contains(&action)
    }

    fn allows_subject(&self, subject: &str) -> bool {
        self.allows_xpath(subject)
    }

    fn validate(&self) -> Result<(), GrantError> {
        if self.allowed_xpath_roots.is_empty()
            || self.allowed_xpath_roots.len() > MAX_MUTATION_ROOTS
        {
            return Err(GrantError::Invalid(format!(
                "mutation grant must contain 1-{MAX_MUTATION_ROOTS} XPath roots"
            )));
        }
        if self.actions.is_empty() {
            return Err(GrantError::Invalid(
                "mutation grant must permit at least one action".to_owned(),
            ));
        }
        let mut roots = BTreeSet::new();
        for root in &self.allowed_xpath_roots {
            if root.len() > 4096 || !root.starts_with("/config/") || root.contains('\0') {
                return Err(GrantError::Invalid(
                    "mutation grant XPath roots must be bounded absolute /config subtrees"
                        .to_owned(),
                ));
            }
            if !roots.insert(root) {
                return Err(GrantError::Invalid(format!(
                    "duplicate mutation XPath root '{root}'"
                )));
            }
        }
        let actions: BTreeSet<_> = self.actions.iter().copied().collect();
        if actions.len() != self.actions.len() {
            return Err(GrantError::Invalid(
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

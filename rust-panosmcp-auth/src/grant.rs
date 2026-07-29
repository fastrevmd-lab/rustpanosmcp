//! PAN-OS mutation grants and action vocabulary.

use mecmcp_auth::{Grant, GrantError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum token-specific XPath roots.
pub const MAX_MUTATION_ROOTS: usize = 64;

/// Rewrite attribute predicates to a single canonical quote style.
///
/// `[@name='x']` and `[@name="x"]` are the same XPath, but the mutation checks
/// compare strings. On LXC 608 the device policy stored one style and the token
/// grant the other, so every write was refused by whichever layer disagreed with
/// the request — the server was fully configured and could not perform a single
/// mutation (rustpanosmcp#82).
///
/// Deliberately not a blind `"` to `'` swap: a value may legitimately contain an
/// apostrophe, and swapping would produce `[@name='O'Brien']`, which is broken
/// XPath. Only the delimiters of a well-formed `[@attr="value"]` are rewritten,
/// and only when the value cannot contain the canonical quote. Anything that
/// does not match that shape is left exactly as it was, so this can never
/// silently widen a root.
#[must_use]
pub fn canonicalize_xpath_quotes(xpath: &str) -> String {
    let bytes = xpath.as_bytes();
    let mut out = String::with_capacity(xpath.len());
    let mut index = 0;

    while index < bytes.len() {
        // Look for the start of an attribute predicate: `[@`
        if bytes[index] == b'['
            && bytes.get(index + 1) == Some(&b'@')
            && let Some((rewritten, consumed)) = rewrite_predicate(&xpath[index..])
        {
            out.push_str(&rewritten);
            index += consumed;
            continue;
        }
        // Push one character, respecting UTF-8 boundaries.
        let ch = xpath[index..].chars().next().unwrap_or('\0');
        out.push(ch);
        index += ch.len_utf8();
    }

    out
}

/// Rewrite one `[@attr="value"]` predicate, returning it and the bytes consumed.
///
/// Returns `None` when the text is not a complete, well-formed predicate whose
/// value can be represented in single quotes — in which case the caller leaves
/// the original untouched.
fn rewrite_predicate(rest: &str) -> Option<(String, usize)> {
    let after_at = &rest[2..];
    let equals = after_at.find('=')?;
    let attr = &after_at[..equals];
    if attr.is_empty()
        || !attr
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'))
    {
        return None;
    }

    let value_part = &after_at[equals + 1..];
    let quote = value_part.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }

    let value_start = quote.len_utf8();
    let value_end = value_part[value_start..].find(quote)? + value_start;
    let value = &value_part[value_start..value_end];

    // The closing bracket must come straight after the closing quote.
    let remainder = &value_part[value_end + quote.len_utf8()..];
    if !remainder.starts_with(']') {
        return None;
    }

    // A value containing an apostrophe cannot be re-emitted in single quotes
    // without escaping, which XPath 1.0 has no syntax for. Leave it alone.
    if value.contains('\'') {
        return None;
    }

    let consumed = 2 + equals + 1 + quote.len_utf8() + value.len() + quote.len_utf8() + 1;
    Some((format!("[@{attr}='{value}']"), consumed))
}

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
        // Compared after canonicalising quote style, so a grant written with
        // double quotes and a request written with single quotes match — they
        // are the same XPath (rustpanosmcp#82).
        let xpath = canonicalize_xpath_quotes(xpath);
        self.allowed_xpath_roots.iter().any(|root| {
            let root = canonicalize_xpath_quotes(root);
            xpath == root
                || xpath
                    .strip_prefix(&root)
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

#[cfg(test)]
mod xpath_quote_tests {
    use super::*;

    const VSYS_ADDRESS_DOUBLE: &str =
        r#"/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/address"#;
    const VSYS_ADDRESS_SINGLE: &str =
        "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address";

    fn grant(root: &str) -> MutationGrant {
        MutationGrant {
            allowed_xpath_roots: vec![root.to_owned()],
            actions: vec![MutationAction::Set],
        }
    }

    /// The defect from LXC 608: the grant and the request used different quote
    /// styles for the same path, so every write was refused (#82).
    #[test]
    fn quote_style_does_not_change_whether_a_path_is_granted() {
        for root in [VSYS_ADDRESS_DOUBLE, VSYS_ADDRESS_SINGLE] {
            for request in [VSYS_ADDRESS_DOUBLE, VSYS_ADDRESS_SINGLE] {
                assert!(
                    grant(root).allows_xpath(request),
                    "a grant written as\n  {root}\nmust accept the same path written as\n  {request}"
                );
            }
        }
    }

    #[test]
    fn descendants_are_still_granted_across_quote_styles() {
        let deeper = format!("{VSYS_ADDRESS_SINGLE}/entry[@name='web-01']");
        assert!(grant(VSYS_ADDRESS_DOUBLE).allows_xpath(&deeper));
    }

    /// Normalising must not widen a grant. A different path is still refused.
    #[test]
    fn an_unrelated_path_is_still_refused() {
        let interfaces =
            r#"/config/devices/entry[@name="localhost.localdomain"]/network/interface/ethernet"#;
        assert!(
            !grant(VSYS_ADDRESS_DOUBLE).allows_xpath(interfaces),
            "canonicalising quotes must not grant paths outside the root"
        );
    }

    /// A sibling whose name merely starts with the root's name must not match.
    #[test]
    fn a_prefix_of_a_longer_sibling_is_not_granted() {
        let root = "/config/devices/entry[@name='fw']/vsys";
        let sibling = "/config/devices/entry[@name='fw2']/vsys";
        assert!(!grant(root).allows_xpath(sibling));
    }

    /// A value containing an apostrophe cannot be re-emitted in single quotes —
    /// XPath 1.0 has no escape for it. A blind `"` to `'` swap would produce
    /// `[@name='O'Brien']`, which is broken. Such a predicate is left untouched.
    #[test]
    fn a_value_containing_an_apostrophe_is_not_mangled() {
        let awkward = r#"/config/devices/entry[@name="O'Brien"]/vsys"#;
        assert_eq!(
            canonicalize_xpath_quotes(awkward),
            awkward,
            "a value with an apostrophe must pass through unchanged"
        );
        assert!(grant(awkward).allows_xpath(awkward));
    }

    /// Anything that is not a complete, well-formed predicate is left alone, so
    /// canonicalisation can never invent a match.
    #[test]
    fn malformed_predicates_pass_through_unchanged() {
        for input in [
            "/config/devices/entry[@name=",
            "/config/devices/entry[@name='unterminated",
            "/config/devices/entry[@='empty-attr']",
            "/config/devices/entry[position()=1]",
        ] {
            assert_eq!(canonicalize_xpath_quotes(input), input, "input: {input}");
        }
    }
}

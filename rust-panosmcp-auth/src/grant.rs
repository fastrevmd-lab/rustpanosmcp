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

/// Whether every `/`-delimited step of `xpath` matches the one shape every
/// read/write/grant xpath check is allowed to accept: a bare name, or
/// `name[@attr='literal']`/`name[@attr="literal"]` with exactly one equality
/// predicate.
///
/// This exists because a naive prefix-and-character check (what
/// `validate_read_xpath`, `validate_write_xpath` and `allows_xpath` each did
/// independently before) accepts XPath axis syntax (`parent::`,
/// `ancestor::`, ...), a bare `.`/`..` step, and predicates that are not a
/// single attribute equality (an existence test `[@name]`, or a
/// cross-attribute compare). All of those pass a "starts with the granted
/// root, next char is `/`" test as plain text while addressing a different
/// node once an XPath engine evaluates the axis or predicate -- the string
/// looks like a descendant of the root, but is not one (MEC-528 F1). Calling
/// this from all three checks means they cannot disagree about what an
/// xpath addresses.
#[must_use]
pub fn is_strict_xpath_shape(xpath: &str) -> bool {
    if xpath.contains("::") {
        return false;
    }
    let Some(steps) = split_xpath_steps(xpath) else {
        return false;
    };
    steps.into_iter().skip(1).all(is_strict_xpath_step)
}

/// Split an xpath into steps on `/` only outside a quoted predicate value
/// (MEC-528 N1): PAN-OS interface names contain `/` (`ethernet1/1`,
/// `ethernet1/1.100`), so a plain `split('/')` cut the predicate in half and
/// rejected every interface xpath. `None` for an unterminated quote.
fn split_xpath_steps(xpath: &str) -> Option<Vec<&str>> {
    let mut steps = Vec::new();
    let mut start = 0;
    let mut quote: Option<u8> = None;
    for (index, byte) in xpath.bytes().enumerate() {
        match quote {
            Some(open) if byte == open => quote = None,
            Some(_) => {}
            None if byte == b'\'' || byte == b'"' => quote = Some(byte),
            None if byte == b'/' => {
                steps.push(&xpath[start..index]);
                start = index + 1;
            }
            None => {}
        }
    }
    if quote.is_some() {
        return None;
    }
    steps.push(&xpath[start..]);
    Some(steps)
}

fn is_strict_xpath_step(step: &str) -> bool {
    if step.is_empty() || step == "." || step == ".." {
        return false;
    }
    let (name, predicate) = match step.find('[') {
        Some(index) => (&step[..index], Some(&step[index..])),
        None => (step, None),
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }
    predicate.is_none_or(is_strict_xpath_predicate)
}

/// Whether `predicate` is exactly one `[@attr='literal']` (or `"..."`)
/// equality, with nothing before, inside, or after it that could change what
/// it matches.
fn is_strict_xpath_predicate(predicate: &str) -> bool {
    let Some(rest) = predicate.strip_prefix("[@") else {
        return false;
    };
    let Some(equals) = rest.find('=') else {
        return false;
    };
    let attr = &rest[..equals];
    if attr.is_empty()
        || !attr
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return false;
    }
    let value_part = &rest[equals + 1..];
    let Some(quote) = value_part.chars().next() else {
        return false;
    };
    if quote != '\'' && quote != '"' {
        return false;
    }
    let value_start = quote.len_utf8();
    let Some(relative_end) = value_part[value_start..].find(quote) else {
        return false;
    };
    let value_end = value_start + relative_end;
    let value = &value_part[value_start..value_end];
    if !value
        .bytes()
        .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && byte != b'\\')
    {
        return false;
    }
    &value_part[value_end + quote.len_utf8()..] == "]"
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
        // Reject axis syntax and non-equality predicates before comparing
        // roots at all: a text prefix match cannot see that `parent::`,
        // `[@name]`, or `[@a=@b]` address a different node than the
        // characters after the granted root suggest (MEC-528 F1).
        if !is_strict_xpath_shape(xpath) {
            return false;
        }
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
    /// Reorder an exact rulebase entry relative to a sibling, or to the top/bottom.
    Move,
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

    /// MEC-528 F1: axis syntax (including axes that move *up* the tree) must
    /// not let a granted write escape its root. Before `is_strict_xpath_shape`
    /// gated `allows_xpath`, this passed as "starts with the granted root,
    /// next char is `/`" even though an XPath engine evaluating `parent::`
    /// addresses a node the granted root does not cover.
    /// MEC-528 N1: a `/` inside a quoted predicate value is part of the
    /// value, not a step separator -- every PAN-OS interface name has one.
    #[test]
    fn interface_names_with_slashes_are_granted() {
        let root = "/config/devices/entry[@name='localhost.localdomain']/network/interface";
        for xpath in [
            format!("{root}/ethernet/entry[@name='ethernet1/1']"),
            format!(
                "{root}/ethernet/entry[@name='ethernet1/1']/layer3/units/entry[@name='ethernet1/1.100']"
            ),
        ] {
            assert!(is_strict_xpath_shape(&xpath), "must parse: {xpath}");
            assert!(grant(root).allows_xpath(&xpath), "must be granted: {xpath}");
        }
        // An unterminated quote is still refused, and a `/` does not hide an axis.
        assert!(!is_strict_xpath_shape(&format!(
            "{root}/ethernet/entry[@name='ethernet1/1]"
        )));
        assert!(!grant(root).allows_xpath(&format!(
            "{root}/ethernet/entry[@name='e1/1']/parent::node()"
        )));
    }

    #[test]
    fn axis_syntax_does_not_escape_the_granted_root() {
        let root = "/config/devices/entry[@name='fw']/vsys/entry[@name='vsys1']/address-book";
        for escape in [
            format!("{root}/entry[@name='x']/parent::node()/entry[@name='y']"),
            format!("{root}/entry[@name='x']/ancestor::config"),
            format!("{root}/following-sibling::vsys"),
        ] {
            assert!(
                !grant(root).allows_xpath(&escape),
                "axis syntax must not be granted: {escape}"
            );
        }
    }

    /// MEC-528 F1: a predicate that is not a single attribute equality --
    /// an existence test, or comparing one attribute to another -- matches
    /// every sibling under a step, which is broader than the one entry a
    /// grant's own predicate names.
    #[test]
    fn non_equality_predicates_do_not_widen_the_granted_root() {
        let root = "/config/devices/entry[@name='fw']/vsys/entry[@name='vsys1']/address-book";
        for candidate in [
            format!("{root}/entry[@name]"),
            format!("{root}/entry[@name=@other]"),
        ] {
            assert!(
                !grant(root).allows_xpath(&candidate),
                "a non-equality predicate must not be granted: {candidate}"
            );
        }
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

//! Known-CVE version-floor checks against a reported PAN-OS `sw-version`.
//!
//! This module only classifies an already-reported version string; it never
//! blocks a call or changes device state. Per the house rule, a model never
//! sees this as an action gate -- it is advisory text surfaced to a human.

/// A parsed PAN-OS release, ordered `(major, minor, maintenance, hotfix)` so
/// that derived [`Ord`] matches PAN-OS's own release ordering (a build with
/// no `-hN` suffix sorts before its first hotfix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PanosVersion {
    major: u32,
    minor: u32,
    maintenance: u32,
    hotfix: u32,
}

impl PanosVersion {
    /// Parse a `sw-version` string such as `10.2.18-h10` or `12.1.5`.
    ///
    /// Returns `None` for anything that is not exactly `major.minor.maintenance`
    /// with an optional `-hN` hotfix suffix -- this check only ever compares
    /// versions it is fully confident it parsed correctly.
    fn parse(raw: &str) -> Option<Self> {
        let (base, hotfix_suffix) = match raw.split_once('-') {
            Some((base, suffix)) => (base, Some(suffix)),
            None => (raw, None),
        };
        let mut parts = base.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let maintenance = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let hotfix = match hotfix_suffix {
            Some(suffix) => suffix.strip_prefix('h')?.parse().ok()?,
            None => 0,
        };
        Some(Self {
            major,
            minor,
            maintenance,
            hotfix,
        })
    }

    fn train(self) -> (u32, u32) {
        (self.major, self.minor)
    }
}

/// Minimum fixed release per release train for CVE-2026-0310.
///
/// Source: vendor advisory for CVE-2026-0310. Update this table (and
/// `docs/COMPATIBILITY.md`) when a new train ships a fix or an existing
/// fix level is superseded.
const CVE_2026_0310_FIX_LEVELS: &[((u32, u32), &str)] = &[
    ((10, 2), "10.2.18-h10"),
    ((11, 1), "11.1.16-h2"),
    ((11, 2), "11.2.13-h2"),
    ((12, 1), "12.1.10"),
    ((12, 2), "12.2.3"),
];

/// If `sw_version` is a recognized release train and is below the published
/// fix level for CVE-2026-0310, return a human-readable warning naming the
/// device's version, its train, and the required fix level.
///
/// Returns `None` when the version is at or above the fix level, or when the
/// version does not parse or belongs to a train with no published fix level
/// here -- silence in either of those cases means "nothing to warn about
/// from this table", not "confirmed safe".
#[must_use]
pub fn cve_2026_0310_warning(sw_version: &str) -> Option<String> {
    let parsed = PanosVersion::parse(sw_version)?;
    let (_, fix_level) = CVE_2026_0310_FIX_LEVELS
        .iter()
        .find(|(train, _)| *train == parsed.train())?;
    let fixed = PanosVersion::parse(fix_level).expect("built-in fix levels parse");
    if parsed < fixed {
        Some(format!(
            "PAN-OS {sw_version} on the {}.{} train is below {fix_level}, the fix level for \
             CVE-2026-0310; upgrade to {fix_level} or later.",
            parsed.major, parsed.minor
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_floor_on_each_known_train_warns() {
        let cases = [
            ("10.2.18-h9", "10.2.18-h10"),
            ("10.2.17", "10.2.18-h10"),
            ("11.1.16-h1", "11.1.16-h2"),
            ("11.1.15", "11.1.16-h2"),
            ("11.2.13-h1", "11.2.13-h2"),
            ("12.1.9", "12.1.10"),
            ("12.2.2", "12.2.3"),
        ];
        for (version, fix_level) in cases {
            let warning = cve_2026_0310_warning(version)
                .unwrap_or_else(|| panic!("expected a warning for {version}"));
            assert!(warning.contains(version), "warning: {warning}");
            assert!(warning.contains(fix_level), "warning: {warning}");
            assert!(warning.contains("CVE-2026-0310"), "warning: {warning}");
        }
    }

    #[test]
    fn at_or_above_floor_on_each_known_train_is_silent() {
        let cases = [
            "10.2.18-h10",
            "10.2.18-h11",
            "10.2.19",
            "11.1.16-h2",
            "11.2.13-h2",
            "12.1.10",
            "12.1.11",
            "12.2.3",
            "12.2.4",
        ];
        for version in cases {
            assert_eq!(
                cve_2026_0310_warning(version),
                None,
                "unexpected warning for {version}"
            );
        }
    }

    #[test]
    fn train_with_no_published_fix_level_is_silent() {
        // 10.1 and 11.0 are no longer supported trains and have no row here;
        // an unrecognized train should never produce a false "fixed" claim.
        assert_eq!(cve_2026_0310_warning("10.1.14-h4"), None);
        assert_eq!(cve_2026_0310_warning("11.0.5"), None);
        assert_eq!(cve_2026_0310_warning("9.1.20"), None);
    }

    #[test]
    fn unparseable_version_is_silent_not_a_panic() {
        assert_eq!(cve_2026_0310_warning(""), None);
        assert_eq!(cve_2026_0310_warning("unknown"), None);
        assert_eq!(cve_2026_0310_warning("10.2"), None);
        assert_eq!(cve_2026_0310_warning("10.2.18-hfoo"), None);
        assert_eq!(cve_2026_0310_warning("10.2.18.1"), None);
    }

    #[test]
    fn hotfix_ordering_is_numeric_not_lexicographic() {
        // h9 < h10 numerically; a naive string compare would get this backwards.
        assert!(cve_2026_0310_warning("10.2.18-h9").is_some());
        assert!(cve_2026_0310_warning("10.2.18-h10").is_none());
    }
}

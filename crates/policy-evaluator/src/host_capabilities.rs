use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

use crate::errors::HostCapabilitiesPatternError;

/// Represents the set of host capabilities a policy is allowed to use.
///
/// Host capability paths follow the format `{namespace}/{operation}`, e.g.
/// `oci/v1/verify`, `net/v1/dns_lookup_host`, `kubernetes/can_i`.
///
/// Supported patterns:
/// - `*`: allow all capabilities
/// - `oci/*`: allow all OCI capabilities regardless of version
/// - `oci/v2/*`: allow all OCI v2 capabilities
/// - `oci/v1/verify`: allow only the exact capability
///
/// Invalid patterns (rejected at parse time):
/// - `oci*`: wildcard must follow a `/`
/// - `oci/v1/oci_*`: wildcard must be the entire last segment
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub enum HostCapabilities {
    /// Deny all host capabilities (empty pattern list).
    #[default]
    DenyAll,
    /// Allow all host capabilities (the `*` pattern was specified).
    AllowAll,
    /// Allow specific capabilities matched by prefix or exact patterns.
    Patterns {
        /// Prefix patterns (e.g., `oci/` from `oci/*`, `oci/v2/` from `oci/v2/*`)
        prefixes: HashSet<String>,
        /// Exact capability paths (e.g., `oci/v1/verify`)
        exact: HashSet<String>,
    },
}

impl HostCapabilities {
    /// Creates a new allow list from a list of patterns.
    ///
    /// Returns an error if any pattern is invalid.
    pub fn new(
        patterns: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, HostCapabilitiesPatternError> {
        let mut prefixes = HashSet::new();
        let mut exact = HashSet::new();

        for pattern in patterns {
            let pattern = pattern.as_ref();
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                return Err(HostCapabilitiesPatternError::Empty);
            }

            if trimmed == "*" {
                return Ok(Self::AllowAll);
            }

            if let Some(pos) = trimmed.find('*') {
                // Wildcard must be at the end and preceded by '/'
                if pos != trimmed.len() - 1 || !trimmed[..pos].ends_with('/') {
                    return Err(HostCapabilitiesPatternError::InvalidWildcard {
                        pattern: pattern.to_string(),
                    });
                }
                // Store the prefix including trailing '/'
                prefixes.insert(trimmed[..pos].to_string());
            } else {
                exact.insert(trimmed.to_string());
            }
        }

        if prefixes.is_empty() && exact.is_empty() {
            return Ok(Self::DenyAll);
        }

        Ok(Self::Patterns { prefixes, exact })
    }

    /// Creates an allow list that allows all capabilities (`*`).
    pub fn allow_all() -> Self {
        Self::AllowAll
    }

    /// Creates an allow list that denies all capabilities (empty list).
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Returns `true` if the given capability path is allowed by this allow list.
    ///
    /// The capability path is constructed as `{namespace}/{operation}`, matching
    /// the waPC host callback namespace and operation parameters.
    pub fn is_allowed(&self, capability_path: &str) -> bool {
        match self {
            Self::AllowAll => true,
            Self::DenyAll => false,
            Self::Patterns { exact, prefixes } => {
                exact.contains(capability_path)
                    || prefixes
                        .iter()
                        .any(|p| capability_path.starts_with(p.as_str()))
            }
        }
    }
}

impl TryFrom<Vec<String>> for HostCapabilities {
    type Error = HostCapabilitiesPatternError;

    fn try_from(patterns: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(patterns)
    }
}

impl From<HostCapabilities> for Vec<String> {
    fn from(allow_list: HostCapabilities) -> Self {
        match allow_list {
            HostCapabilities::AllowAll => vec!["*".to_string()],
            HostCapabilities::DenyAll => vec![],
            HostCapabilities::Patterns { prefixes, exact } => {
                let mut result: Vec<String> =
                    prefixes.into_iter().map(|p| format!("{p}*")).collect();
                result.sort();
                let mut exact_sorted: Vec<String> = exact.into_iter().collect();
                exact_sorted.sort();
                result.extend(exact_sorted);
                result
            }
        }
    }
}

impl fmt::Display for HostCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowAll => write!(f, "[*]"),
            Self::DenyAll => write!(f, "[]"),
            Self::Patterns { prefixes, exact } => {
                let mut items: Vec<String> = prefixes.iter().map(|p| format!("{p}*")).collect();
                items.sort();
                let mut exact_sorted: Vec<&String> = exact.iter().collect();
                exact_sorted.sort();
                items.extend(exact_sorted.into_iter().cloned());
                write!(f, "[{}]", items.join(", "))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::empty_allows_nothing(vec![], "oci/v1/verify", false)]
    #[case::wildcard_allows_all(vec!["*"], "oci/v1/verify", true)]
    #[case::wildcard_allows_all_2(vec!["*"], "kubernetes/can_i", true)]
    #[case::exact_match(vec!["oci/v1/verify"], "oci/v1/verify", true)]
    #[case::exact_no_match(vec!["oci/v1/verify"], "oci/v2/verify", false)]
    #[case::prefix_oci(vec!["oci/*"], "oci/v1/verify", true)]
    #[case::prefix_oci_v2(vec!["oci/*"], "oci/v2/verify", true)]
    #[case::prefix_oci_manifest(vec!["oci/*"], "oci/v1/manifest_digest", true)]
    #[case::prefix_no_match(vec!["oci/*"], "net/v1/dns_lookup_host", false)]
    #[case::prefix_versioned(vec!["oci/v2/*"], "oci/v2/verify", true)]
    #[case::prefix_versioned_no_match(vec!["oci/v2/*"], "oci/v1/verify", false)]
    #[case::multiple_patterns(
        vec!["oci/v1/verify", "net/v1/dns_lookup_host"],
        "oci/v1/verify",
        true
    )]
    #[case::multiple_patterns_second(
        vec!["oci/v1/verify", "net/v1/dns_lookup_host"],
        "net/v1/dns_lookup_host",
        true
    )]
    #[case::multiple_patterns_no_match(
        vec!["oci/v1/verify", "net/v1/dns_lookup_host"],
        "kubernetes/can_i",
        false
    )]
    #[case::mixed_prefix_and_exact(
        vec!["oci/*", "kubernetes/can_i"],
        "oci/v1/manifest_digest",
        true
    )]
    #[case::mixed_prefix_and_exact_2(
        vec!["oci/*", "kubernetes/can_i"],
        "kubernetes/can_i",
        true
    )]
    #[case::mixed_no_match(
        vec!["oci/*", "kubernetes/can_i"],
        "net/v1/dns_lookup_host",
        false
    )]
    fn is_capability_allowed(
        #[case] patterns: Vec<&str>,
        #[case] capability: &str,
        #[case] expected: bool,
    ) {
        let allow_list = HostCapabilities::new(patterns).expect("patterns should be valid");
        assert_eq!(
            allow_list.is_allowed(capability),
            expected,
            "capability={capability}"
        );
    }

    #[rstest]
    #[case::partial_wildcard("oci*")]
    #[case::mid_wildcard("oci/v1/oci_*")]
    #[case::wildcard_not_last("*/oci")]
    fn invalid_patterns(#[case] pattern: &str) {
        let result = HostCapabilities::new(vec![pattern.to_string()]);
        assert!(result.is_err(), "pattern {pattern:?} should be invalid");
    }

    #[test]
    fn empty_pattern_is_invalid() {
        let result = HostCapabilities::new(vec!["".to_string()]);
        assert!(result.is_err());
    }

    #[rstest]
    #[case::standalone(vec!["*"])]
    #[case::wildcard_with_others(vec!["*", "oci/*", "kubernetes/can_i"])]
    fn wildcard_parses_to_allow_all(#[case] patterns: Vec<&str>) {
        let result = HostCapabilities::new(patterns);
        assert_eq!(result.unwrap(), HostCapabilities::AllowAll);
    }

    #[test]
    fn valid_patterns_parse() {
        let patterns = vec![
            "oci/*".to_string(),
            "oci/v2/*".to_string(),
            "oci/v1/verify".to_string(),
            "kubernetes/can_i".to_string(),
        ];
        let result = HostCapabilities::new(patterns);
        assert!(result.is_ok());
    }

    #[test]
    fn constructors_produce_correct_variants() {
        assert_eq!(HostCapabilities::deny_all(), HostCapabilities::DenyAll);
        assert_eq!(HostCapabilities::allow_all(), HostCapabilities::AllowAll);
    }

    #[test]
    fn deny_all_denies_all() {
        let allow_list = HostCapabilities::deny_all();
        assert!(!allow_list.is_allowed("oci/v1/verify"));
        assert!(!allow_list.is_allowed("kubernetes/can_i"));
    }

    #[test]
    fn serde_roundtrip() {
        let patterns = vec!["oci/*".to_string(), "kubernetes/can_i".to_string()];
        let allow_list = HostCapabilities::new(patterns.clone()).unwrap();
        let json = serde_json::to_string(&allow_list).unwrap();
        let deserialized: HostCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(allow_list, deserialized);
    }

    #[test]
    fn display() {
        let allow_list = HostCapabilities::new(["*"]).unwrap();
        assert_eq!(allow_list.to_string(), "[*]");

        let allow_list = HostCapabilities::deny_all();
        assert_eq!(allow_list.to_string(), "[]");

        let allow_list = HostCapabilities::new(["oci/*", "kubernetes/can_i"]).unwrap();
        assert_eq!(allow_list.to_string(), "[oci/*, kubernetes/can_i]");
    }
}

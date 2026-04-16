use serde::{Deserialize, Serialize};
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
pub struct HostCapabilitiesAllowList {
    /// When true, all capabilities are allowed (the `*` pattern was specified)
    allow_all: bool,
    /// Prefix patterns (e.g., `oci/` from `oci/*`, `oci/v2/` from `oci/v2/*`)
    prefixes: Vec<String>,
    /// Exact capability paths (e.g., `oci/v1/verify`)
    exact: Vec<String>,
}

impl HostCapabilitiesAllowList {
    /// Creates a new allow list from a list of patterns.
    ///
    /// Returns an error if any pattern is invalid.
    pub fn new(patterns: Vec<String>) -> Result<Self, HostCapabilitiesPatternError> {
        let mut allow_all = false;
        let mut prefixes = Vec::new();
        let mut exact = Vec::new();

        for pattern in &patterns {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                return Err(HostCapabilitiesPatternError::Empty {
                    pattern: pattern.clone(),
                });
            }

            if trimmed == "*" {
                allow_all = true;
                continue; // check for invalid patterns
            }

            if let Some(pos) = trimmed.find('*') {
                // Wildcard must be at the end and preceded by '/'
                if pos != trimmed.len() - 1 || !trimmed[..pos].ends_with('/') {
                    return Err(HostCapabilitiesPatternError::InvalidWildcard {
                        pattern: pattern.clone(),
                    });
                }
                // Store the prefix including trailing '/'
                prefixes.push(trimmed[..pos].to_string());
            } else {
                exact.push(trimmed.to_string());
            }
        }

        Ok(Self {
            allow_all,
            prefixes,
            exact,
        })
    }

    /// Creates an allow list that allows all capabilities (`*`).
    pub fn allow_all() -> Self {
        HostCapabilitiesAllowList::new(vec!["*".to_string()]).unwrap()
    }

    /// Creates an allow list that denies all capabilities (empty list).
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Returns `true` if the given capability path is allowed by this allow list.
    ///
    /// The capability path is constructed as `{namespace}/{operation}`, matching
    /// the waPC host callback namespace and operation parameters.
    pub fn is_capability_allowed(&self, capability_path: &str) -> bool {
        if self.allow_all {
            return true;
        }

        if self.exact.iter().any(|e| e == capability_path) {
            return true;
        }

        if self
            .prefixes
            .iter()
            .any(|p| capability_path.starts_with(p.as_str()))
        {
            return true;
        }

        false
    }
}

impl TryFrom<Vec<String>> for HostCapabilitiesAllowList {
    type Error = HostCapabilitiesPatternError;

    fn try_from(patterns: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(patterns)
    }
}

impl<'a> TryFrom<Vec<&'a str>> for HostCapabilitiesAllowList {
    type Error = HostCapabilitiesPatternError;

    fn try_from(patterns: Vec<&'a str>) -> Result<Self, Self::Error> {
        Self::new(patterns.into_iter().map(String::from).collect())
    }
}

impl From<HostCapabilitiesAllowList> for Vec<String> {
    fn from(allow_list: HostCapabilitiesAllowList) -> Self {
        let mut result = Vec::new();
        if allow_list.allow_all {
            result.push("*".to_string());
        }
        for prefix in allow_list.prefixes {
            result.push(format!("{prefix}*"));
        }
        result.extend(allow_list.exact);
        result
    }
}

impl fmt::Display for HostCapabilitiesAllowList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allow_all {
            return write!(f, "[*]");
        }
        let items: Vec<String> = self.clone().into();
        if items.is_empty() {
            write!(f, "[]")
        } else {
            write!(f, "[{}]", items.join(", "))
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
        let allow_list =
            HostCapabilitiesAllowList::try_from(patterns).expect("patterns should be valid");
        assert_eq!(
            allow_list.is_capability_allowed(capability),
            expected,
            "capability={capability}"
        );
    }

    #[rstest]
    #[case::partial_wildcard("oci*")]
    #[case::mid_wildcard("oci/v1/oci_*")]
    #[case::wildcard_not_last("*/oci")]
    fn invalid_patterns(#[case] pattern: &str) {
        let result = HostCapabilitiesAllowList::new(vec![pattern.to_string()]);
        assert!(result.is_err(), "pattern {pattern:?} should be invalid");
    }

    #[test]
    fn empty_pattern_is_invalid() {
        let result = HostCapabilitiesAllowList::new(vec!["".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn valid_patterns_parse() {
        let patterns = vec![
            "*".to_string(),
            "oci/*".to_string(),
            "oci/v2/*".to_string(),
            "oci/v1/verify".to_string(),
            "kubernetes/can_i".to_string(),
        ];
        let result = HostCapabilitiesAllowList::new(patterns);
        assert!(result.is_ok());
    }

    #[test]
    fn default_denies_all() {
        let allow_list = HostCapabilitiesAllowList::default();
        assert!(!allow_list.is_capability_allowed("oci/v1/verify"));
        assert!(!allow_list.is_capability_allowed("kubernetes/can_i"));
    }

    #[test]
    fn serde_roundtrip() {
        let patterns = vec!["oci/*".to_string(), "kubernetes/can_i".to_string()];
        let allow_list = HostCapabilitiesAllowList::new(patterns.clone()).unwrap();
        let json = serde_json::to_string(&allow_list).unwrap();
        let deserialized: HostCapabilitiesAllowList = serde_json::from_str(&json).unwrap();
        assert_eq!(allow_list, deserialized);
    }

    #[test]
    fn display() {
        let allow_list = HostCapabilitiesAllowList::new(vec!["*".into()]).unwrap();
        assert_eq!(allow_list.to_string(), "[*]");

        let allow_list = HostCapabilitiesAllowList::default();
        assert_eq!(allow_list.to_string(), "[]");

        let allow_list =
            HostCapabilitiesAllowList::new(vec!["oci/*".into(), "kubernetes/can_i".into()])
                .unwrap();
        assert_eq!(allow_list.to_string(), "[oci/*, kubernetes/can_i]");
    }
}

use anyhow::Result;

use serde::Deserialize;
use serde_yaml::Value;
use std::collections::HashMap;

use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Debug, Clone)]
pub enum PolicyMode {
    #[serde(rename = "monitor")]
    Monitor,
    #[serde(rename = "protect")]
    Protect,
}

impl Default for PolicyMode {
    fn default() -> PolicyMode {
        PolicyMode::Protect
    }
}

impl From<PolicyMode> for String {
    fn from(policy_mode: PolicyMode) -> String {
        match policy_mode {
            PolicyMode::Monitor => String::from("monitor"),
            PolicyMode::Protect => String::from("protect"),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Policy {
    pub url: String,
    #[serde(default, rename = "policyMode")]
    pub policy_mode: PolicyMode,
    #[serde(rename = "allowedToMutate")]
    pub allowed_to_mutate: Option<bool>,
    #[serde(skip)]
    pub wasm_module_path: Option<PathBuf>,
    #[serde(default)]
    pub settings: Option<HashMap<String, Value>>,
}

// Reads the policies configuration file, returns a HashMap with String as value
// and Policy as values. The key is the name of the policy as provided by the user
// inside of the configuration file. This name is used to build the API path
// exposing the policy.
pub fn read_policies_file(path: &Path) -> Result<HashMap<String, Policy>> {
    let settings_file = File::open(path)?;
    let ps: HashMap<String, Policy> = serde_yaml::from_reader(&settings_file)?;
    Ok(ps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_settings_when_data_is_provided() {
        let input = r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings:
    valid_namespace: valid
"#;
        let policies: HashMap<String, Policy> = serde_yaml::from_str(input).unwrap();
        assert!(!policies.is_empty());

        let policy = policies.get("example").unwrap();
        assert!(policy.allowed_to_mutate.is_none());
        assert!(policy.settings.is_some());
    }

    #[test]
    fn test_allowed_to_mutate_settings() {
        let input = r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  allowedToMutate: true
  settings:
    valid_namespace: valid
"#;
        let policies: HashMap<String, Policy> = serde_yaml::from_str(input).unwrap();
        assert!(!policies.is_empty());

        let policy = policies.get("example").unwrap();
        assert!(policy.allowed_to_mutate.unwrap());
        assert!(policy.settings.is_some());

        let input2 = r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  allowedToMutate: false
  settings:
    valid_namespace: valid
"#;
        let policies2: HashMap<String, Policy> = serde_yaml::from_str(input2).unwrap();
        assert!(!policies2.is_empty());

        let policy2 = policies2.get("example").unwrap();
        assert_eq!(policy2.allowed_to_mutate.unwrap(), false);
        assert!(policy2.settings.is_some());
    }

    #[test]
    fn get_settings_when_empty_map_is_provided() {
        let input = r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#;

        let policies: HashMap<String, Policy> = serde_yaml::from_str(input).unwrap();
        assert!(!policies.is_empty());

        let policy = policies.get("example").unwrap();
        assert!(policy.settings.is_some());
    }

    #[test]
    fn get_settings_when_no_settings_are_provided() {
        let input = r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
"#;

        let policies: HashMap<String, Policy> = serde_yaml::from_str(input).unwrap();
        assert!(!policies.is_empty());

        let policy = policies.get("example").unwrap();
        assert!(policy.settings.is_none());
    }

    #[test]
    fn get_settings_when_settings_is_null() {
        let input = r#"
{
    "privileged-pods": {
        "url": "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5",
        "settings": null
    }
}
"#;

        let policies: HashMap<String, Policy> = serde_yaml::from_str(input).unwrap();
        assert!(!policies.is_empty());

        let policy = policies.get("privileged-pods").unwrap();
        assert!(policy.settings.is_none());
    }
}

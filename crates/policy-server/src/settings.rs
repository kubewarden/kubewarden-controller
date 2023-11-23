use anyhow::{anyhow, Result};

use policy_evaluator::policy_metadata::ContextAwareResource;
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::iter::FromIterator;
use std::path::Path;

#[derive(Deserialize, Debug, Clone, Default)]
pub enum PolicyMode {
    #[serde(rename = "monitor")]
    Monitor,
    #[serde(rename = "protect")]
    #[default]
    Protect,
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
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub url: String,
    #[serde(default)]
    pub policy_mode: PolicyMode,
    pub allowed_to_mutate: Option<bool>,
    pub settings: Option<HashMap<String, Value>>,
    #[serde(default)]
    pub context_aware_resources: BTreeSet<ContextAwareResource>,
}

impl Policy {
    pub fn settings_to_json(&self) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
        match self.settings.as_ref() {
            None => Ok(None),
            Some(settings) => {
                let settings =
                    serde_yaml::Mapping::from_iter(settings.iter().map(|(key, value)| {
                        (serde_yaml::Value::String(key.to_string()), value.clone())
                    }));
                Ok(Some(convert_yaml_map_to_json(settings).map_err(|e| {
                    anyhow!("cannot convert YAML settings to JSON: {:?}", e)
                })?))
            }
        }
    }
}

/// Helper function that takes a YAML map and returns a
/// JSON object.
fn convert_yaml_map_to_json(
    yml_map: serde_yaml::Mapping,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    // convert the policy settings from yaml format to json
    let yml_string = serde_yaml::to_string(&yml_map).map_err(|e| {
        anyhow!(
            "error while converting {:?} from yaml to string: {}",
            yml_map,
            e
        )
    })?;

    let v: serde_json::Value = serde_yaml::from_str(&yml_string).map_err(|e| {
        anyhow!(
            "error while converting {:?} from yaml string to json: {}",
            yml_map,
            e
        )
    })?;

    Ok(v.as_object()
        .map_or_else(serde_json::Map::<String, serde_json::Value>::new, |m| {
            m.clone()
        }))
}

/// Reads the policies configuration file, returns a HashMap with String as value
/// and Policy as values. The key is the name of the policy as provided by the user
/// inside of the configuration file. This name is used to build the API path
/// exposing the policy.
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
        assert!(!policy2.allowed_to_mutate.unwrap());
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

    #[test]
    fn handle_yaml_map_with_data() {
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
        let json_data = convert_yaml_map_to_json(serde_yaml::Mapping::from_iter(
            policy
                .settings
                .as_ref()
                .unwrap()
                .iter()
                .map(|(key, value)| (serde_yaml::Value::String(key.clone()), value.clone())),
        ));
        assert!(json_data.is_ok());

        let settings = json_data.unwrap();
        assert_eq!(settings.get("valid_namespace").unwrap(), "valid");
    }

    #[test]
    fn handle_yaml_map_with_no_data() {
        let input = r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#;
        let policies: HashMap<String, Policy> = serde_yaml::from_str(input).unwrap();
        assert!(!policies.is_empty());

        let policy = policies.get("example").unwrap();
        let json_data = convert_yaml_map_to_json(serde_yaml::Mapping::from_iter(
            policy
                .settings
                .as_ref()
                .unwrap()
                .iter()
                .map(|(key, value)| (serde_yaml::Value::String(key.clone()), value.clone())),
        ));
        assert!(json_data.is_ok());

        let settings = json_data.unwrap();
        assert!(settings.is_empty());
    }
}

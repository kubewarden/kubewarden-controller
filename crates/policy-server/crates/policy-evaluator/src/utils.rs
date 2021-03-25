use anyhow::{anyhow, Result};

// Helper function that takes a YAML map and returns a
// JSON object.
pub(crate) fn convert_yaml_map_to_json(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use std::collections::HashMap;

    #[test]
    fn handle_yaml_map_with_data() {
        let input = r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings:
    valid_namespace: valid
"#;
        let policies: HashMap<String, Policy> = serde_yaml::from_str(&input).unwrap();
        assert_eq!(policies.is_empty(), false);

        let policy = policies.get("example").unwrap();
        let json_data = convert_yaml_map_to_json(policy.settings());
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
        let policies: HashMap<String, Policy> = serde_yaml::from_str(&input).unwrap();
        assert_eq!(policies.is_empty(), false);

        let policy = policies.get("example").unwrap();
        let json_data = convert_yaml_map_to_json(policy.settings());
        assert!(json_data.is_ok());

        let settings = json_data.unwrap();
        assert!(settings.is_empty());
    }
}

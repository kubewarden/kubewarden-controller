use anyhow::Result;
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use validator::{Validate, ValidationError};

#[derive(Deserialize, Serialize, Debug, Clone, Hash, Eq, PartialEq)]
pub enum Operation {
    #[serde(rename = "CREATE")]
    Create,
    #[serde(rename = "UPDATE")]
    Update,
    #[serde(rename = "DELETE")]
    Delete,
    #[serde(rename = "CONNECT")]
    Connect,
    #[serde(rename = "*")]
    All,
}

#[derive(Deserialize, Serialize, Debug, Clone, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[validate(length(min = 1), custom = "validate_asterisk_usage")]
    pub api_groups: Vec<String>,
    #[validate(length(min = 1), custom = "validate_asterisk_usage")]
    pub api_versions: Vec<String>,
    #[validate(length(min = 1), custom = "validate_resources")]
    pub resources: Vec<String>,
    #[validate(
        length(min = 1),
        custom = "validate_asterisk_usage_inside_of_operations"
    )]
    pub operations: Vec<Operation>,
}

fn validate_asterisk_usage(data: &[String]) -> Result<(), ValidationError> {
    if data.contains(&String::from("*")) && data.len() > 1 {
        return Err(ValidationError::new(
            "No other elements can be defined when '*' is used",
        ));
    }
    Ok(())
}

fn validate_asterisk_usage_inside_of_operations(data: &[Operation]) -> Result<(), ValidationError> {
    if data.contains(&Operation::All) && data.len() > 1 {
        return Err(ValidationError::new(
            "No other elements can be defined when '*' is used",
        ));
    }
    Ok(())
}

fn validate_resources(data: &[String]) -> Result<(), ValidationError> {
    // This method is a transposition of the check done by Kubernetes
    // see https://github.com/kubernetes/kubernetes/blob/09268c16853b233ebaedcd6a877eac23690b5190/pkg/apis/admissionregistration/validation/validation.go#L44

    // */x
    let mut resources_with_wildcard_subresources: HashSet<String> = HashSet::new();
    // x/*
    let mut subresources_with_wildcard_resource: HashSet<String> = HashSet::new();
    // */*
    let mut has_double_wildcard = false;
    // *
    let mut has_single_wildcard = false;
    // x
    let mut has_resource_without_subresource = false;

    for resource in data.iter() {
        if resource.is_empty() {
            return Err(ValidationError::new("empty resource is not allowed"));
        }
        match resource.as_str() {
            "*/*" => has_double_wildcard = true,
            "*" => has_single_wildcard = true,
            _ => {}
        };

        let parts: Vec<&str> = resource.splitn(2, '/').collect();
        if parts.len() == 1 {
            has_resource_without_subresource = resource.as_str() != "*";
            continue;
        }
        let res = parts[0];
        let sub = parts[1];

        if resources_with_wildcard_subresources.contains(res) {
            let msg = format!("if '{}/*' is present, must not specify {}", resource, res);
            return Err(ValidationError::new(Box::leak(msg.into_boxed_str())));
        }
        if subresources_with_wildcard_resource.contains(sub) {
            let msg = format!("if '*/{}' is present, must not specify {}", sub, resource);
            return Err(ValidationError::new(Box::leak(msg.into_boxed_str())));
        }
        if sub == "*" {
            resources_with_wildcard_subresources.insert(String::from(res));
        }
        if res == "*" {
            subresources_with_wildcard_resource.insert(String::from(sub));
        }
    }
    if data.len() > 1 && has_double_wildcard {
        return Err(ValidationError::new(
            "if '*/*' is present, must not specify other resources",
        ));
    }
    if has_single_wildcard && has_resource_without_subresource {
        return Err(ValidationError::new(
            "if '*' is present, must not specify other resources without subresources",
        ));
    }

    Ok(())
}

#[derive(Deserialize, Serialize, Debug, Clone, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    #[validate(required, custom = "validate_protocol_version")]
    pub protocol_version: Option<ProtocolVersion>,
    #[validate]
    pub rules: Vec<Rule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    pub mutating: bool,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            protocol_version: None,
            rules: vec![],
            labels: Some(HashMap::new()),
            mutating: false,
        }
    }
}

fn validate_protocol_version(protocol: &ProtocolVersion) -> Result<(), ValidationError> {
    match protocol {
        ProtocolVersion::Unknown => Err(ValidationError::new(
            "Must specifify a valid protocol version",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    #[test]
    fn metadata_validation_pass() -> Result<(), ()> {
        let pod_rule = Rule {
            api_groups: vec![String::from("")],
            api_versions: vec![String::from("v1")],
            resources: vec![String::from("pods")],
            operations: vec![Operation::Create],
        };
        let metadata = Metadata {
            protocol_version: Some(ProtocolVersion::V1),
            rules: vec![pod_rule],
            labels: None,
            mutating: false,
        };
        assert!(metadata.validate().is_ok());

        Ok(())
    }

    #[test]
    fn metadata_validation_failure() -> Result<(), ()> {
        // fail because api_groups has both '*' and another value
        let mut pod_rule = Rule {
            api_groups: vec![String::from(""), String::from("*")],
            api_versions: vec![String::from("v1")],
            resources: vec![String::from("pods")],
            operations: vec![Operation::Create],
        };
        let protocol_version = Some(ProtocolVersion::V1);

        let mut metadata = Metadata {
            protocol_version,
            labels: None,
            rules: vec![pod_rule],
            mutating: false,
        };
        assert!(metadata.validate().is_err());

        // fail because api_group is empty
        pod_rule = Rule {
            api_groups: vec![],
            api_versions: vec![String::from("v1")],
            resources: vec![String::from("pods")],
            operations: vec![Operation::Create],
        };
        metadata.rules = vec![pod_rule];
        assert!(metadata.validate().is_err());

        // fail because operations has both '*' and another value
        pod_rule = Rule {
            api_groups: vec![String::from("")],
            api_versions: vec![String::from("v1")],
            resources: vec![String::from("pods")],
            operations: vec![Operation::All, Operation::Create],
        };
        metadata.rules = vec![pod_rule];
        assert!(metadata.validate().is_err());

        // faile because there's no valid protocol version defined
        pod_rule = Rule {
            api_groups: vec![String::from("")],
            api_versions: vec![String::from("v1")],
            resources: vec![String::from("pods")],
            operations: vec![Operation::Create],
        };
        metadata = Metadata {
            rules: vec![pod_rule],
            labels: None,
            ..Default::default()
        };
        assert!(metadata.validate().is_err());

        pod_rule = Rule {
            api_groups: vec![String::from("")],
            api_versions: vec![String::from("v1")],
            resources: vec![String::from("pods")],
            operations: vec![Operation::Create],
        };
        metadata = Metadata {
            rules: vec![pod_rule],
            labels: None,
            protocol_version: None,
            mutating: false,
        };
        assert!(metadata.validate().is_err());

        Ok(())
    }

    #[test]
    fn metadata_without_rules() -> Result<(), ()> {
        let metadata = Metadata {
            rules: vec![],
            protocol_version: Some(ProtocolVersion::V1),
            labels: None,
            mutating: false,
        };

        let expected = json!({
            "protocolVersion": "v1",
            "rules": [ ],
            "mutating": false
        });

        let actual = serde_json::to_value(&metadata).unwrap();
        assert_json_eq!(expected, actual);
        Ok(())
    }

    #[test]
    fn metadata_init() -> Result<(), ()> {
        let pod_rule = Rule {
            api_groups: vec![String::from("")],
            api_versions: vec![String::from("v1")],
            resources: vec![String::from("pods")],
            operations: vec![Operation::Create],
        };
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(String::from("author"), String::from("Flavio Castelli"));

        let metadata = Metadata {
            labels: Some(labels),
            protocol_version: Some(ProtocolVersion::V1),
            rules: vec![pod_rule],
            mutating: false,
        };

        let expected = json!(
        {
            "protocolVersion": "v1",
            "rules": [
                {
                    "apiGroups":[""],
                    "apiVersions":["v1"],
                    "resources":["pods"],
                    "operations":["CREATE"]
                }
            ],
            "labels": {
                "author": "Flavio Castelli"
            },
            "mutating": false
        });

        let actual = serde_json::to_value(&metadata).unwrap();
        assert_json_eq!(expected, actual);
        Ok(())
    }

    #[test]
    fn validate_resource_asterisk_can_coexist_with_resources_that_have_subresources(
    ) -> Result<(), ()> {
        let pod_rule = Rule {
            api_groups: vec![String::from("a")],
            api_versions: vec![String::from("a")],
            resources: vec![
                String::from("*"),
                String::from("a/b"),
                String::from("a/*"),
                String::from("*/b"),
            ],
            operations: vec![Operation::Create],
        };
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(String::from("author"), String::from("Flavio Castelli"));

        let metadata = Metadata {
            labels: Some(labels),
            protocol_version: Some(ProtocolVersion::V1),
            rules: vec![pod_rule],
            mutating: false,
        };

        assert!(metadata.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_resource_asterisk_cannot_mix_with_resources_that_do_not_have_subresources(
    ) -> Result<(), ()> {
        let pod_rule = Rule {
            api_groups: vec![String::from("a")],
            api_versions: vec![String::from("a")],
            resources: vec![String::from("*"), String::from("a")],
            operations: vec![Operation::Create],
        };
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(String::from("author"), String::from("Flavio Castelli"));

        let metadata = Metadata {
            labels: Some(labels),
            protocol_version: Some(ProtocolVersion::V1),
            rules: vec![pod_rule],
            mutating: false,
        };

        assert!(metadata.validate().is_err());
        Ok(())
    }

    #[test]
    fn validate_resource_foo_slash_asterisk_subresource_cannot_mix_with_foo_slash_bar(
    ) -> Result<(), ()> {
        let pod_rule = Rule {
            api_groups: vec![String::from("a")],
            api_versions: vec![String::from("a")],
            resources: vec![String::from("a/*"), String::from("a/x")],
            operations: vec![Operation::Create],
        };
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(String::from("author"), String::from("Flavio Castelli"));

        let metadata = Metadata {
            labels: Some(labels),
            protocol_version: Some(ProtocolVersion::V1),
            rules: vec![pod_rule],
            mutating: false,
        };

        assert!(metadata.validate().is_err());
        Ok(())
    }

    #[test]
    fn validate_resource_foo_slash_asterisk_can_mix_with_foo() -> Result<(), ()> {
        let pod_rule = Rule {
            api_groups: vec![String::from("a")],
            api_versions: vec![String::from("a")],
            resources: vec![String::from("a/*"), String::from("a")],
            operations: vec![Operation::Create],
        };
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(String::from("author"), String::from("Flavio Castelli"));

        let metadata = Metadata {
            labels: Some(labels),
            protocol_version: Some(ProtocolVersion::V1),
            rules: vec![pod_rule],
            mutating: false,
        };

        assert!(metadata.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_resource_asterisk_slash_bar_cannot_mix_with_foo_slash_bar() -> Result<(), ()> {
        let pod_rule = Rule {
            api_groups: vec![String::from("a")],
            api_versions: vec![String::from("a")],
            resources: vec![String::from("*/a"), String::from("x/a")],
            operations: vec![Operation::Create],
        };
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(String::from("author"), String::from("Flavio Castelli"));

        let metadata = Metadata {
            labels: Some(labels),
            protocol_version: Some(ProtocolVersion::V1),
            rules: vec![pod_rule],
            mutating: false,
        };

        assert!(metadata.validate().is_err());
        Ok(())
    }

    #[test]
    fn validate_resource_double_asterisk_cannot_mix_with_other_resources() -> Result<(), ()> {
        let pod_rule = Rule {
            api_groups: vec![String::from("a")],
            api_versions: vec![String::from("a")],
            resources: vec![String::from("*/*"), String::from("a")],
            operations: vec![Operation::Create],
        };
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(String::from("author"), String::from("Flavio Castelli"));

        let metadata = Metadata {
            labels: Some(labels),
            protocol_version: Some(ProtocolVersion::V1),
            rules: vec![pod_rule],
            mutating: false,
        };

        assert!(metadata.validate().is_err());
        Ok(())
    }
}

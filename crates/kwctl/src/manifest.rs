use anyhow::{anyhow, Result};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use validator::Validate;

use policy_evaluator::policy_metadata::{Metadata, Rule};

const POLICY_TITLE_ANNOTATION: &str = "io.kubewarden.policy.title";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterAdmissionPolicy {
    api_version: String,
    kind: String,
    metadata: ObjectMeta,
    spec: ClusterAdmissionPolicySpec,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterAdmissionPolicySpec {
    module: String,
    settings: serde_yaml::Mapping,
    rules: Vec<Rule>,
    mutating: bool,
}

impl TryFrom<ScaffoldData> for ClusterAdmissionPolicy {
    type Error = anyhow::Error;

    fn try_from(data: ScaffoldData) -> Result<Self, Self::Error> {
        data.metadata.validate()?;
        Ok(ClusterAdmissionPolicy {
            api_version: String::from("policies.kubewarden.io/v1alpha2"),
            kind: String::from("ClusterAdmissionPolicy"),
            metadata: ObjectMeta {
                name: data.policy_title,
                ..Default::default()
            },
            spec: ClusterAdmissionPolicySpec {
                module: data.uri,
                settings: data.settings,
                rules: data.metadata.rules.clone(),
                mutating: data.metadata.mutating,
            },
        })
    }
}

struct ScaffoldData {
    pub uri: String,
    policy_title: Option<String>,
    metadata: Metadata,
    settings: serde_yaml::Mapping,
}

pub(crate) fn manifest(
    uri: &str,
    resource_type: &str,
    settings: Option<String>,
    policy_title: Option<String>,
) -> Result<()> {
    let wasm_path = crate::utils::wasm_path(uri)?;
    let metadata = Metadata::from_path(&wasm_path)?
        .ok_or_else(||
            anyhow!(
                "No Kubewarden metadata found inside of '{}'.\nPolicies can be annotated with the `kwctl annotate` command.",
                uri)
        )?;

    let settings_yml: serde_yaml::Mapping =
        serde_yaml::from_str(&settings.unwrap_or_else(|| String::from("{}")))?;

    let scaffold_data = ScaffoldData {
        uri: String::from(uri),
        policy_title: get_policy_title_from_cli_or_metadata(policy_title, &metadata),
        metadata,
        settings: settings_yml,
    };
    let resource = match resource_type {
        "ClusterAdmissionPolicy" => ClusterAdmissionPolicy::try_from(scaffold_data),
        other => Err(anyhow!(
            "Resource {} unknown. Valid types are: ClusterAdmissionPolicy",
            other,
        )),
    }?;

    let stdout = std::io::stdout();
    let out = stdout.lock();
    serde_yaml::to_writer(out, &resource)?;

    Ok(())
}

fn get_policy_title_from_cli_or_metadata(
    policy_title: Option<String>,
    metadata: &Metadata,
) -> Option<String> {
    policy_title.or_else(|| {
        metadata
            .annotations
            .as_ref()
            .unwrap_or(&HashMap::new())
            .get(POLICY_TITLE_ANNOTATION)
            .map(|s| s.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_metadata_with_no_annotations() -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: None,
            mutating: false,
            context_aware: false,
            execution_mode: Default::default(),
        }
    }

    fn mock_metadata_with_title(title: String) -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: Some(HashMap::from([(
                POLICY_TITLE_ANNOTATION.to_string(),
                title,
            )])),
            mutating: false,
            context_aware: false,
            execution_mode: Default::default(),
        }
    }

    #[test]
    fn get_policy_title_from_cli_or_metadata_returns_name_from_cli_if_present() {
        let policy_title = Some("name".to_string());
        assert_eq!(
            policy_title,
            get_policy_title_from_cli_or_metadata(
                policy_title.clone(),
                &mock_metadata_with_no_annotations()
            )
        )
    }

    #[test]
    fn get_policy_title_from_cli_or_metadata_returns_none_if_both_are_missing() {
        assert_eq!(
            None,
            get_policy_title_from_cli_or_metadata(None, &mock_metadata_with_no_annotations())
        )
    }

    #[test]
    fn get_policy_title_from_cli_or_metadata_returns_title_from_annotation_if_name_from_cli_not_present(
    ) {
        let policy_title = "title".to_string();
        assert_eq!(
            Some(policy_title.clone()),
            get_policy_title_from_cli_or_metadata(
                None,
                &mock_metadata_with_title(policy_title.clone())
            )
        )
    }
}

use anyhow::{anyhow, Result};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use policy_evaluator::validator::Validate;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{self, File};
use std::path::PathBuf;
use time::OffsetDateTime;

use policy_evaluator::constants::KUBEWARDEN_ANNOTATION_POLICY_TITLE;
use policy_evaluator::policy_artifacthub::ArtifactHubPkg;
use policy_evaluator::policy_fetcher::verify::config::{
    LatestVerificationConfig, Signature, VersionedVerificationConfig,
};
use policy_evaluator::policy_metadata::{Metadata, Rule};

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
    // Skip serialization when this is true, which is the default case.
    // This is needed as a temporary fix for https://github.com/kubewarden/kubewarden-controller/issues/395
    #[serde(skip_serializing_if = "is_true")]
    background_audit: bool,
}

fn is_true(b: &bool) -> bool {
    *b
}

impl TryFrom<ScaffoldData> for ClusterAdmissionPolicy {
    type Error = anyhow::Error;

    fn try_from(data: ScaffoldData) -> Result<Self, Self::Error> {
        data.metadata.validate()?;
        Ok(ClusterAdmissionPolicy {
            api_version: String::from("policies.kubewarden.io/v1"),
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
                background_audit: data.metadata.background_audit,
            },
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionPolicy {
    api_version: String,
    kind: String,
    metadata: ObjectMeta,
    spec: AdmissionPolicySpec,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionPolicySpec {
    module: String,
    settings: serde_yaml::Mapping,
    rules: Vec<Rule>,
    mutating: bool,
    // Skip serialization when this is true, which is the default case.
    // This is needed as a temporary fix for https://github.com/kubewarden/kubewarden-controller/issues/395
    #[serde(skip_serializing_if = "is_true")]
    background_audit: bool,
}

impl TryFrom<ScaffoldData> for AdmissionPolicy {
    type Error = anyhow::Error;

    fn try_from(data: ScaffoldData) -> Result<Self, Self::Error> {
        data.metadata.validate()?;
        Ok(AdmissionPolicy {
            api_version: String::from("policies.kubewarden.io/v1"),
            kind: String::from("AdmissionPolicy"),
            metadata: ObjectMeta {
                name: data.policy_title,
                ..Default::default()
            },
            spec: AdmissionPolicySpec {
                module: data.uri,
                settings: data.settings,
                rules: data.metadata.rules.clone(),
                mutating: data.metadata.mutating,
                background_audit: data.metadata.background_audit,
            },
        })
    }
}

#[derive(Clone)]
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
        "ClusterAdmissionPolicy" => {
            serde_yaml::to_value(ClusterAdmissionPolicy::try_from(scaffold_data)?)
                .map_err(|e| anyhow!("{}", e))
        }
        "AdmissionPolicy" => serde_yaml::to_value(AdmissionPolicy::try_from(scaffold_data)?)
            .map_err(|e| anyhow!("{}", e)),
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
            .get(KUBEWARDEN_ANNOTATION_POLICY_TITLE)
            .map(|s| s.to_string())
    })
}

pub(crate) fn verification_config() -> Result<String> {
    let mut comment_header = r#"# Default Kubewarden verification config
#
# With this config, the only valid policies are those signed by Kubewarden
# infrastructure.
#
# This config can be saved to its default location (for this OS) with:
#   kwctl scaffold verification-config > "#
        .to_string();

    comment_header.push_str(
        super::KWCTL_DEFAULT_VERIFICATION_CONFIG_PATH
            .to_owned()
            .as_str(),
    );
    comment_header.push_str(
        r#"
#
# Providing a config in the default location enables Sigstore verification.
# See https://docs.kubewarden.io for more Sigstore verification options."#,
    );

    let kubewarden_verification_config =
        VersionedVerificationConfig::V1(LatestVerificationConfig {
            all_of: Some(vec![Signature::GithubAction {
                owner: "kubewarden".to_string(),
                repo: None,
                annotations: None,
            }]),
            any_of: None,
        });

    Ok(format!(
        "{}\n{}",
        comment_header,
        serde_yaml::to_string(&kubewarden_verification_config)?
    ))
}

pub(crate) fn artifacthub(
    metadata_path: PathBuf,
    version: &str,
    questions_path: Option<PathBuf>,
) -> Result<String> {
    let comment_header = r#"# Kubewarden Artifacthub Package config
#
# Use this config to submit the policy to https://artifacthub.io.
#
# This config can be saved to its default location with:
#   kwctl scaffold artifacthub > artifacthub-pkg.yml "#
        .to_string();

    let metadata_file =
        File::open(metadata_path).map_err(|e| anyhow!("Error opening metadata file: {}", e))?;
    let metadata: Metadata = serde_yaml::from_reader(&metadata_file)
        .map_err(|e| anyhow!("Error unmarshalling metadata {}", e))?;
    let questions_content: String;
    let questions = match questions_path {
        Some(path) => {
            questions_content = fs::read_to_string(path)
                .map_err(|e| anyhow!("Error reading questions file: {}", e))?;
            Some(questions_content.as_str())
        }
        None => None,
    };

    let kubewarden_artifacthub_pkg =
        ArtifactHubPkg::from_metadata(&metadata, version, OffsetDateTime::now_utc(), questions)?;

    Ok(format!(
        "{}\n{}",
        comment_header,
        serde_yaml::to_string(&kubewarden_artifacthub_pkg)?
    ))
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
            background_audit: true,
            context_aware: false,
            execution_mode: Default::default(),
        }
    }

    fn mock_metadata_with_title(title: String) -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: Some(HashMap::from([(
                KUBEWARDEN_ANNOTATION_POLICY_TITLE.to_string(),
                title,
            )])),
            mutating: false,
            background_audit: true,
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

    #[test]
    fn omit_background_audit_during_serialization_when_true() {
        // testing fix for https://github.com/kubewarden/kubewarden-controller/issues/395
        let policy_title = "test".to_string();
        let mut metadata = mock_metadata_with_title(policy_title.clone());
        metadata.protocol_version = Some(policy_evaluator::ProtocolVersion::V1);
        assert!(metadata.background_audit);

        let scaffold_data = ScaffoldData {
            uri: "not_relevant".to_string(),
            policy_title: get_policy_title_from_cli_or_metadata(Some(policy_title), &metadata),
            metadata,
            settings: Default::default(),
        };

        let out = serde_yaml::to_string(
            &ClusterAdmissionPolicy::try_from(scaffold_data.clone())
                .expect("cannot build ClusterAdmissionPolicy"),
        )
        .expect("serialization error");
        assert!(!out.contains("backgroundAudit"));

        let out = serde_yaml::to_string(
            &AdmissionPolicy::try_from(scaffold_data).expect("cannot build AdmissionPolicy"),
        )
        .expect("serialization error");
        assert!(!out.contains("backgroundAudit"));
    }

    #[test]
    fn do_not_omit_background_audit_during_serialization_when_false() {
        // testing fix for https://github.com/kubewarden/kubewarden-controller/issues/395
        let policy_title = "test".to_string();
        let mut metadata = mock_metadata_with_title(policy_title.clone());
        metadata.protocol_version = Some(policy_evaluator::ProtocolVersion::V1);
        metadata.background_audit = false;
        assert!(!metadata.background_audit);

        let scaffold_data = ScaffoldData {
            uri: "not_relevant".to_string(),
            policy_title: get_policy_title_from_cli_or_metadata(Some(policy_title), &metadata),
            metadata,
            settings: Default::default(),
        };

        let out = serde_yaml::to_string(
            &ClusterAdmissionPolicy::try_from(scaffold_data.clone())
                .expect("cannot build ClusterAdmissionPolicy"),
        )
        .expect("serialization error");
        assert!(out.contains("backgroundAudit"));

        let out = serde_yaml::to_string(
            &AdmissionPolicy::try_from(scaffold_data).expect("cannot build AdmissionPolicy"),
        )
        .expect("serialization error");
        assert!(out.contains("backgroundAudit"));
    }
}

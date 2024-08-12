use anyhow::{anyhow, Result};
use k8s_openapi::api::admissionregistration::v1::{
    ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
};
use policy_evaluator::{policy_fetcher::oci_client::Reference, policy_metadata::Rule};
use std::{collections::BTreeSet, convert::TryFrom, fs::File, path::Path};
use tracing::warn;

use crate::scaffold::kubewarden_crds::{ClusterAdmissionPolicy, ClusterAdmissionPolicySpec};

pub(crate) fn vap(cel_policy_module: &str, vap_path: &Path, binding_path: &Path) -> Result<()> {
    let vap_file = File::open(vap_path)
        .map_err(|e| anyhow!("cannot open {}: #{e}", vap_path.to_str().unwrap()))?;
    let binding_file = File::open(binding_path)
        .map_err(|e| anyhow!("cannot open {}: #{e}", binding_path.to_str().unwrap()))?;

    let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(vap_file)
        .map_err(|e| anyhow!("cannot convert given data into a ValidatingAdmissionPolicy: #{e}"))?;
    let vap_binding: ValidatingAdmissionPolicyBinding = serde_yaml::from_reader(binding_file)
        .map_err(|e| {
            anyhow!("cannot convert given data into a ValidatingAdmissionPolicyBinding: #{e}")
        })?;

    match cel_policy_module.parse::<Reference>() {
        Ok(cel_policy_ref) => match cel_policy_ref.tag() {
            None | Some("latest") => {
                warn!(
                    "Using the 'latest' version of the CEL policy could lead to unexpected behavior. It is recommended to use a specific version to avoid breaking changes."
                );
            }
            _ => {}
        },
        Err(_) => {
            warn!("The CEL policy module specified is not a valid OCI reference");
        }
    }

    let cluster_admission_policy =
        convert_vap_to_cluster_admission_policy(cel_policy_module, vap, vap_binding)?;

    serde_yaml::to_writer(std::io::stdout(), &cluster_admission_policy)?;

    Ok(())
}

fn convert_vap_to_cluster_admission_policy(
    cel_policy_module: &str,
    vap: ValidatingAdmissionPolicy,
    vap_binding: ValidatingAdmissionPolicyBinding,
) -> anyhow::Result<ClusterAdmissionPolicy> {
    let vap_spec = vap.spec.unwrap_or_default();
    if vap_spec.audit_annotations.is_some() {
        warn!("auditAnnotations are not supported by Kubewarden's CEL policy yet. They will be ignored.");
    }
    if vap_spec.match_conditions.is_some() {
        warn!("matchConditions are not supported by Kubewarden's CEL policy yet. They will be ignored.");
    }
    if vap_spec.param_kind.is_some() {
        // It's not safe to skip this, the policy will definitely not work.
        return Err(anyhow!(
            "paramKind is not supported by Kubewarden's CEL policy yet"
        ));
    }

    let mut settings = serde_yaml::Mapping::new();

    // migrate CEL variables
    if let Some(vap_variables) = vap_spec.variables {
        let vap_variables: Vec<serde_yaml::Value> = vap_variables
            .iter()
            .map(|v| serde_yaml::to_value(v).expect("cannot convert VAP variable to YAML"))
            .collect();
        settings.insert("variables".into(), vap_variables.into());
    }

    // migrate CEL validations
    if let Some(vap_validations) = vap_spec.validations {
        let kw_cel_validations: Vec<serde_yaml::Value> = vap_validations
            .iter()
            .map(|v| serde_yaml::to_value(v).expect("cannot convert VAP validation to YAML"))
            .collect();
        settings.insert("validations".into(), kw_cel_validations.into());
    }

    // VAP specifies the namespace selector inside of the binding
    let namespace_selector = vap_binding
        .spec
        .unwrap_or_default()
        .match_resources
        .unwrap_or_default()
        .namespace_selector;

    // VAP rules are specified inside of the VAP object
    let vap_match_constraints = vap_spec.match_constraints.unwrap_or_default();
    let match_policy = vap_match_constraints.match_policy;
    let rules = vap_match_constraints
        .resource_rules
        .unwrap_or_default()
        .iter()
        .map(Rule::try_from)
        .collect::<Result<Vec<Rule>, &'static str>>()
        .map_err(|e| anyhow!("error converting VAP matchConstraints into rules: {e}"))?;

    // migrate VAP
    let cluster_admission_policy = ClusterAdmissionPolicy {
        api_version: "policies.kubewarden.io/v1".to_string(),
        kind: "ClusterAdmissionPolicy".to_string(),
        metadata: vap_binding.metadata,
        spec: ClusterAdmissionPolicySpec {
            module: cel_policy_module.to_string(),
            namespace_selector,
            match_policy,
            rules,
            object_selector: vap_match_constraints.object_selector,
            mutating: false,
            background_audit: true,
            context_aware_resources: BTreeSet::new(),
            failure_policy: vap_spec.failure_policy,
            mode: None, // VAP policies are always in protect mode, which is the default for KW
            settings,
        },
    };

    Ok(cluster_admission_policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    const CEL_POLICY_MODULE: &str = "ghcr.io/kubewarden/policies/cel-policy:latest";

    fn test_data(path: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(path)
            .to_string_lossy()
            .to_string()
    }

    #[rstest]
    #[case::vap_without_variables("vap/vap-without-variables.yml", "vap/vap-binding.yml", false)]
    #[case::vap_with_variables("vap/vap-with-variables.yml", "vap/vap-binding.yml", true)]
    fn from_vap_to_cluster_admission_policy(
        #[case] vap_yaml_path: &str,
        #[case] vap_binding_yaml_path: &str,
        #[case] has_variables: bool,
    ) {
        let yaml_file = File::open(test_data(vap_yaml_path)).unwrap();
        let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(yaml_file).unwrap();

        let expected_validations =
            serde_yaml::to_value(vap.clone().spec.unwrap().validations.unwrap()).unwrap();
        let expected_rules = vap
            .clone()
            .spec
            .unwrap()
            .match_constraints
            .unwrap()
            .resource_rules
            .unwrap()
            .iter()
            .map(Rule::try_from)
            .collect::<Result<Vec<Rule>, &str>>()
            .unwrap();

        let yaml_file = File::open(test_data(vap_binding_yaml_path)).unwrap();
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).unwrap();

        let cluster_admission_policy = convert_vap_to_cluster_admission_policy(
            CEL_POLICY_MODULE,
            vap.clone(),
            vap_binding.clone(),
        )
        .unwrap();

        assert_eq!(CEL_POLICY_MODULE, cluster_admission_policy.spec.module);
        assert!(!cluster_admission_policy.spec.mutating);
        assert_eq!(cluster_admission_policy.spec.rules, expected_rules);
        assert!(cluster_admission_policy.spec.background_audit);
        assert!(cluster_admission_policy
            .spec
            .context_aware_resources
            .is_empty());
        assert_eq!(
            vap.clone().spec.unwrap().failure_policy,
            cluster_admission_policy.spec.failure_policy
        );
        assert!(cluster_admission_policy.spec.mode.is_none());
        assert_eq!(
            vap.clone()
                .spec
                .unwrap()
                .match_constraints
                .unwrap()
                .match_policy,
            cluster_admission_policy.spec.match_policy
        );
        assert_eq!(
            vap_binding
                .clone()
                .spec
                .unwrap()
                .match_resources
                .unwrap()
                .namespace_selector,
            cluster_admission_policy.spec.namespace_selector
        );
        assert!(cluster_admission_policy.spec.object_selector.is_none());
        assert_eq!(
            expected_validations,
            cluster_admission_policy.spec.settings["validations"]
        );

        if has_variables {
            let expected_variables =
                serde_yaml::to_value(vap.clone().spec.unwrap().variables.unwrap()).unwrap();
            assert_eq!(
                expected_variables,
                cluster_admission_policy.spec.settings["variables"]
            );
        } else {
            assert!(!cluster_admission_policy
                .spec
                .settings
                .contains_key("variables"));
        }
    }
}

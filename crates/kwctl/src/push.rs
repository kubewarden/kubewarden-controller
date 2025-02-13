use std::{collections::BTreeMap, fs, path::PathBuf};

use anyhow::{anyhow, Result};
use policy_evaluator::{
    constants::KUBEWARDEN_ANNOTATION_POLICY_SOURCE,
    policy_fetcher::{
        oci_client::annotations::ORG_OPENCONTAINERS_IMAGE_SOURCE, registry::Registry,
        sources::Sources,
    },
    policy_metadata::Metadata,
};
use tracing::warn;

use crate::backend::BackendDetector;

pub(crate) async fn push(
    wasm_path: PathBuf,
    uri: &str,
    sources: Option<&Sources>,
    force: bool,
) -> Result<String> {
    let metadata = Metadata::from_path(&wasm_path)?;

    if metadata.is_none() {
        if force {
            let backend_detector = BackendDetector::default();
            if can_be_force_pushed_without_metadata(backend_detector, wasm_path.clone())? {
                eprintln!("Warning: pushing a non-annotated policy!");
            } else {
                return Err(anyhow!("Rego policies cannot be pushed without metadata"));
            }
        } else {
            return Err(anyhow!("Cannot push a policy that is not annotated. Use `annotate` command or `push --force`"));
        }
    }

    let annotations = metadata.and_then(|meta| meta.annotations.map(build_oci_annotations));

    let policy = fs::read(&wasm_path).map_err(|e| anyhow!("Cannot open policy file: {:?}", e))?;
    Registry::new()
        .push(&policy, uri, sources, annotations)
        .await
        .map_err(anyhow::Error::new)
}

fn can_be_force_pushed_without_metadata(
    backend_detector: BackendDetector,
    wasm_path: PathBuf,
) -> Result<bool> {
    let is_rego = backend_detector
        .is_rego_policy(&wasm_path)
        .map_err(|e| anyhow!("Cannot understand if the policy is based on Rego: {:?}", e))?;

    Ok(!is_rego)
}

/// Augment the annotations with the `org.opencontainers.image.source`
/// annotation, if the `io.kubewarden.policy.source` annotation is present.
fn build_oci_annotations(annotations: BTreeMap<String, String>) -> BTreeMap<String, String> {
    // filter all the multi-line annotations, they are not supported by the OCI spec
    let mut annotations: BTreeMap<String, String> = annotations
        .iter()
        .filter(|(k, v)| {
            let filter = v.lines().count() <= 1;
            if filter {
                warn!(
                    annotation = k,
                    "annotation is a multi-line string, it will be removed from the OCI manifest",
                );
            }
            filter
        })
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    if let Some(source) = annotations.get(KUBEWARDEN_ANNOTATION_POLICY_SOURCE) {
        if !annotations.contains_key(ORG_OPENCONTAINERS_IMAGE_SOURCE) {
            annotations.insert(
                ORG_OPENCONTAINERS_IMAGE_SOURCE.to_string(),
                source.to_owned(),
            );
        }
    }

    annotations
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_evaluator::constants::{
        KUBEWARDEN_ANNOTATION_POLICY_URL, KUBEWARDEN_ANNOTATION_POLICY_USAGE,
    };

    #[test]
    fn test_build_oci_annotations_propagate_policy_source() {
        let policy_source = "example.com";
        let policy_url = "http://example.com";

        let mut annotations = BTreeMap::new();
        annotations.insert(
            KUBEWARDEN_ANNOTATION_POLICY_SOURCE.to_string(),
            policy_source.to_string(),
        );
        annotations.insert(
            KUBEWARDEN_ANNOTATION_POLICY_URL.to_string(),
            policy_url.to_string(),
        );
        annotations.insert(
            KUBEWARDEN_ANNOTATION_POLICY_USAGE.to_string(),
            "this is a multi-line\nstring".to_string(),
        );

        let actual = build_oci_annotations(annotations);

        assert!(!actual.contains_key(KUBEWARDEN_ANNOTATION_POLICY_USAGE));
        assert_eq!(
            actual.get(ORG_OPENCONTAINERS_IMAGE_SOURCE).unwrap(),
            policy_source
        );
        assert_eq!(
            actual.get(KUBEWARDEN_ANNOTATION_POLICY_URL).unwrap(),
            policy_url,
        );
        assert_eq!(
            actual.get(KUBEWARDEN_ANNOTATION_POLICY_SOURCE).unwrap(),
            policy_source
        );
    }

    #[test]
    fn test_build_oci_annotations_do_not_overwrite_oci_source_if_already_set() {
        let policy_source = "example.com";
        let oci_source = "oci.org";

        let mut annotations = BTreeMap::new();
        annotations.insert(
            KUBEWARDEN_ANNOTATION_POLICY_SOURCE.to_string(),
            policy_source.to_string(),
        );
        annotations.insert(
            KUBEWARDEN_ANNOTATION_POLICY_USAGE.to_string(),
            "this is a multi-line\nstring".to_string(),
        );
        annotations.insert(
            ORG_OPENCONTAINERS_IMAGE_SOURCE.to_string(),
            oci_source.to_string(),
        );

        let actual = build_oci_annotations(annotations);
        assert!(!actual.contains_key(KUBEWARDEN_ANNOTATION_POLICY_USAGE));
        assert_eq!(
            actual.get(ORG_OPENCONTAINERS_IMAGE_SOURCE).unwrap(),
            oci_source
        );
        assert_eq!(
            actual.get(KUBEWARDEN_ANNOTATION_POLICY_SOURCE).unwrap(),
            policy_source
        );
    }
}

use anyhow::{anyhow, Result};
use policy_evaluator::policy_evaluator::PolicyExecutionMode;
use policy_evaluator::policy_fetcher::store::Store;
use regex::Regex;
use serde_json::json;
use std::path::PathBuf;
use url::Url;

pub(crate) fn map_path_to_uri(uri_or_sha_prefix: &str) -> Result<String> {
    let uri_has_schema = Regex::new(r"^\w+://").unwrap();
    if uri_has_schema.is_match(uri_or_sha_prefix) {
        return Ok(String::from(uri_or_sha_prefix));
    }

    let path = PathBuf::from(uri_or_sha_prefix);
    if path.exists() {
        let path = path.canonicalize()?;

        Ok(Url::from_file_path(path).unwrap().to_string())
    } else {
        let store = Store::default();
        if let Some(policy) = store.get_policy_by_sha_prefix(uri_or_sha_prefix)? {
            Ok(policy.uri.clone())
        } else {
            Err(anyhow!(
                "Cannot find policy with prefix: {}",
                uri_or_sha_prefix
            ))
        }
    }
}

pub(crate) fn wasm_path(uri: &str) -> Result<PathBuf> {
    let url = Url::parse(uri)?;
    match url.scheme() {
        "file" => url
            .to_file_path()
            .map_err(|err| anyhow!("cannot retrieve path from uri {}: {:?}", url, err)),
        "http" | "https" | "registry" => {
            let store = Store::default();
            let policy = store.get_policy_by_uri(uri)?;

            if let Some(policy) = policy {
                Ok(policy.local_path)
            } else {
                Err(anyhow!("Cannot find policy '{uri}' inside of the local store.\nTry executing `kwctl pull {uri}`", uri = uri))
            }
        }
        _ => Err(anyhow!("unknown scheme: {}", url.scheme())),
    }
}

pub(crate) fn new_policy_execution_mode_from_str(name: &str) -> Result<PolicyExecutionMode> {
    let execution_mode: PolicyExecutionMode =
        serde_json::from_value(json!(name)).map_err(|_| {
            anyhow!(
                "Unknown policy execution mode \"{}\". Valid values are {}, {}, {}",
                name,
                serde_json::to_string(&PolicyExecutionMode::KubewardenWapc).unwrap(),
                serde_json::to_string(&PolicyExecutionMode::Opa).unwrap(),
                serde_json::to_string(&PolicyExecutionMode::OpaGatekeeper).unwrap(),
            )
        })?;
    Ok(execution_mode)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_map_path_to_uri_remote_scheme() -> Result<()> {
        assert_eq!(
            map_path_to_uri("registry://some-registry.com/some-path/some-policy:0.0.1")?,
            String::from("registry://some-registry.com/some-path/some-policy:0.0.1"),
        );

        Ok(())
    }

    #[test]
    fn test_map_path_to_uri_local_scheme() -> Result<()> {
        assert_eq!(
            map_path_to_uri("file:///absolute/directory/some-policy-0.0.1.wasm")?,
            "file:///absolute/directory/some-policy-0.0.1.wasm",
        );

        Ok(())
    }

    #[test]
    fn test_build_policy_execution_mode_from_valid_input() {
        let mut data: HashMap<String, PolicyExecutionMode> = HashMap::new();
        data.insert(String::from("opa"), PolicyExecutionMode::Opa);
        data.insert(
            String::from("gatekeeper"),
            PolicyExecutionMode::OpaGatekeeper,
        );
        data.insert(
            String::from("kubewarden-wapc"),
            PolicyExecutionMode::KubewardenWapc,
        );

        for (name, mode) in data {
            let actual = new_policy_execution_mode_from_str(name.as_str());
            assert!(
                actual.is_ok(),
                "Error while converting {}: {:?}",
                name,
                actual
            );

            let actual = actual.unwrap();
            assert_eq!(actual, mode, "Expected {}, got {}", mode, actual);
        }
    }

    #[test]
    fn test_build_policy_execution_mode_from_invalid_input() {
        let actual = new_policy_execution_mode_from_str("test");
        assert!(actual.is_err(),);
    }
}

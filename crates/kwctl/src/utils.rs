use anyhow::{anyhow, Result};
use policy_evaluator::policy_evaluator::PolicyExecutionMode;
use policy_evaluator::policy_fetcher::oci_distribution::Reference;
use policy_evaluator::policy_fetcher::store::{errors::StoreError, Store};
use regex::Regex;
use serde_json::json;
use std::path::PathBuf;
use std::str::FromStr;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub(crate) enum LookupError {
    #[error("Cannot find policy with uri: {0}")]
    PolicyMissing(String),
    #[error("{0}")]
    StoreError(#[from] StoreError),
    #[error("Unknown scheme: {0}")]
    UnknownScheme(String),
    #[error("{0}")]
    UrlParserError(#[from] url::ParseError),
    #[error("Error while converting URL to string")]
    UrlToStringConversionError(),
    #[error("{0}")]
    IoError(#[from] std::io::Error),
}

pub(crate) fn map_path_to_uri(uri_or_sha_prefix: &str) -> std::result::Result<String, LookupError> {
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
            Err(LookupError::PolicyMissing(uri_or_sha_prefix.to_string()))
        }
    }
}

pub(crate) fn get_uri(uri_or_sha_prefix: &String) -> std::result::Result<String, LookupError> {
    map_path_to_uri(uri_or_sha_prefix).or_else(|_| {
        Reference::from_str(uri_or_sha_prefix)
            .map(|oci_reference| format!("registry://{}", oci_reference.whole()))
            .map_err(|_| LookupError::PolicyMissing(uri_or_sha_prefix.to_string()))
    })
}

pub(crate) fn get_wasm_path(uri_or_sha_prefix: &str) -> std::result::Result<PathBuf, LookupError> {
    let uri = get_uri(&uri_or_sha_prefix.to_owned())?;
    wasm_path(&uri)
}

pub(crate) fn wasm_path(uri: &str) -> std::result::Result<PathBuf, LookupError> {
    let url = Url::parse(uri)?;
    match url.scheme() {
        "file" => url
            .to_file_path()
            .map_err(|_| LookupError::UrlToStringConversionError()),
        "http" | "https" | "registry" => {
            let store = Store::default();
            let policy = store.get_policy_by_uri(uri)?;

            if let Some(policy) = policy {
                Ok(policy.local_path)
            } else {
                Err(LookupError::PolicyMissing(uri.to_string()))
            }
        }
        _ => Err(LookupError::UnknownScheme(url.scheme().to_string())),
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

use anyhow::{anyhow, Result};
use policy_fetcher::store::Store;
use regex::Regex;
use std::{env, path::PathBuf};
use url::Url;

pub(crate) fn map_path_to_uri(uri: &str) -> Result<String> {
    let uri_has_schema = Regex::new(r"^\w+://").unwrap();
    if uri_has_schema.is_match(uri) {
        return Ok(String::from(uri));
    }
    if PathBuf::from(uri).is_absolute() {
        Ok(format!("file://{}", uri))
    } else {
        Ok(format!(
            "file://{}/{}",
            env::current_dir()?
                .into_os_string()
                .into_string()
                .map_err(|err| anyhow!("invalid path: {:?}", err))?,
            uri
        ))
    }
}

pub(crate) fn wasm_path(uri: &str) -> Result<PathBuf> {
    let url = Url::parse(uri)?;
    match url.scheme() {
        "file" => url
            .to_file_path()
            .map_err(|err| anyhow!("cannot retrieve path from uri {}: {:?}", url, err)),
        "http" | "https" | "registry" => {
            let policies = Store::default().list()?;
            let policy = policies.iter().find(|policy| policy.uri == uri).ok_or_else(|| anyhow!("Cannot find policy '{uri}' inside of the local store.\nTry executing `kwctl pull {uri}`", uri = uri))?;
            Ok(policy.local_path.clone())
        }
        _ => Err(anyhow!("unknown scheme: {}", url.scheme())),
    }
}

#[cfg(test)]
mod tests {
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
    fn test_map_path_to_uri_missing_scheme() -> Result<()> {
        assert_eq!(
            map_path_to_uri("some-policy-0.0.1.wasm")?,
            format!(
                "file://{}",
                env::current_dir()?
                    .join("some-policy-0.0.1.wasm")
                    .into_os_string()
                    .into_string()
                    .map_err(|_| anyhow!("cannot get policy test path"))?,
            ),
        );

        assert_eq!(
            map_path_to_uri("/absolute/directory/some-policy-0.0.1.wasm")?,
            "file:///absolute/directory/some-policy-0.0.1.wasm",
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
}

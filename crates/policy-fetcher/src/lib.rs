extern crate directories;
extern crate reqwest;
extern crate rustls;
extern crate walkdir;

use anyhow::{anyhow, Result};
use std::boxed::Box;
use std::fs;
use url::Url;

pub mod fetcher;
mod https;
pub mod policy;
pub mod registry;
pub mod sources;
pub mod store;
pub mod verify;

use crate::fetcher::{ClientProtocol, PolicyFetcher, TlsVerificationMode};
use crate::https::Https;
use crate::policy::Policy;
use crate::registry::build_fully_resolved_reference;
use crate::registry::Registry;
use crate::sources::Sources;
use crate::store::Store;

use std::path::{Path, PathBuf};
use tracing::debug;
use url::ParseError;

// re-export for usage by kwctl, policy-server, policy-evaluator,...
pub use oci_distribution;
pub use sigstore;

#[derive(Debug)]
pub enum PullDestination {
    MainStore,
    Store(PathBuf),
    LocalFile(PathBuf),
}

pub async fn fetch_policy(
    url: &str,
    destination: PullDestination,
    sources: Option<&Sources>,
) -> Result<Policy> {
    let url = match Url::parse(url) {
        Ok(u) => Ok(u),
        Err(ParseError::RelativeUrlWithoutBase) => {
            Url::parse(format!("registry://{}", url).as_str())
        }
        Err(e) => Err(e),
    }?;
    match url.scheme() {
        "file" => {
            // no-op: return early
            return Ok(Policy {
                uri: url.to_string(),
                local_path: url
                    .to_file_path()
                    .map_err(|err| anyhow!("cannot retrieve path from uri {}: {:?}", url, err))?,
            });
        }
        "registry" | "http" | "https" => Ok(()),
        _ => Err(anyhow!("unknown scheme: {}", url.scheme())),
    }?;
    let (store, destination) = pull_destination(&url, &destination)?;
    if let Some(store) = store {
        store.ensure(&store.policy_full_path(url.as_str(), store::PolicyPath::PrefixOnly)?)?;
    }
    match url.scheme() {
        "registry" => {
            // On a registry, the `latest` tag always pulls the latest version
            let reference = build_fully_resolved_reference(url.as_str())?;
            if reference.tag() != Some("latest") && Path::exists(&destination) {
                return Ok(Policy {
                    uri: url.to_string(),
                    local_path: destination,
                });
            }
        }
        "http" | "https" => {
            if Path::exists(&destination) {
                return Ok(Policy {
                    uri: url.to_string(),
                    local_path: destination,
                });
            }
        }
        _ => unreachable!(),
    }
    debug!(?url, "pulling policy");
    let policy_fetcher = url_fetcher(url.scheme())?;
    let sources_default = Sources::default();
    let sources = sources.unwrap_or(&sources_default);

    match policy_fetcher
        .fetch(&url, client_protocol(&url, sources)?)
        .await
    {
        Err(err) => {
            if !sources.is_insecure_source(&host_and_port(&url)?) {
                return Err(anyhow!(
                    "the policy {} could not be downloaded due to error: {}",
                    url,
                    err
                ));
            }
        }
        Ok(bytes) => return create_file_if_valid(&bytes, &destination, url.to_string()),
    }
    if let Ok(bytes) = policy_fetcher
        .fetch(
            &url,
            ClientProtocol::Https(TlsVerificationMode::NoTlsVerification),
        )
        .await
    {
        return create_file_if_valid(&bytes, &destination, url.to_string());
    }

    if let Ok(bytes) = policy_fetcher.fetch(&url, ClientProtocol::Http).await {
        return create_file_if_valid(&bytes, &destination, url.to_string());
    }

    Err(anyhow!("could not pull policy {}", url))
}

fn client_protocol(url: &Url, sources: &Sources) -> Result<ClientProtocol> {
    if let Some(certificates) = sources.source_authority(&host_and_port(url)?) {
        return Ok(ClientProtocol::Https(
            TlsVerificationMode::CustomCaCertificates(certificates),
        ));
    }
    Ok(ClientProtocol::Https(TlsVerificationMode::SystemCa))
}

fn pull_destination(url: &Url, destination: &PullDestination) -> Result<(Option<Store>, PathBuf)> {
    Ok(match destination {
        PullDestination::MainStore => {
            let store = Store::default();
            let policy_path =
                store.policy_full_path(url.as_str(), store::PolicyPath::PrefixAndFilename)?;
            (Some(store), policy_path)
        }
        PullDestination::Store(root) => {
            let store = Store::new(root);
            let policy_path =
                store.policy_full_path(url.as_str(), store::PolicyPath::PrefixAndFilename)?;
            (Some(store), policy_path)
        }
        PullDestination::LocalFile(destination) => {
            if Path::is_dir(destination) {
                let filename = url.path().split('/').last().unwrap();
                (None, destination.join(filename))
            } else {
                (None, PathBuf::from(destination))
            }
        }
    })
}

// Helper function, takes the URL of the policy and allocates the
// right struct to interact with it
#[allow(clippy::box_default)]
fn url_fetcher(scheme: &str) -> Result<Box<dyn PolicyFetcher>> {
    match scheme {
        "http" | "https" => Ok(Box::new(Https::default())),
        "registry" => Ok(Box::new(Registry::new())),
        _ => Err(anyhow!("unknown scheme: {}", scheme)),
    }
}

pub(crate) fn host_and_port(url: &Url) -> Result<String> {
    Ok(format!(
        "{}{}",
        url.host_str()
            .ok_or_else(|| anyhow!("invalid URL {}", url))?,
        url.port()
            .map(|port| format!(":{}", port))
            .unwrap_or_default(),
    ))
}

// Each Wasm file begins with a well known bytes sequence, known as
// "magic bytes" (see https://en.wikipedia.org/wiki/List_of_file_signatures).
//
// The Wasm magic bytes sequence is defined inside of its official specification:
// https://webassembly.github.io/spec/core/bikeshed/#binary-magic
const WASM_MAGIC_NUMBER: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

fn create_file_if_valid(bytes: &[u8], destination: &Path, url: String) -> Result<Policy> {
    if !bytes.starts_with(&WASM_MAGIC_NUMBER) {
        return Err(anyhow!("invalid wasm file"));
    };
    fs::write(destination, bytes)
        .map_err(|e| anyhow!("wasm module cannot be save to {:?}: {}", destination, e))?;

    Ok(Policy {
        uri: url,
        local_path: destination.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use std::{fs, path::Path};
    use tempfile::NamedTempFile;

    fn read_fixture(filename: &Path) -> Vec<u8> {
        let test_data_file = std::env::current_dir()
            .unwrap_or_else(|_| panic!("[test setup error] could not read the current directory"))
            .join("tests")
            .join("test_data")
            .join(filename);

        fs::read(&test_data_file).unwrap_or_else(|_| {
            panic!(
                "[test setup error] could not read file {:?}",
                &test_data_file
            )
        })
    }

    fn store_path(path: &str) -> PathBuf {
        Store::default().root.join(path)
    }

    #[test]
    fn local_file_pull_destination_excluding_filename() -> Result<()> {
        assert_eq!(
            pull_destination(
                &Url::parse("https://host.example.com:1234/path/to/policy.wasm")?,
                &PullDestination::LocalFile(std::env::current_dir()?),
            )?,
            (None, std::env::current_dir()?.join("policy.wasm"),),
        );
        Ok(())
    }

    #[test]
    fn local_file_pull_destination_including_filename() -> Result<()> {
        assert_eq!(
            pull_destination(
                &Url::parse("https://host.example.com:1234/path/to/policy.wasm")?,
                &PullDestination::LocalFile(std::env::current_dir()?.join("named-policy.wasm")),
            )?,
            (None, std::env::current_dir()?.join("named-policy.wasm"),),
        );
        Ok(())
    }

    #[test]
    fn store_pull_destination_from_http_with_port() -> Result<()> {
        assert_eq!(
            pull_destination(
                &Url::parse("http://host.example.com:1234/path/to/policy.wasm")?,
                &PullDestination::MainStore,
            )?,
            (
                Some(Store::default()),
                store_path("http/host.example.com:1234/path/to/policy.wasm"),
            ),
        );
        Ok(())
    }

    #[test]
    fn store_pull_destination_from_http() -> Result<()> {
        assert_eq!(
            pull_destination(
                &Url::parse("http://host.example.com/path/to/policy.wasm")?,
                &PullDestination::MainStore,
            )?,
            (
                Some(Store::default()),
                store_path("http/host.example.com/path/to/policy.wasm"),
            ),
        );
        Ok(())
    }

    #[test]
    fn store_pull_destination_from_https() -> Result<()> {
        assert_eq!(
            pull_destination(
                &Url::parse("https://host.example.com/path/to/policy.wasm")?,
                &PullDestination::MainStore,
            )?,
            (
                Some(Store::default()),
                store_path("https/host.example.com/path/to/policy.wasm"),
            ),
        );
        Ok(())
    }

    #[test]
    fn store_pull_destination_from_https_with_port() -> Result<()> {
        assert_eq!(
            pull_destination(
                &Url::parse("https://host.example.com:1234/path/to/policy.wasm")?,
                &PullDestination::MainStore,
            )?,
            (
                Some(Store::default()),
                store_path("https/host.example.com:1234/path/to/policy.wasm"),
            ),
        );
        Ok(())
    }

    #[test]
    fn store_pull_destination_from_registry() -> Result<()> {
        assert_eq!(
            pull_destination(
                &Url::parse("registry://host.example.com/path/to/policy:tag")?,
                &PullDestination::MainStore,
            )?,
            (
                Some(Store::default()),
                store_path("registry/host.example.com/path/to/policy:tag"),
            ),
        );
        assert_eq!(
            pull_destination(
                &Url::parse("registry://host.example.com/policy:tag")?,
                &PullDestination::MainStore,
            )?,
            (
                Some(Store::default()),
                store_path("registry/host.example.com/policy:tag"),
            ),
        );
        Ok(())
    }

    #[test]
    fn store_pull_destination_from_registry_with_port() -> Result<()> {
        assert_eq!(
            pull_destination(
                &Url::parse("registry://host.example.com:1234/path/to/policy:tag")?,
                &PullDestination::MainStore,
            )?,
            (
                Some(Store::default()),
                store_path("registry/host.example.com:1234/path/to/policy:tag"),
            ),
        );
        Ok(())
    }

    #[rstest]
    #[case("simple.wasm", true)]
    #[case("auth-present.json", false)]
    fn save_only_wasm_files_to_disk(#[case] fixture_file: &str, #[case] success: bool) {
        let dest = NamedTempFile::new().expect("Cannot create tmp file");
        let file_contents = read_fixture(Path::new(fixture_file));

        let outcome = create_file_if_valid(&file_contents, dest.path(), "not relevant".to_string());
        assert_eq!(outcome.is_ok(), success);
    }
}

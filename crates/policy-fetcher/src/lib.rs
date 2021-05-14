extern crate directories;
extern crate reqwest;
extern crate rustls;
extern crate walkdir;

use anyhow::{anyhow, Result};
use std::boxed::Box;
use url::Url;

pub mod fetcher;
mod https;
mod local;
pub mod policy;
pub mod registry;
pub mod sources;
pub mod store;

use crate::registry::config::DockerConfig;

use crate::fetcher::Fetcher;
use crate::https::Https;
use crate::local::Local;
use crate::registry::Registry;
use crate::sources::Sources;
use crate::store::Store;

use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum PullDestination {
    MainStore,
    Store(PathBuf),
    LocalFile(PathBuf),
}

pub async fn fetch_policy(
    url: &str,
    destination: PullDestination,
    docker_config: Option<DockerConfig>,
    sources: &Sources,
) -> Result<PathBuf> {
    let url = Url::parse(url)?;
    match url.scheme() {
        "file" => {
            // no-op: return early
            return url
                .to_file_path()
                .map_err(|err| anyhow!("cannot retrieve path from uri {}: {:?}", url, err));
        }
        "http" | "https" | "registry" => Ok(()),
        _ => Err(anyhow!("unknown scheme: {}", url.scheme())),
    }?;
    let (store, destination) = pull_destination(&url, &destination)?;
    if let Some(store) = store {
        store.ensure(&store.policy_full_path(url.as_str(), store::PolicyPath::PrefixOnly)?)?;
    }
    // TODO (ereslibre): add special meaning for certain tags if they
    // exist: e.g. the `latest` tag should always be pulled
    if Path::exists(&destination) {
        return Ok(destination);
    }
    eprintln!("pulling policy...");
    url_fetcher(&url, docker_config, destination)?
        .fetch(sources)
        .await
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
            if Path::is_dir(&destination) {
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
fn url_fetcher(
    url: &Url,
    docker_config: Option<DockerConfig>,
    destination: PathBuf,
) -> Result<Box<dyn Fetcher>> {
    match url.scheme() {
        "file" => Ok(Box::new(Local::new(PathBuf::from(url.path())))),
        "http" | "https" => Ok(Box::new(Https::new(url.clone(), destination))),
        "registry" => Ok(Box::new(Registry::new(
            url.clone(),
            docker_config,
            destination,
        ))),
        _ => Err(anyhow!("unknown scheme: {}", url.scheme())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

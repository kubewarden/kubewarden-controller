use anyhow::Result;
use policy_fetcher::{registry::config::DockerConfig, registry::Registry, sources::Sources};

/// Helper struct to interact with an OCI registry
pub(crate) struct Client {
    sources: Option<Sources>,
    registry: Registry,
}

impl Client {
    pub fn new(sources: Option<Sources>, docker_config: Option<DockerConfig>) -> Self {
        let registry = Registry::new(docker_config.as_ref());
        Client { sources, registry }
    }

    /// Fetch the manifest digest of the OCI resource referenced via `image`
    pub async fn digest(&self, image: &str) -> Result<String> {
        let image_with_proto = format!("registry://{}", image);
        self.registry
            .manifest_digest(&image_with_proto, self.sources.as_ref())
            .await
    }
}

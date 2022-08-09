use anyhow::{anyhow, Result};
use policy_fetcher::oci_distribution::Reference;
use policy_fetcher::{registry::Registry, sources::Sources};

/// Helper struct to interact with an OCI registry
pub(crate) struct Client {
    sources: Option<Sources>,
    registry: Registry,
}

impl Client {
    pub fn new(sources: Option<Sources>) -> Self {
        let registry = Registry {};
        Client { sources, registry }
    }

    /// Fetch the manifest digest of the OCI resource referenced via `image`
    pub async fn digest(&self, image: &str) -> Result<String> {
        // this is needed to expand names as `busybox` into
        // fully resolved references like `docker.io/library/busybox`
        let image_ref: Reference = image.parse()?;

        let image_with_proto = format!("registry://{}", image_ref.whole());
        let image_digest = self
            .registry
            .manifest_digest(&image_with_proto, self.sources.as_ref())
            .await?;
        serde_json::to_string(&image_digest)
            .map_err(|e| anyhow!("Cannot serialize response to json: {}", e))
    }
}

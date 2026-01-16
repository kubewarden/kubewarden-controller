use std::time::Duration;

use anyhow::Result;
use cached::proc_macro::cached;
use kubewarden_policy_sdk::host_capabilities::oci::ManifestDigestResponse;
use policy_fetcher::{
    oci_client::{
        Reference,
        manifest::{OciImageManifest, OciManifest},
    },
    registry::Registry,
    sources::Sources,
};
use serde::{Deserialize, Serialize};

/// Helper struct to interact with an OCI registry
pub(crate) struct Client {
    sources: Option<Sources>,
    registry: Registry,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ManifestAndConfigResponse {
    pub manifest: OciImageManifest,
    pub digest: String,
    pub config: serde_json::Value,
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

        Ok(image_digest)
    }

    pub async fn manifest(&self, image: &str) -> Result<OciManifest> {
        // this is needed to expand names as `busybox` into
        // fully resolved references like `docker.io/library/busybox`
        let image_ref: Reference = image.parse()?;

        let image_with_proto = format!("registry://{}", image_ref.whole());
        let manifest = self
            .registry
            .manifest(&image_with_proto, self.sources.as_ref())
            .await?;
        Ok(manifest)
    }

    pub async fn manifest_and_config(&self, image: &str) -> Result<ManifestAndConfigResponse> {
        // this is needed to expand names as `busybox` into
        // fully resolved references like `docker.io/library/busybox`
        let image_ref: Reference = image.parse()?;
        let image_with_proto = format!("registry://{}", image_ref.whole());
        let (manifest, digest, config) = self
            .registry
            .manifest_and_config(&image_with_proto, self.sources.as_ref())
            .await?;
        Ok(ManifestAndConfigResponse {
            manifest,
            digest,
            config,
        })
    }
}

// Interacting with a remote OCI registry is time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the digests results.
//
// Details about this cache:
//   * only the image "url" is used as key. oci::Client is not hashable, plus
//     the client is always the same
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
#[cached(
    time = 60,
    result = true,
    sync_writes = "default",
    key = "String",
    convert = r#"{ format!("{}", img) }"#,
    with_cached_flag = true
)]
pub(crate) async fn get_oci_digest_cached(
    oci_client: &Client,
    img: &str,
) -> Result<cached::Return<ManifestDigestResponse>> {
    oci_client
        .digest(img)
        .await
        .map(|digest| ManifestDigestResponse { digest })
        .map(cached::Return::new)
}

// Interacting with a remote OCI registry is time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the manifest results.
//
// Details about this cache:
//   * only the image "url" is used as key. oci::Client is not hashable, plus
//     the client is always the same
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
#[cached(
    time = 60,
    result = true,
    sync_writes = "default",
    key = "String",
    convert = r#"{ format!("{}", img) }"#,
    with_cached_flag = true
)]
pub(crate) async fn get_oci_manifest_cached(
    oci_client: &Client,
    img: &str,
) -> Result<cached::Return<OciManifest>> {
    oci_client.manifest(img).await.map(cached::Return::new)
}

#[cached(
    time = 60,
    result = true,
    sync_writes = "default",
    key = "String",
    convert = r#"{ format!("{}", img) }"#,
    with_cached_flag = true
)]
pub(crate) async fn get_oci_manifest_and_config_cached(
    oci_client: &Client,
    img: &str,
) -> Result<cached::Return<ManifestAndConfigResponse>> {
    oci_client
        .manifest_and_config(img)
        .await
        .map(cached::Return::new)
}

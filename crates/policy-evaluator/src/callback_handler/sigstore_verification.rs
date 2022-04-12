use anyhow::{anyhow, Result};
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::{FulcioAndRekorData, Verifier};
use std::collections::HashMap;

pub(crate) struct Client {
    verifier: Verifier,
    docker_config: Option<DockerConfig>,
}

impl Client {
    pub fn new(
        sources: Option<Sources>,
        docker_config: Option<DockerConfig>,
        fulcio_and_rekor_data: &FulcioAndRekorData,
    ) -> Result<Self> {
        let verifier = Verifier::new(sources, fulcio_and_rekor_data)?;
        Ok(Client {
            verifier,
            docker_config,
        })
    }

    pub async fn is_pub_key_trusted(
        &mut self,
        image: String,
        pub_keys: Vec<String>,
        annotations: HashMap<String, String>,
    ) -> Result<bool> {
        if pub_keys.is_empty() {
            return Err(anyhow!("Must provide at least one pub key"));
        }
        let result = self
            .verifier
            .verify_pub_key(self.docker_config.as_ref(), image, pub_keys, annotations)
            .await;

        match result {
            Ok(_) => Ok(true),
            Err(e) => Err(e),
        }
    }
}

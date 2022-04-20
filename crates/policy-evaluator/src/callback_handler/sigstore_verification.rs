use anyhow::{anyhow, Result};
use policy_fetcher::kubewarden_policy_sdk::host_capabilities::verification::{
    KeylessInfo, VerificationResponse,
};
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

    pub async fn verify_public_key(
        &mut self,
        image: String,
        pub_keys: Vec<String>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<VerificationResponse> {
        if pub_keys.is_empty() {
            return Err(anyhow!("Must provide at least one pub key"));
        }
        let result = self
            .verifier
            .verify_pub_key(self.docker_config.as_ref(), image, pub_keys, annotations)
            .await;

        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e),
        }
    }

    pub async fn verify_keyless(
        &mut self,
        image: String,
        keyless: Vec<KeylessInfo>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<VerificationResponse> {
        if keyless.is_empty() {
            return Err(anyhow!("Must provide keyless info"));
        }
        let result = self
            .verifier
            .verify_keyless_exact_match(self.docker_config.as_ref(), image, keyless, annotations)
            .await;

        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e),
        }
    }
}

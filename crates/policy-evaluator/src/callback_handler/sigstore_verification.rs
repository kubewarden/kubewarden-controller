use anyhow::{anyhow, Result};
use olpc_cjson::CanonicalFormatter;
use policy_fetcher::kubewarden_policy_sdk::host_capabilities::verification::LatestVerificationConfig;
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::{FulcioAndRekorData, Verifier};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::error;

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

    pub async fn is_trusted(&mut self, config: &IsTrustedSettings) -> Result<bool> {
        if !config.has_constraints() {
            return Err(anyhow!("Must provide value for at least all_of or any_of"));
        }
        let result = self
            .verifier
            .verify(
                config.image.as_str(),
                self.docker_config.as_ref(),
                &config.config,
            )
            .await;

        match result {
            Ok(_) => Ok(true),
            Err(e) => Err(e),
        }
    }
}

#[derive(Serialize, Debug)]
pub(crate) struct IsTrustedSettings {
    image: String,
    config: LatestVerificationConfig,
}

impl IsTrustedSettings {
    pub fn new(image: String, config: LatestVerificationConfig) -> Self {
        IsTrustedSettings { image, config }
    }

    pub fn has_constraints(&self) -> bool {
        self.config.all_of.is_some() || self.config.any_of.is_some()
    }

    // This function returns a hash of the IsTrustedSettings struct.
    // The has is computed by doing a canonical JSON representation of
    // the struct.
    //
    // This method cannot error, because its value is used by the `cached`
    // macro, which doesn't allow error handling.
    // Because of that the method will return the '0' value when something goes
    // wrong during the serialization operation. This is very unlikely to happen
    pub fn hash(&self) -> String {
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        if let Err(e) = self.serialize(&mut ser) {
            error!(err=?e, settings=?self, "Cannot perform canonical serialization");
            return "0".to_string();
        }

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        let result = hasher.finalize();
        result
            .iter()
            .map(|v| format!("{:x}", v))
            .collect::<Vec<String>>()
            .join("")
    }
}

use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::host_capabilities::verification::{
    KeylessInfo, KeylessPrefixInfo, VerificationResponse,
};
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::config::{LatestVerificationConfig, Signature, Subject};
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
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        for k in pub_keys.iter() {
            let signature = Signature::PubKey {
                owner: None,
                key: k.clone(),
                annotations: annotations.clone(),
            };
            signatures_all_of.push(signature);
        }
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        let result = self
            .verifier
            .verify(&image, self.docker_config.as_ref(), &verification_config)
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
        // Build interim VerificationConfig:
        //
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        for k in keyless.iter() {
            let signature = Signature::GenericIssuer {
                issuer: k.issuer.clone(),
                subject: Subject::Equal(k.subject.clone()),
                annotations: annotations.clone(),
            };
            signatures_all_of.push(signature);
        }
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        let result = self
            .verifier
            .verify(&image, self.docker_config.as_ref(), &verification_config)
            .await;
        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e),
        }
    }

    pub async fn verify_keyless_prefix(
        &mut self,
        image: String,
        keyless_prefix: Vec<KeylessPrefixInfo>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<VerificationResponse> {
        if keyless_prefix.is_empty() {
            return Err(anyhow!("Must provide keyless info"));
        }
        // Build interim VerificationConfig:
        //
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        for k in keyless_prefix.iter() {
            let prefix = url::Url::parse(&k.url_prefix).expect("Cannot build url prefix");
            let signature = Signature::GenericIssuer {
                issuer: k.issuer.clone(),
                subject: Subject::UrlPrefix(prefix),
                annotations: annotations.clone(),
            };
            signatures_all_of.push(signature);
        }
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        let result = self
            .verifier
            .verify(&image, self.docker_config.as_ref(), &verification_config)
            .await;
        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e),
        }
    }

    pub async fn verify_github_actions(
        &mut self,
        image: String,
        owner: String,
        repo: Option<String>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<VerificationResponse> {
        if owner.is_empty() {
            return Err(anyhow!("Must provide owner info"));
        }
        // Build interim VerificationConfig:
        //
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        let signature = Signature::GithubAction {
            owner: owner.clone(),
            repo: repo.clone(),
            annotations: annotations.clone(),
        };
        signatures_all_of.push(signature);
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        let result = self
            .verifier
            .verify(&image, self.docker_config.as_ref(), &verification_config)
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

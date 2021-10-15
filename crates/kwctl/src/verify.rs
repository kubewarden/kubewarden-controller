use anyhow::{anyhow, Result};
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::Verifier;
use std::io::prelude::*;
use std::{collections::HashMap, fs::File};

pub(crate) async fn verify(
    url: &str,
    docker_config: Option<DockerConfig>,
    sources: Option<Sources>,
    annotations: Option<HashMap<String, String>>,
    key_file: &str,
) -> Result<()> {
    let mut pub_key_file =
        File::open(key_file).map_err(|e| anyhow!("Cannot read verification key file: {:?}", e))?;
    let mut verification_key = String::new();
    pub_key_file
        .read_to_string(&mut verification_key)
        .map_err(|e| anyhow!("Error reading contents of verification key file {:?}", e))?;

    let mut verifier = Verifier::new(sources);
    verifier
        .verify(url, docker_config, annotations, &verification_key)
        .await?;

    println!("Policy successfully verified");
    Ok(())
}

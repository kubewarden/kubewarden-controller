use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::{collections::HashMap, convert::TryFrom};

#[derive(Deserialize, Debug)]
pub(crate) struct RegistryAuthRaw {
    auth: String,
}

#[derive(Deserialize, Debug)]
pub struct DockerConfigRaw {
    auths: HashMap<String, RegistryAuthRaw>,
}

#[derive(Clone, Debug)]
pub(crate) enum RegistryAuth {
    BasicAuth(Vec<u8>, Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct DockerConfig {
    pub(crate) auths: HashMap<String, RegistryAuth>,
}

impl From<DockerConfigRaw> for DockerConfig {
    fn from(docker_config: DockerConfigRaw) -> Self {
        DockerConfig {
            auths: docker_config
                .auths
                .into_iter()
                .filter_map(|(host, auth)| {
                    if let Ok(registry_auth) = RegistryAuth::try_from(auth) {
                        Some((host, registry_auth))
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}

impl TryFrom<RegistryAuthRaw> for RegistryAuth {
    type Error = anyhow::Error;

    fn try_from(auth: RegistryAuthRaw) -> Result<Self> {
        if let Ok(basic_auth) = base64::decode(auth.auth) {
            let splitted: Vec<&[u8]> = basic_auth.split(|c| *c == b':').collect();
            if splitted.len() == 2 {
                let (username, password) = (splitted[0], splitted[1]);
                Ok(RegistryAuth::BasicAuth(username.into(), password.into()))
            } else {
                Err(anyhow!("basic auth not in the form username:password"))
            }
        } else {
            Err(anyhow!("invalid base64 encoding"))
        }
    }
}

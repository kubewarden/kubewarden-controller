use anyhow::{anyhow, Result};
use oci_distribution::Reference;
use serde::Deserialize;
use std::{
    collections::HashMap, convert::TryFrom, convert::TryInto, fs::File, path::Path, str::FromStr,
};
use tracing::error;

#[derive(Deserialize, Debug)]
pub(crate) struct RegistryAuthRaw {
    // `auth` is optional because we have to be liberal on what we
    // accept: a tool or a user might change the configuration file in
    // disk and end up with a syntactically valid JSON, but
    // semantically invalid. Check:
    // https://github.com/kubernetes/kubectl/issues/571
    auth: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct DockerConfigRaw {
    auths: HashMap<String, RegistryAuthRaw>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RegistryAuth {
    BasicAuth(Vec<u8>, Vec<u8>),
}

impl TryFrom<RegistryAuth> for sigstore::registry::Auth {
    type Error = anyhow::Error;

    fn try_from(ra: RegistryAuth) -> Result<Self> {
        let RegistryAuth::BasicAuth(username, password) = ra;
        Ok(sigstore::registry::Auth::Basic(
            String::from_utf8(username).map_err(|e| anyhow!("username is not utf8: {:?}", e))?,
            String::from_utf8(password).map_err(|e| anyhow!("password is not utf8: {:?}", e))?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DockerConfig {
    pub auths: HashMap<String, RegistryAuth>,
}

impl DockerConfig {
    pub fn auth(&self, image_url: &str) -> Result<Option<RegistryAuth>> {
        let reference =
            Reference::from_str(image_url.strip_prefix("registry://").unwrap_or(image_url))?;

        Ok(self.auths.get(reference.registry()).cloned())
    }
}

impl TryFrom<DockerConfigRaw> for DockerConfig {
    type Error = anyhow::Error;

    fn try_from(docker_config: DockerConfigRaw) -> Result<Self> {
        Ok(DockerConfig {
            auths: docker_config
                .auths
                .into_iter()
                .filter_map(|(host, auth)| match OptionalRegistryAuth::try_from(auth) {
                    Ok(registry_auth) => registry_auth.map(|registry_auth| (host, registry_auth)),
                    Err(e) => {
                        error!(
                            host = %host,
                            error = %e,
                            "error parsing host configuration, host ignored",
                        );
                        None
                    }
                })
                .collect(),
        })
    }
}

type OptionalRegistryAuth = Option<RegistryAuth>;

impl TryFrom<RegistryAuthRaw> for OptionalRegistryAuth {
    type Error = anyhow::Error;

    fn try_from(auth: RegistryAuthRaw) -> Result<Self> {
        if let Some(auth) = auth.auth {
            if let Ok(basic_auth) = base64::decode(auth) {
                let splitted: Vec<&[u8]> = basic_auth.split(|c| *c == b':').collect();
                if splitted.len() == 2 {
                    let (username, password) = (splitted[0], splitted[1]);
                    Ok(Some(RegistryAuth::BasicAuth(
                        username.into(),
                        password.into(),
                    )))
                } else {
                    Err(anyhow!("basic auth not in the form username:password"))
                }
            } else {
                Err(anyhow!("invalid base64 encoding"))
            }
        } else {
            Ok(None)
        }
    }
}

pub fn read_docker_config_json_file(path: &Path) -> Result<DockerConfig> {
    serde_json::from_reader::<_, DockerConfigRaw>(File::open(path)?)?.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::FromIterator;

    #[test]
    fn test_missing_auth_key() -> Result<()> {
        let auths = vec![
            (
                "auth-registry.example.com".to_string(),
                RegistryAuthRaw {
                    // echo -n "username:password" | base64 -w0
                    auth: Some("dXNlcm5hbWU6cGFzc3dvcmQ=".to_string()),
                },
            ),
            (
                "authless-registry.example.com".to_string(),
                RegistryAuthRaw { auth: None },
            ),
        ];

        let docker_config: DockerConfig = DockerConfigRaw {
            auths: HashMap::from_iter(auths),
        }
        .try_into()?;

        assert_eq!(docker_config.auths.len(), 1);

        Ok(())
    }
}

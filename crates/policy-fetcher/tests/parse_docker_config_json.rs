mod common;

use common::test_data;
use policy_fetcher::registry::config::{DockerConfig, DockerConfigRaw, RegistryAuth};
use std::{collections::HashMap, convert::TryInto, iter::FromIterator, path::Path};

fn docker_config(test_data_file: &str) -> DockerConfig {
    let test_data_contents = test_data(Path::new(test_data_file));
    serde_json::from_str::<DockerConfigRaw>(&test_data_contents)
        .expect("could not unmarshal config file")
        .try_into()
        .expect("could not convert external config to internal type")
}

#[test]
fn parses_with_auth_present() {
    assert_eq!(
        docker_config("auth-present.json"),
        DockerConfig {
            auths: HashMap::from_iter(vec![(
                "https://index.docker.io/v1/".to_string(),
                RegistryAuth::BasicAuth("username".into(), "token".into())
            )])
        }
    )
}

#[test]
fn parses_with_some_auth_missing() {
    assert_eq!(
        docker_config("auth-some-missing.json"),
        DockerConfig {
            auths: HashMap::from_iter(vec![(
                "example.registry.com".to_string(),
                RegistryAuth::BasicAuth("username".into(), "token".into())
            ),])
        }
    )
}

#[test]
fn parses_with_invalid_base64() {
    assert_eq!(
        docker_config("auth-with-invalid-base64.json"),
        DockerConfig {
            auths: HashMap::from_iter(vec![(
                "valid-base64.registry.com".to_string(),
                RegistryAuth::BasicAuth("username".into(), "token".into())
            ),])
        }
    )
}

#[test]
fn parses_with_invalid_username_password() {
    assert_eq!(
        docker_config("auth-with-invalid-username-password.json"),
        DockerConfig {
            auths: HashMap::from_iter(vec![(
                "valid-username-password.registry.com".to_string(),
                RegistryAuth::BasicAuth("username".into(), "token".into())
            ),])
        }
    )
}

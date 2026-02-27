use std::{env, path::Path};

use anyhow::Result;
use clap::ArgMatches;
use policy_evaluator::policy_fetcher::{
    proxy::ProxyConfig,
    sources::{Sources, read_sources_file},
    store::DEFAULT_ROOT,
};
use tracing::warn;

const DOCKER_CONFIG_ENV_VAR: &str = "DOCKER_CONFIG";

pub(crate) fn remote_server_options(matches: &ArgMatches) -> Result<Option<Sources>> {
    let sources = if let Some(sources_path) = matches.get_one::<String>("sources-path") {
        Some(read_sources_file(Path::new(&sources_path))?)
    } else {
        let sources_path = DEFAULT_ROOT.config_dir().join("sources.yaml");
        if Path::exists(&sources_path) {
            Some(read_sources_file(&sources_path)?)
        } else {
            None
        }
    };

    // Inject proxy settings read from the environment so every HTTP client
    // inside policy-fetcher honours them without needing system-proxy feature.
    let sources = sources.map(|mut s| {
        s.proxies = Some(ProxyConfig::from_env());
        s
    });

    if let Some(docker_config_json_path) = matches.get_one::<String>("docker-config-json-path") {
        // docker_credential crate expects the config path in the $DOCKER_CONFIG. Keep docker-config-json-path parameter for backwards compatibility
        unsafe {
            env::set_var(DOCKER_CONFIG_ENV_VAR, docker_config_json_path);
        }
    }
    if let Ok(docker_config_path_str) = env::var(DOCKER_CONFIG_ENV_VAR) {
        let docker_config_path = Path::new(&docker_config_path_str).join("config.json");
        match docker_config_path.as_path().try_exists() {
            Ok(exist) => {
                if !exist {
                    warn!(
                        "Docker config file not found. Check if you are pointing to the directory containing the file. The file path should be {}.",
                        docker_config_path.display()
                    );
                }
            }
            Err(_) => {
                warn!(
                    "Docker config file not found. Check if you are pointing to the directory containing the file. The file path should be {}.",
                    docker_config_path.display()
                );
            }
        }
    }

    Ok(sources)
}

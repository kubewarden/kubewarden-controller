extern crate anyhow;
extern crate clap;
extern crate directories;
extern crate policy_evaluator;
extern crate policy_fetcher;
extern crate serde_yaml;

use anyhow::{anyhow, Result};
use clap::{
    clap_app, crate_authors, crate_description, crate_name, crate_version, AppSettings, ArgMatches,
};
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use policy_fetcher::registry::config::{DockerConfig, DockerConfigRaw};
use policy_fetcher::sources::{read_sources_file, Sources};
use policy_fetcher::store::DEFAULT_ROOT;
use policy_fetcher::PullDestination;

mod policies;
mod pull;
mod run;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = clap_app!(
        (crate_name!()) =>
            (version: crate_version!())
            (author: crate_authors!(",\n"))
            (about: crate_description!())
            (@subcommand policies =>
             (about: "Lists all downloaded policies")
            )
            (@subcommand pull =>
             (about: "Pulls a Kubewarden policy from a given URI")
             (@arg ("docker-config-json-path"): --("docker-config-json-path") +takes_value "Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
             (@arg ("sources-path"): --("sources-path") +takes_value "YAML file holding source information (https, registry insecure hosts, custom CA's...)")
             (@arg ("output-path"): -o --("output-path") +takes_value "Output file. If not provided will be downloaded to the Kubewarden store")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://, https://, file://")
            )
            (@subcommand run =>
             (about: "Runs a Kubewarden policy from a given URI")
             (@arg ("docker-config-json-path"): --("docker-config-json-path") +takes_value "Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
             (@arg ("sources-path"): --("sources-path") +takes_value "YAML file holding source information (https, registry insecure hosts, custom CA's...)")
             (@arg ("request-path"): * -r --("request-path") +takes_value "File containing the Kubernetes admission request object in JSON format")
             (@arg ("settings-path"): -s --("settings-path") +takes_value "File containing the settings for this policy")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://, https://, file://")
            )
    )
    .setting(AppSettings::SubcommandRequiredElseHelp)
    .get_matches();

    match matches.subcommand_name() {
        Some("policies") => {
            for policy in policies::list()? {
                println!("{}", policy);
            }
            Ok(())
        }
        Some("pull") => {
            if let Some(ref matches) = matches.subcommand_matches("pull") {
                let uri = matches.value_of("uri").unwrap();
                let destination = matches
                    .value_of("output-path")
                    .map(|output| PathBuf::from_str(output).unwrap());
                let destination = match destination {
                    Some(destination) => PullDestination::LocalFile(destination),
                    None => PullDestination::MainStore,
                };
                let (sources, docker_config) = pull_options(matches);
                pull::pull(uri, docker_config, sources, destination).await?;
            };
            Ok(())
        }
        Some("run") => {
            if let Some(ref matches) = matches.subcommand_matches("run") {
                let uri = matches.value_of("uri").unwrap();
                let request = fs::read_to_string(matches.value_of("request-path").unwrap())?;
                let settings = matches.value_of("settings-path")
                    .map(|settings| fs::read_to_string(settings).unwrap());
                let (sources, docker_config) = pull_options(matches);
                run::pull_and_run(uri, docker_config, sources, &request, settings).await?;
            }
            Ok(())
        }
        Some(command) => Err(anyhow!("unknown subcommand: {}", command)),
        None => {
            // NOTE: this should not happen due to
            // SubcommandRequiredElseHelp setting
            unreachable!();
        }
    }
}

fn pull_options(matches: &ArgMatches) -> (Option<Sources>, Option<DockerConfig>) {
    let sources = matches
        .value_of("sources-path")
        .and_then(|sources_path| read_sources_file(Path::new(sources_path)).ok())
        .or_else(|| read_sources_file(&DEFAULT_ROOT.config_dir().join("sources.yaml")).ok());

    let docker_config = matches
        .value_of("docker-config-json-path")
        .and_then(|docker_config_json_path| fs::read_to_string(&*docker_config_json_path).ok())
        .and_then(|contents| {
            serde_json::from_str(&contents)
                .map(|config: DockerConfigRaw| config.into())
                .ok()
        });

    (sources, docker_config)
}

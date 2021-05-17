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

use policy_fetcher::registry::config::{read_docker_config_json_file, DockerConfig};
use policy_fetcher::sources::{read_sources_file, Sources};
use policy_fetcher::store::DEFAULT_ROOT;
use policy_fetcher::PullDestination;

mod annotate;
mod constants;
mod inspect;
mod policies;
mod pull;
mod push;
mod rm;
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
            (@subcommand push =>
             (about: "Pushes a Kubewarden policy to an OCI registry")
             (@arg ("docker-config-json-path"): --("docker-config-json-path") +takes_value "Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
             (@arg ("policy-path"): * -p --("policy-path") +takes_value "Policy file to push")
             (@arg ("sources-path"): --("sources-path") +takes_value "YAML file holding source information (https, registry insecure hosts, custom CA's...)")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://")
            )
            (@subcommand rm =>
             (about: "Removes a Kubewarden policy from the store")
             (@arg ("uri"): * "Policy URI")
            )
            (@subcommand run =>
             (about: "Runs a Kubewarden policy from a given URI")
             (@arg ("docker-config-json-path"): --("docker-config-json-path") +takes_value "Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
             (@arg ("sources-path"): --("sources-path") +takes_value "YAML file holding source information (https, registry insecure hosts, custom CA's...)")
             (@arg ("request-path"): * -r --("request-path") +takes_value "File containing the Kubernetes admission request object in JSON format")
             (@arg ("settings-path"): -s --("settings-path") +takes_value "File containing the settings for this policy")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://, https://, file://")
            )
            (@subcommand annotate =>
             (about: "Add Kubewarden metadata to a WebAssembly module")
             (@arg ("metadata-path"): * -m --("metadata-path") +takes_value "File containing the metadata")
             (@arg ("wasm-path"): * "Path to WebAssembly module to be annotated")
             (@arg ("output-path"): * -o --("output-path") +takes_value "Output file")
            )
            (@subcommand inspect =>
             (about: "Inspect Kubewarden policy")
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
                let (sources, docker_config) = remote_server_options(matches)?;
                pull::pull(uri, docker_config, sources, destination).await?;
            };
            Ok(())
        }
        Some("push") => {
            if let Some(ref matches) = matches.subcommand_matches("push") {
                let (sources, docker_config) = remote_server_options(matches)?;
                let policy = fs::read(matches.value_of("policy-path").unwrap())?;
                let uri = matches.value_of("uri").unwrap();
                push::push(&policy, uri, docker_config, sources).await?;
            };
            Ok(())
        }
        Some("rm") => {
            if let Some(ref matches) = matches.subcommand_matches("rm") {
                let uri = matches.value_of("uri").unwrap();
                rm::rm(uri)?;
            }
            Ok(())
        }
        Some("run") => {
            if let Some(ref matches) = matches.subcommand_matches("run") {
                let uri = matches.value_of("uri").unwrap();
                let request = fs::read_to_string(matches.value_of("request-path").unwrap())?;
                let settings = matches
                    .value_of("settings-path")
                    .map(|settings| -> Result<String> { Ok(fs::read_to_string(settings)?) })
                    .transpose()?;
                let (sources, docker_config) = remote_server_options(matches)?;
                run::pull_and_run(uri, docker_config, sources, &request, settings).await?;
            }
            Ok(())
        }
        Some("annotate") => {
            if let Some(ref matches) = matches.subcommand_matches("annotate") {
                let wasm_path = matches
                    .value_of("wasm-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let metadata_file = matches
                    .value_of("metadata-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let destination = matches
                    .value_of("output-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                annotate::write_annotation(wasm_path, metadata_file, destination)?;
            }
            Ok(())
        }
        Some("inspect") => {
            if let Some(ref matches) = matches.subcommand_matches("inspect") {
                let uri = matches.value_of("uri").unwrap();
                inspect::inspect(uri)?;
            };
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

fn remote_server_options(matches: &ArgMatches) -> Result<(Option<Sources>, Option<DockerConfig>)> {
    let sources = if let Some(sources_path) = matches.value_of("sources-path") {
        Some(read_sources_file(Path::new(sources_path))?)
    } else {
        let sources_path = DEFAULT_ROOT.config_dir().join("sources.yaml");
        if Path::exists(&sources_path) {
            Some(read_sources_file(&sources_path)?)
        } else {
            None
        }
    };

    let docker_config =
        if let Some(docker_config_json_path) = matches.value_of("docker-config-json-path") {
            Some(read_docker_config_json_file(Path::new(
                docker_config_json_path,
            ))?)
        } else {
            let docker_config_json_path = DEFAULT_ROOT.config_dir().join("config.json");
            if Path::exists(&docker_config_json_path) {
                Some(read_docker_config_json_file(&docker_config_json_path)?)
            } else {
                None
            }
        };

    Ok((sources, docker_config))
}

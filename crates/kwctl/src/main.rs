extern crate anyhow;
extern crate clap;
extern crate directories;
extern crate policy_evaluator;
extern crate policy_fetcher;
extern crate pretty_bytes;
#[macro_use]
extern crate prettytable;
extern crate serde_yaml;
extern crate sha2;

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use directories::UserDirs;
use std::{
    convert::TryFrom,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

use tracing::debug;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use policy_evaluator::{policy_evaluator::PolicyExecutionMode, policy_metadata::Metadata};
use policy_fetcher::registry::config::{read_docker_config_json_file, DockerConfig};
use policy_fetcher::sources::{read_sources_file, Sources};
use policy_fetcher::store::DEFAULT_ROOT;
use policy_fetcher::PullDestination;

use crate::utils::new_policy_execution_mode_from_str;

mod annotate;
mod backend;
mod cli;
mod completions;
mod inspect;
mod manifest;
mod policies;
mod pull;
mod push;
mod rm;
mod run;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();

    // setup logging
    let level_filter = if matches.is_present("verbose") {
        "debug"
    } else {
        "info"
    };
    let filter_layer = EnvFilter::new(level_filter)
        .add_directive("cranelift_codegen=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("cranelift_wasm=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("regalloc=off".parse().unwrap()); // this crate generates lots of tracing events we don't care about
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    match matches.subcommand_name() {
        Some("policies") => policies::list(),
        Some("pull") => {
            if let Some(matches) = matches.subcommand_matches("pull") {
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
            if let Some(matches) = matches.subcommand_matches("push") {
                let (sources, docker_config) = remote_server_options(matches)?;
                let wasm_uri = crate::utils::map_path_to_uri(matches.value_of("policy").unwrap())?;
                let wasm_path = crate::utils::wasm_path(wasm_uri.as_str())?;
                let uri = matches
                    .value_of("uri")
                    .map(|u| {
                        if u.starts_with("registry://") {
                            String::from(u)
                        } else {
                            format!("registry://{}", u)
                        }
                    })
                    .unwrap();

                debug!(
                    policy = wasm_path.to_string_lossy().to_string().as_str(),
                    destination = uri.as_str(),
                    "policy push"
                );

                let policy = fs::read(&wasm_path)?;
                let force = matches.is_present("force");
                let metadata = Metadata::from_path(&wasm_path)?;
                if metadata.is_none() {
                    if force {
                        eprintln!("Warning: pushing a non-annotated policy!");
                    } else {
                        return Err(anyhow!("Cannot push a policy that is not annotated. Use `annotate` command or `push --force`"));
                    }
                }

                push::push(&policy, &uri, docker_config, sources).await?;
            };
            println!("Policy successfully pushed");
            Ok(())
        }
        Some("rm") => {
            if let Some(matches) = matches.subcommand_matches("rm") {
                let uri = matches.value_of("uri").unwrap();
                rm::rm(uri)?;
            }
            Ok(())
        }
        Some("run") => {
            if let Some(matches) = matches.subcommand_matches("run") {
                let uri = matches.value_of("uri").unwrap();
                let request = match matches.value_of("request-path").unwrap() {
                    "-" => {
                        let mut buffer = String::new();
                        io::stdin()
                            .read_to_string(&mut buffer)
                            .map_err(|e| anyhow!("Error reading request from stdin: {}", e))?;
                        buffer
                    }
                    request_path => fs::read_to_string(request_path).map_err(|e| {
                        anyhow!(
                            "Error opening request file {}; {}",
                            matches.value_of("request-path").unwrap(),
                            e
                        )
                    })?,
                };
                if matches.is_present("settings-path") && matches.is_present("settings-json") {
                    return Err(anyhow!(
                        "'settings-path' and 'settings-json' cannot be used at the same time"
                    ));
                }
                let settings = if matches.is_present("settings-path") {
                    matches
                        .value_of("settings-path")
                        .map(|settings| -> Result<String> {
                            fs::read_to_string(settings).map_err(|e| {
                                anyhow!("Error reading settings from {}: {}", settings, e)
                            })
                        })
                        .transpose()?
                } else if matches.is_present("settings-json") {
                    Some(String::from(matches.value_of("settings-json").unwrap()))
                } else {
                    None
                };
                let (sources, docker_config) = remote_server_options(matches)
                    .map_err(|e| anyhow!("Error getting remote server options: {}", e))?;
                let execution_mode: Option<PolicyExecutionMode> =
                    if let Some(mode_name) = matches.value_of("execution-mode") {
                        Some(new_policy_execution_mode_from_str(mode_name)?)
                    } else {
                        None
                    };
                run::pull_and_run(
                    uri,
                    execution_mode,
                    docker_config,
                    sources,
                    &request,
                    settings,
                )
                .await?;
            }
            Ok(())
        }
        Some("annotate") => {
            if let Some(matches) = matches.subcommand_matches("annotate") {
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
            if let Some(matches) = matches.subcommand_matches("inspect") {
                let uri = matches.value_of("uri").unwrap();
                let output = inspect::OutputType::try_from(matches.value_of("output"))?;

                inspect::inspect(uri, output)?;
            };
            Ok(())
        }
        Some("manifest") => {
            if let Some(matches) = matches.subcommand_matches("manifest") {
                let uri = matches.value_of("uri").unwrap();
                let resource_type = matches.value_of("type").unwrap();
                if matches.is_present("settings-path") && matches.is_present("settings-json") {
                    return Err(anyhow!(
                        "'settings-path' and 'settings-json' cannot be used at the same time"
                    ));
                }
                let settings = if matches.is_present("settings-path") {
                    matches
                        .value_of("settings-path")
                        .map(|settings| -> Result<String> {
                            fs::read_to_string(settings).map_err(|e| {
                                anyhow!("Error reading settings from {}: {}", settings, e)
                            })
                        })
                        .transpose()?
                } else if matches.is_present("settings-json") {
                    Some(String::from(matches.value_of("settings-json").unwrap()))
                } else {
                    None
                };

                manifest::manifest(uri, resource_type, settings)?;
            };
            Ok(())
        }
        Some("completions") => {
            if let Some(matches) = matches.subcommand_matches("completions") {
                let shell = match matches.value_of("shell").unwrap() {
                    "bash" => clap::Shell::Bash,
                    "fish" => clap::Shell::Fish,
                    "zsh" => clap::Shell::Zsh,
                    "elvish" => clap::Shell::Elvish,
                    "powershell" => clap::Shell::PowerShell,
                    unknown => {
                        eprintln!("Unknown shell '{}'", unknown);
                        std::process::exit(1);
                    }
                };
                completions::completions(&shell)?;
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
        } else if let Some(user_dir) = UserDirs::new() {
            let config_json_path = user_dir.home_dir().join(".docker").join("config.json");
            if Path::exists(&config_json_path) {
                Some(read_docker_config_json_file(&config_json_path)?)
            } else {
                None
            }
        } else {
            None
        };

    Ok((sources, docker_config))
}

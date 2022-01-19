extern crate anyhow;
extern crate clap;
extern crate directories;
extern crate policy_evaluator;
extern crate policy_fetcher;
extern crate pretty_bytes;
#[macro_use]
extern crate prettytable;
extern crate serde_yaml;

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use directories::UserDirs;
use std::{
    collections::HashMap,
    convert::TryFrom,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};
use verify::VerificationAnnotations;

use tracing::debug;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use policy_evaluator::policy_evaluator::PolicyExecutionMode;
use policy_fetcher::registry::config::{read_docker_config_json_file, DockerConfig};
use policy_fetcher::sources::{read_sources_file, Sources};
use policy_fetcher::store::DEFAULT_ROOT;
use policy_fetcher::PullDestination;

use sigstore::SigstoreOpts;

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
mod sigstore;
mod utils;
mod verify;

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
        .add_directive("hyper=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
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
                let (key_files, annotations) = verification_options(matches)?;
                let sigstore_options = sigstore_options(matches)?;

                let mut verified_manifest_digest: Option<String> = None;
                if let Some(ref sigstore_options) = sigstore_options {
                    // verify policy prior to pulling if keys listed, and keep the
                    // verified manifest digest of last iteration, even if all are
                    // the same:
                    if let Some(keys) = key_files {
                        for key in keys {
                            verified_manifest_digest = Some(
                                verify::verify(
                                    uri,
                                    docker_config.as_ref(),
                                    sources.as_ref(),
                                    annotations.as_ref(),
                                    &key,
                                    sigstore_options,
                                )
                                .await
                                .map_err(|e| {
                                    anyhow!(
                                        "Policy cannot be validated with key '{}': {:?}",
                                        key,
                                        e
                                    )
                                })?,
                            );
                        }
                    }
                }

                let policy =
                    pull::pull(uri, docker_config.as_ref(), sources.as_ref(), destination).await?;

                if let Some(ref sigstore_options) = sigstore_options {
                    if let Some(digest) = verified_manifest_digest {
                        verify::verify_local_checksum(
                            &policy,
                            docker_config.as_ref(),
                            sources.as_ref(),
                            &digest,
                            sigstore_options,
                        )
                        .await?
                    }
                }
            };
            Ok(())
        }
        Some("verify") => {
            if let Some(matches) = matches.subcommand_matches("verify") {
                let uri = matches.value_of("uri").unwrap();
                let (sources, docker_config) = remote_server_options(matches)?;
                let (key_files, annotations) = verification_options(matches)?;
                let sigstore_options = sigstore_options(matches)?
                    .ok_or(anyhow!("could not retrieve sigstore options"))?;

                match key_files {
                    Some(keys) => {
                        for key in keys {
                            verify::verify(
                                uri,
                                docker_config.as_ref(),
                                sources.as_ref(),
                                annotations.as_ref(),
                                &key,
                                &sigstore_options,
                            )
                            .await
                            .map_err(|e| {
                                anyhow!("Policy cannot be validated with key '{}': {:?}", key, e)
                            })?;
                        }
                    }
                    None => {
                        return Err(anyhow!("keyless verification not yet implemented"));
                    }
                }
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

                let force = matches.is_present("force");

                push::push(
                    wasm_path,
                    &uri,
                    docker_config.as_ref(),
                    sources.as_ref(),
                    force,
                )
                .await?;
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
                let (key_files, annotations) = verification_options(matches)?;
                let sigstore_options = sigstore_options(matches)?;

                let mut verified_manifest_digest: Option<String> = None;
                if let Some(ref sigstore_options) = sigstore_options {
                    // verify policy prior to pulling if keys listed, and keep the
                    // verified manifest digest of last iteration, even if all are
                    // the same:
                    if let Some(keys) = key_files {
                        for key in keys {
                            verified_manifest_digest = Some(
                                verify::verify(
                                    uri,
                                    docker_config.as_ref(),
                                    sources.as_ref(),
                                    annotations.as_ref(),
                                    &key,
                                    sigstore_options,
                                )
                                .await
                                .map_err(|e| {
                                    anyhow!(
                                        "Policy cannot be validated with key '{}': {:?}",
                                        key,
                                        e
                                    )
                                })?,
                            );
                        }
                    }
                }

                run::pull_and_run(
                    uri,
                    execution_mode,
                    docker_config.as_ref(),
                    sources.as_ref(),
                    &request,
                    settings,
                    &verified_manifest_digest,
                    sigstore_options.clone().as_ref(),
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
                let policy_title = matches.value_of("title");

                manifest::manifest(uri, resource_type, settings, policy_title.map(String::from))?;
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
        Some(read_sources_file(Path::new(&sources_path))?)
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

fn verification_options(
    matches: &ArgMatches,
) -> Result<(Option<Vec<String>>, Option<VerificationAnnotations>)> {
    let key_files: Option<Vec<String>>;
    key_files = matches
        .values_of("verification-key")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    let annotations: Option<VerificationAnnotations>;
    annotations = match matches.values_of("verification-annotation") {
        None => None,
        Some(items) => {
            let mut values: HashMap<String, String> = HashMap::new();
            for item in items {
                let tmp: Vec<_> = item.splitn(2, '=').collect();
                if tmp.len() == 2 {
                    values.insert(String::from(tmp[0]), String::from(tmp[1]));
                }
            }
            if values.is_empty() {
                None
            } else {
                Some(values)
            }
        }
    };

    if key_files.is_none() && annotations.is_some() {
        return Err(anyhow!(
            "Intending to verify annotations, but no verification keys were passed"
        ));
    }

    Ok((key_files, annotations))
}

fn sigstore_options(matches: &ArgMatches) -> Result<Option<SigstoreOpts>> {
    let fulcio_cert = if let Some(fulcio_cert_path) = matches.value_of("fulcio-cert-path") {
        Some(fs::read(fulcio_cert_path)?)
    } else if Path::exists(&cli::SIGSTORE_FULCIO_CERT_PATH) {
        Some(fs::read(&*cli::SIGSTORE_FULCIO_CERT_PATH)?)
    } else {
        None
    };

    let rekor_public_key =
        if let Some(rekor_public_key_path) = matches.value_of("rekor-public-key-path") {
            Some(fs::read(rekor_public_key_path)?)
        } else if Path::exists(&cli::SIGSTORE_REKOR_PUBLIC_KEY_PATH) {
            Some(fs::read(&*cli::SIGSTORE_REKOR_PUBLIC_KEY_PATH)?)
        } else {
            None
        };

    if fulcio_cert.is_none() && rekor_public_key.is_none() {
        return Ok(None);
    }

    if fulcio_cert.is_none() || rekor_public_key.is_none() {
        return Err(anyhow!(
            "both a fulcio certificate and a rekor public key are required, these can be generated by using the `cosign initialize` command"
        ));
    }

    Ok(Some(SigstoreOpts {
        fulcio_cert: fulcio_cert.unwrap(),
        rekor_public_key: String::from_utf8(rekor_public_key.unwrap())?,
    }))
}

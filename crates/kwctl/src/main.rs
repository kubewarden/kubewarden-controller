extern crate anyhow;
extern crate clap;
extern crate directories;
extern crate policy_evaluator;
extern crate pretty_bytes;
#[macro_use]
extern crate prettytable;
extern crate serde_yaml;

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use itertools::Itertools;
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    convert::TryFrom,
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

use tokio::task::spawn_blocking;
use verify::VerificationAnnotations;

use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
};

use crate::load::load;
use crate::save::save;
use policy_evaluator::policy_evaluator::PolicyExecutionMode;
use policy_evaluator::policy_fetcher::{
    registry::Registry,
    sigstore,
    sources::{read_sources_file, Certificate, Sources},
    store::DEFAULT_ROOT,
    verify::{
        config::{read_verification_file, LatestVerificationConfig, Signature, Subject},
        FulcioAndRekorData,
    },
    PullDestination,
};

use crate::utils::new_policy_execution_mode_from_str;

mod annotate;
mod backend;
mod bench;
mod cli;
mod completions;
mod info;
mod inspect;
mod load;
mod policies;
mod pull;
mod push;
mod rm;
mod run;
mod save;
mod scaffold;
mod utils;
mod verify;

pub(crate) const KWCTL_VERIFICATION_CONFIG: &str = "verification-config.yml";
const DOCKER_CONFIG_ENV_VAR: &str = "DOCKER_CONFIG";

lazy_static! {
    pub(crate) static ref KWCTL_DEFAULT_VERIFICATION_CONFIG_PATH: String = {
        DEFAULT_ROOT
            .config_dir()
            .join(KWCTL_VERIFICATION_CONFIG)
            .display()
            .to_string()
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();

    // setup logging
    let verbose = matches
        .get_one::<bool>("verbose")
        .unwrap_or(&false)
        .to_owned();
    let level_filter = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let filter_layer = EnvFilter::from_default_env()
        .add_directive(level_filter.into())
        .add_directive("cranelift_codegen=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("cranelift_wasm=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("hyper=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("regalloc=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("wasmtime_cache=off".parse().unwrap()); // wasmtime_cache messages are not critical and just confuse users
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    match matches.subcommand_name() {
        Some("policies") => policies::list(),
        Some("info") => info::info(),
        Some("pull") => {
            if let Some(matches) = matches.subcommand_matches("pull") {
                let uri = matches.get_one::<String>("uri").unwrap();
                let destination = matches
                    .get_one::<String>("output-path")
                    .map(|output| PathBuf::from_str(output).unwrap());
                let destination = match destination {
                    Some(destination) => PullDestination::LocalFile(destination),
                    None => PullDestination::MainStore,
                };

                let sources = remote_server_options(matches)?;

                let verification_options = verification_options(matches)?;
                let mut verified_manifest_digest: Option<String> = None;
                if verification_options.is_some() {
                    let fulcio_and_rekor_data = build_fulcio_and_rekor_data(matches).await?;
                    // verify policy prior to pulling if keys listed, and keep the
                    // verified manifest digest:
                    verified_manifest_digest = Some(
                        verify::verify(
                            uri,
                            sources.as_ref(),
                            verification_options.as_ref().unwrap(),
                            fulcio_and_rekor_data.as_ref(),
                        )
                        .await
                        .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?,
                    );
                }

                let policy = pull::pull(uri, sources.as_ref(), destination).await?;

                if verification_options.is_some() {
                    let fulcio_and_rekor_data = build_fulcio_and_rekor_data(matches).await?;
                    verify::verify_local_checksum(
                        &policy,
                        sources.as_ref(),
                        &verified_manifest_digest.unwrap(),
                        fulcio_and_rekor_data.as_ref(),
                    )
                    .await?
                }
            };
            Ok(())
        }
        Some("verify") => {
            if let Some(matches) = matches.subcommand_matches("verify") {
                let uri = matches.get_one::<String>("uri").unwrap();
                let sources = remote_server_options(matches)?;
                let verification_options = verification_options(matches)?
                    .ok_or_else(|| anyhow!("could not retrieve sigstore options"))?;
                let fulcio_and_rekor_data = build_fulcio_and_rekor_data(matches).await?;
                verify::verify(
                    uri,
                    sources.as_ref(),
                    &verification_options,
                    fulcio_and_rekor_data.as_ref(),
                )
                .await
                .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?;
            };
            Ok(())
        }
        Some("push") => {
            if let Some(matches) = matches.subcommand_matches("push") {
                let sources = remote_server_options(matches)?;
                let wasm_uri =
                    crate::utils::map_path_to_uri(matches.get_one::<String>("policy").unwrap())?;
                let wasm_path = crate::utils::wasm_path(wasm_uri.as_str())?;
                let uri = matches
                    .get_one::<String>("uri")
                    .map(|u| {
                        if u.starts_with("registry://") {
                            u.clone()
                        } else {
                            format!("registry://{u}")
                        }
                    })
                    .unwrap();

                debug!(
                    policy = wasm_path.to_string_lossy().to_string().as_str(),
                    destination = uri.as_str(),
                    "policy push"
                );

                let force = matches.contains_id("force");

                let immutable_ref = push::push(wasm_path, &uri, sources.as_ref(), force).await?;

                match matches.get_one::<String>("output").map(|s| s.as_str()) {
                    Some("json") => {
                        let mut response: HashMap<&str, String> = HashMap::new();
                        response.insert("immutable_ref", immutable_ref);
                        serde_json::to_writer(std::io::stdout(), &response)?
                    }
                    _ => {
                        println!("Policy successfully pushed: {immutable_ref}");
                    }
                }
            };
            Ok(())
        }
        Some("rm") => {
            if let Some(matches) = matches.subcommand_matches("rm") {
                let uri = matches.get_one::<String>("uri").unwrap();
                rm::rm(uri)?;
            }
            Ok(())
        }
        Some("run") => {
            if let Some(matches) = matches.subcommand_matches("run") {
                let pull_and_run_settings = parse_pull_and_run_settings(matches).await?;
                run::pull_and_run(&pull_and_run_settings).await?;
            }
            Ok(())
        }
        Some("bench") => {
            if let Some(matches) = matches.subcommand_matches("bench") {
                use std::time::Duration;

                let pull_and_run_settings = parse_pull_and_run_settings(matches).await?;
                let mut benchmark_cfg = tiny_bench::BenchmarkConfig::default();

                if let Some(measurement_time) = matches.get_one::<String>("measurement_time") {
                    let duration: u64 = measurement_time.parse().map_err(|e| {
                        anyhow!("Cannot convert 'measurement-time' to seconds: {:?}", e)
                    })?;
                    benchmark_cfg.measurement_time = Duration::from_secs(duration);
                }
                if let Some(num_resamples) = matches.get_one::<String>("num_resamples") {
                    let num: usize = num_resamples.parse().map_err(|e| {
                        anyhow!("Cannot convert 'num-resamples' to number: {:?}", e)
                    })?;
                    benchmark_cfg.num_resamples = num;
                }
                if let Some(num_samples) = matches.get_one::<String>("num_samples") {
                    let num: usize = num_samples
                        .parse()
                        .map_err(|e| anyhow!("Cannot convert 'num-samples' to number: {:?}", e))?;
                    benchmark_cfg.num_resamples = num;
                }
                if let Some(warm_up_time) = matches.get_one::<String>("warm_up_time") {
                    let duration: u64 = warm_up_time.parse().map_err(|e| {
                        anyhow!("Cannot convert 'warm-up-time' to seconds: {:?}", e)
                    })?;
                    benchmark_cfg.warm_up_time = Duration::from_secs(duration);
                }
                benchmark_cfg.dump_results_to_disk = matches.contains_id("dump_results_to_disk");

                bench::pull_and_bench(&bench::PullAndBenchSettings {
                    pull_and_run_settings,
                    benchmark_cfg,
                })
                .await?;
            }
            Ok(())
        }
        Some("annotate") => {
            if let Some(matches) = matches.subcommand_matches("annotate") {
                let wasm_path = matches
                    .get_one::<String>("wasm-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let metadata_file = matches
                    .get_one::<String>("metadata-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let destination = matches
                    .get_one::<String>("output-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let usage_file = matches
                    .get_one::<String>("usage-path")
                    .map(|output| PathBuf::from_str(output).unwrap());
                annotate::write_annotation(wasm_path, metadata_file, destination, usage_file)?;
            }
            Ok(())
        }
        Some("inspect") => {
            if let Some(matches) = matches.subcommand_matches("inspect") {
                let uri = matches.get_one::<String>("uri").unwrap();
                let output = inspect::OutputType::try_from(
                    matches.get_one::<String>("output").map(|s| s.as_str()),
                )?;
                let sources = remote_server_options(matches)?;

                inspect::inspect(uri, output, sources).await?;
            };
            Ok(())
        }
        Some("scaffold") => {
            if let Some(matches) = matches.subcommand_matches("scaffold") {
                if let Some(_matches) = matches.subcommand_matches("verification-config") {
                    println!("{}", scaffold::verification_config()?);
                }
            }
            if let Some(matches) = matches.subcommand_matches("scaffold") {
                if let Some(artifacthub_matches) = matches.subcommand_matches("artifacthub") {
                    let metadata_file = artifacthub_matches
                        .get_one::<String>("metadata-path")
                        .map(|output| PathBuf::from_str(output).unwrap())
                        .unwrap();
                    let version = artifacthub_matches.get_one::<String>("version").unwrap();
                    let questions_file = artifacthub_matches
                        .get_one::<String>("questions-path")
                        .map(|output| PathBuf::from_str(output).unwrap());
                    println!(
                        "{}",
                        scaffold::artifacthub(metadata_file, version, questions_file)?
                    );
                }
            }
            if let Some(matches) = matches.subcommand_matches("scaffold") {
                if let Some(matches) = matches.subcommand_matches("manifest") {
                    let uri = matches.get_one::<String>("uri").unwrap();
                    let resource_type = matches.get_one::<String>("type").unwrap();
                    if matches.contains_id("settings-path") && matches.contains_id("settings-json")
                    {
                        return Err(anyhow!(
                            "'settings-path' and 'settings-json' cannot be used at the same time"
                        ));
                    }
                    let settings = if matches.contains_id("settings-path") {
                        matches
                            .get_one::<String>("settings-path")
                            .map(|settings| -> Result<String> {
                                fs::read_to_string(settings).map_err(|e| {
                                    anyhow!("Error reading settings from {}: {}", settings, e)
                                })
                            })
                            .transpose()?
                    } else if matches.contains_id("settings-json") {
                        Some(matches.get_one::<String>("settings-json").unwrap().clone())
                    } else {
                        None
                    };
                    let policy_title = matches.get_one::<String>("title").cloned();

                    let allow_context_aware_resources = matches
                        .get_one::<bool>("allow-context-aware")
                        .unwrap_or(&false)
                        .to_owned();

                    scaffold::manifest(
                        uri,
                        resource_type.parse()?,
                        settings.as_deref(),
                        policy_title.as_deref(),
                        allow_context_aware_resources,
                    )?;
                };
            }
            Ok(())
        }
        Some("completions") => {
            if let Some(matches) = matches.subcommand_matches("completions") {
                completions::completions(matches.get_one::<String>("shell").unwrap())?;
            }
            Ok(())
        }
        Some("digest") => {
            if let Some(matches) = matches.subcommand_matches("digest") {
                let uri = matches.get_one::<String>("uri").unwrap();
                let sources = remote_server_options(matches)?;
                let registry = Registry::new();
                let digest = registry.manifest_digest(uri, sources.as_ref()).await?;
                println!("{uri}@{digest}");
            }
            Ok(())
        }
        Some("save") => {
            if let Some(matches) = matches.subcommand_matches("save") {
                let policies = matches.get_many::<String>("policies").unwrap();
                let output = matches.get_one::<String>("output").unwrap();

                save(policies.collect_vec(), output)?;
            }
            Ok(())
        }
        Some("load") => {
            if let Some(matches) = matches.subcommand_matches("load") {
                let input = matches.get_one::<String>("input").unwrap();
                load(input)?;
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

fn remote_server_options(matches: &ArgMatches) -> Result<Option<Sources>> {
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

    if let Some(docker_config_json_path) = matches.get_one::<String>("docker-config-json-path") {
        // docker_credential crate expects the config path in the $DOCKER_CONFIG. Keep docker-config-json-path parameter for backwards compatibility
        env::set_var(DOCKER_CONFIG_ENV_VAR, docker_config_json_path);
    }

    Ok(sources)
}

fn verification_options(matches: &ArgMatches) -> Result<Option<LatestVerificationConfig>> {
    if let Some(verification_config) = build_verification_options_from_flags(matches)? {
        // flags present, built configmap from them:
        if matches.contains_id("verification-config-path") {
            return Err(anyhow!(
                "verification-config-path cannot be used in conjunction with other verification flags"
            ));
        }
        return Ok(Some(verification_config));
    }
    if let Some(verification_config_path) = matches.get_one::<String>("verification-config-path") {
        // config flag present, read it:
        Ok(Some(read_verification_file(Path::new(
            &verification_config_path,
        ))?))
    } else {
        let verification_config_path = DEFAULT_ROOT.config_dir().join(KWCTL_VERIFICATION_CONFIG);
        if Path::exists(&verification_config_path) {
            // default config flag present, read it:
            info!(path = ?verification_config_path, "Default verification config present, using it");
            Ok(Some(read_verification_file(&verification_config_path)?))
        } else {
            Ok(None)
        }
    }
}

/// Takes clap flags and builds a Some(LatestVerificationConfig) containing all
/// passed pub keys and annotations in LatestVerificationConfig.AllOf.
/// If no verification flags where used, it returns a None.
fn build_verification_options_from_flags(
    matches: &ArgMatches,
) -> Result<Option<LatestVerificationConfig>> {
    let key_files: Option<Vec<String>> = matches
        .get_many::<String>("verification-key")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    let annotations: Option<VerificationAnnotations> =
        match matches.get_many::<String>("verification-annotation") {
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

    let cert_email: Option<String> = matches
        .get_many::<String>("cert-email")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());
    let cert_oidc_issuer: Option<String> = matches
        .get_many::<String>("cert-oidc-issuer")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    let github_owner: Option<String> = matches
        .get_many::<String>("github-owner")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());
    let github_repo: Option<String> = matches
        .get_many::<String>("github-repo")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    if key_files.is_none()
        && annotations.is_none()
        && cert_email.is_none()
        && cert_oidc_issuer.is_none()
        && github_owner.is_none()
        && github_repo.is_none()
    {
        // no verification flags were used, don't create a LatestVerificationConfig
        return Ok(None);
    }

    if key_files.is_none()
        && cert_email.is_none()
        && cert_oidc_issuer.is_none()
        && github_owner.is_none()
        && annotations.is_some()
    {
        return Err(anyhow!(
            "Intending to verify annotations, but no verification keys, OIDC issuer or GitHub owner were passed"
        ));
    }

    if github_repo.is_some() && github_owner.is_none() {
        return Err(anyhow!(
            "Intending to verify GitHub actions signature, but the repository owner is missing."
        ));
    }

    let mut signatures: Vec<Signature> = Vec::new();

    if (cert_email.is_some() && cert_oidc_issuer.is_none())
        || (cert_email.is_none() && cert_oidc_issuer.is_some())
    {
        return Err(anyhow!(
            "Intending to verify OIDC issuer, but no email or issuer were provided. You must pass the email and OIDC issuer to be validated together "
        ));
    } else if cert_email.is_some() && cert_oidc_issuer.is_some() {
        let sig = Signature::GenericIssuer {
            issuer: cert_oidc_issuer.unwrap(),
            subject: Subject::Equal(cert_email.unwrap()),
            annotations: annotations.clone(),
        };
        signatures.push(sig)
    }

    if let Some(repo_owner) = github_owner {
        let sig = Signature::GithubAction {
            owner: repo_owner,
            repo: github_repo,
            annotations: annotations.clone(),
        };
        signatures.push(sig)
    }

    for key_path in key_files.iter().flatten() {
        let sig = Signature::PubKey {
            owner: None,
            key: fs::read_to_string(key_path)
                .map_err(|e| anyhow!("could not read file {}: {:?}", key_path, e))?
                .to_string(),
            annotations: annotations.clone(),
        };
        signatures.push(sig);
    }
    let signatures_all_of: Option<Vec<Signature>> = if signatures.is_empty() {
        None
    } else {
        Some(signatures)
    };
    let verification_config = LatestVerificationConfig {
        all_of: signatures_all_of,
        any_of: None,
    };
    Ok(Some(verification_config))
}

/// Takes clap flags and builds a Result<run::PullAndRunSettings> instance
async fn parse_pull_and_run_settings(matches: &ArgMatches) -> Result<run::PullAndRunSettings> {
    let uri = matches.get_one::<String>("uri").unwrap();
    let request = match matches
        .get_one::<String>("request-path")
        .map(|s| s.as_str())
        .unwrap()
    {
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
                matches.get_one::<String>("request-path").unwrap(),
                e
            )
        })?,
    };
    if matches.contains_id("settings-path") && matches.contains_id("settings-json") {
        return Err(anyhow!(
            "'settings-path' and 'settings-json' cannot be used at the same time"
        ));
    }
    let settings = if matches.contains_id("settings-path") {
        matches
            .get_one::<String>("settings-path")
            .map(|settings| -> Result<String> {
                fs::read_to_string(settings)
                    .map_err(|e| anyhow!("Error reading settings from {}: {}", settings, e))
            })
            .transpose()?
    } else if matches.contains_id("settings-json") {
        Some(matches.get_one::<String>("settings-json").unwrap().clone())
    } else {
        None
    };
    let sources = remote_server_options(matches)
        .map_err(|e| anyhow!("Error getting remote server options: {}", e))?;
    let execution_mode: Option<PolicyExecutionMode> =
        if let Some(mode_name) = matches.get_one::<String>("execution-mode") {
            Some(new_policy_execution_mode_from_str(mode_name)?)
        } else {
            None
        };

    let verification_options = verification_options(matches)?;
    let mut verified_manifest_digest: Option<String> = None;
    let fulcio_and_rekor_data = build_fulcio_and_rekor_data(matches).await?;
    if verification_options.is_some() {
        // verify policy prior to pulling if keys listed, and keep the
        // verified manifest digest:
        verified_manifest_digest = Some(
            verify::verify(
                uri,
                sources.as_ref(),
                verification_options.as_ref().unwrap(),
                fulcio_and_rekor_data.as_ref(),
            )
            .await
            .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?,
        );
    }

    let enable_wasmtime_cache = !matches
        .get_one::<bool>("disable-wasmtime-cache")
        .unwrap_or(&false)
        .to_owned();

    let allow_context_aware_resources = matches
        .get_one::<bool>("allow-context-aware")
        .unwrap_or(&false)
        .to_owned();

    Ok(run::PullAndRunSettings {
        uri: uri.to_owned(),
        user_execution_mode: execution_mode,
        sources,
        request,
        settings,
        verified_manifest_digest,
        fulcio_and_rekor_data,
        enable_wasmtime_cache,
        allow_context_aware_resources,
    })
}

async fn build_fulcio_and_rekor_data(matches: &ArgMatches) -> Result<Option<FulcioAndRekorData>> {
    if matches.contains_id("fulcio-cert-path") || matches.contains_id("rekor-public-key-path") {
        let mut fulcio_certs: Vec<Certificate> = vec![];
        if let Some(items) = matches.get_many::<String>("fulcio-cert-path") {
            for item in items {
                let data = fs::read(item)?;
                let cert = Certificate::Pem(data);
                fulcio_certs.push(cert);
            }
        };

        let rekor_public_key = if let Some(rekor_public_key_path) =
            matches.get_one::<String>("rekor-public-key-path")
        {
            Some(fs::read_to_string(rekor_public_key_path)?)
        } else {
            None
        };

        if fulcio_certs.is_empty() || rekor_public_key.is_none() {
            return Err(anyhow!(
                "both a fulcio certificate and a rekor public key are required"
            ));
        }

        Ok(Some(FulcioAndRekorData::FromCustomData {
            fulcio_certs,
            rekor_public_key,
        }))
    } else {
        let checkout_path = DEFAULT_ROOT.config_dir().join("fulcio_and_rekor_data");
        if !Path::exists(&checkout_path) {
            fs::create_dir_all(checkout_path.clone())?
        }

        let repo =
            spawn_blocking(move || sigstore::tuf::SigstoreRepository::fetch(Some(&checkout_path)))
                .await?;
        match repo {
            Ok(repo) => Ok(Some(FulcioAndRekorData::FromTufRepository { repo })),
            Err(e) => {
                warn!("Cannot fetch TUF repository: {:?}", e);
                // policy-fetcher will print the needed follow-up warning messages
                Ok(None)
            }
        }
    }
}

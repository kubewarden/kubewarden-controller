use anyhow::{anyhow, Result};
use clap::{crate_authors, crate_name, crate_version, Arg, Command};
use serde_json::json;
use std::{fs::File, io::BufReader, path::PathBuf, process};

use tracing::debug;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

mod opa;
use opa::wasm::Evaluator;

pub(crate) fn build_cli() -> Command<'static> {
    Command::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .about("evaluate a OPA policy")
        .arg(
            Arg::new("verbose")
                .short('v')
                .takes_value(false)
                .help("Increase verbosity"),
        )
        .subcommand(
            Command::new("eval")
                .about("evaluate a OPA policy")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .long("input")
                        .takes_value(true)
                        .help("JSON string with the input"),
                )
                .arg(
                    Arg::new("input-path")
                        .long("input-path")
                        .takes_value(true)
                        .help("path to the file containing the JSON input"),
                )
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .takes_value(true)
                        .help("JSON string with the data"),
                )
                .arg(
                    Arg::new("entrypoint")
                        .short('e')
                        .long("entrypoint")
                        .takes_value(true)
                        .help("OPA entrypoint to evaluate"),
                )
                .arg(
                    Arg::new("policy")
                        .required(true)
                        .index(1)
                        .help("Path to the wasm file containing the policy"),
                ),
        )
        .subcommand(Command::new("builtins").about("List the supported builtins"))
        .arg_required_else_help(true)
}

fn main() -> Result<()> {
    let matches = build_cli().get_matches();

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
        Some("builtins") => {
            println!("These are the OPA builtins currently supported:");
            for b in Evaluator::implemented_builtins() {
                println!("  - {}", b);
            }
            Ok(())
        }
        Some("eval") => {
            if let Some(matches) = matches.subcommand_matches("eval") {
                if matches.is_present("input") && matches.is_present("input-path") {
                    return Err(anyhow!(
                        "Cannot use 'input' and 'input-path' at the same time"
                    ));
                }
                let input: serde_json::Value = if matches.is_present("input") {
                    serde_json::from_str(matches.value_of("input").unwrap())
                        .map_err(|e| anyhow!("Cannot parse input: {:?}", e))?
                } else if matches.is_present("input-path") {
                    let file = File::open(matches.value_of("input-path").unwrap())
                        .map_err(|e| anyhow!("Cannot read input file: {:?}", e))?;
                    let reader = BufReader::new(file);
                    serde_json::from_reader(reader)?
                } else {
                    json!({})
                };

                let data: serde_json::Value = matches
                    .value_of("data")
                    .or(Some("{}"))
                    .map(|d| {
                        serde_json::from_str(d).map_err(|e| anyhow!("Cannot parse data: {:?}", e))
                    })
                    .unwrap()?;

                let policy = matches.value_of("policy").unwrap();
                let mut evaluator = Evaluator::from_path(
                    policy.to_string(),
                    &PathBuf::from(policy),
                    &opa::host_callbacks::DEFAULT_HOST_CALLBACKS,
                )?;

                let (major, minor) = evaluator.opa_abi_version()?;
                debug!(major, minor, "OPA Wasm ABI");

                let not_implemented_builtins = evaluator.not_implemented_builtins()?;
                if !not_implemented_builtins.is_empty() {
                    eprintln!("Cannot evaluate policy, these builtins are not yet implemented:");
                    for b in not_implemented_builtins {
                        eprintln!("  - {}", b);
                    }
                    process::exit(1);
                }

                let entrypoint = matches.value_of("entrypoint").or(Some("0")).unwrap();
                let entrypoint_id = match entrypoint.parse() {
                    Ok(id) => id,
                    _ => evaluator.entrypoint_id(&String::from(entrypoint))?,
                };

                let evaluation_res = evaluator.evaluate(entrypoint_id, &input, &data)?;
                println!("{}", serde_json::to_string_pretty(&evaluation_res)?);
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

use anyhow::{anyhow, Result};
use clap::{clap_app, crate_authors, crate_description, crate_name, crate_version, AppSettings};
use serde_json::json;
use std::{fs::File, io::BufReader, process};

use tracing::debug;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

mod opa;
use opa::wasm::Evaluator;

fn main() -> Result<()> {
    let matches = clap_app!(
    (crate_name!()) =>
        (version: crate_version!())
        (author: crate_authors!(",\n"))
        (about: crate_description!())
        (@arg verbose: -v "Increase verbosity")
        (@subcommand eval =>
            (about: "evaluate a OPA policy")
            (@arg ("input"): -i --("input") +takes_value "JSON string with the input")
            (@arg ("input-path"): --("input-path") +takes_value "path to the file containing the JSON input")
            (@arg ("data"): -d --("data") +takes_value "JSON string with the data")
            (@arg ("entrypoint"): -e --("entrypoint") +takes_value "OPA entrypoint to evaluate")
            (@arg ("policy"): * "Path to the wasm file containing the policy")
        )
        (@subcommand builtins =>
            (about: "List the supported builtins")
        )
    )
    .setting(AppSettings::SubcommandRequiredElseHelp)
    .get_matches();

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
            if let Some(ref matches) = matches.subcommand_matches("eval") {
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

                let mut evaluator = Evaluator::new(matches.value_of("policy").unwrap())?;

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

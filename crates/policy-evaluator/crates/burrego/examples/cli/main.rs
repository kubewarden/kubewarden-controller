use anyhow::{anyhow, Result};

use serde_json::json;
use std::{fs::File, io::BufReader, path::PathBuf, process};

use tracing::debug;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

extern crate burrego;
use burrego::opa::wasm::Evaluator;

extern crate clap;
use clap::Parser;

#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub(crate) struct Cli {
    /// Enable verbose mode
    #[clap(short, long, value_parser)]
    verbose: bool,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Commands {
    /// Evaluate a Rego policy compiled to WebAssembly
    Eval {
        /// JSON string with the input
        #[clap(short, long, value_name = "JSON", value_parser)]
        input: Option<String>,

        /// Path to file containing the JSON input
        #[clap(long, value_name = "JSON_FILE", value_parser)]
        input_path: Option<String>,

        /// JSON string with the data
        #[clap(short, long, value_name = "JSON", default_value = "{}", value_parser)]
        data: String,

        /// OPA entrypoint to evaluate
        #[clap(
            short,
            long,
            value_name = "ENTRYPOINT_ID",
            default_value = "0",
            value_parser
        )]
        entrypoint: String,

        /// Path to WebAssembly module to load
        #[clap(value_parser, value_name = "WASM_FILE", value_parser)]
        policy: String,
    },
    /// List the supported builtins
    Builtins,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // setup logging
    let level_filter = if cli.verbose { "debug" } else { "info" };
    let filter_layer = EnvFilter::new(level_filter)
        .add_directive("cranelift_codegen=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("cranelift_wasm=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("regalloc=off".parse().unwrap()); // this crate generates lots of tracing events we don't care about
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    match &cli.command {
        Commands::Builtins => {
            println!("These are the OPA builtins currently supported:");
            for b in Evaluator::implemented_builtins() {
                println!("  - {}", b);
            }
            Ok(())
        }
        Commands::Eval {
            input,
            input_path,
            data,
            entrypoint,
            policy,
        } => {
            if input.is_some() && input_path.is_some() {
                return Err(anyhow!(
                    "Cannot use 'input' and 'input-path' at the same time"
                ));
            }
            let input_value: serde_json::Value = if let Some(input_json) = input {
                serde_json::from_str(&input_json)
                    .map_err(|e| anyhow!("Cannot parse input: {:?}", e))?
            } else if let Some(input_filename) = input_path {
                let file = File::open(input_filename)
                    .map_err(|e| anyhow!("Cannot read input file: {:?}", e))?;
                let reader = BufReader::new(file);
                serde_json::from_reader(reader)?
            } else {
                json!({})
            };

            let data_value: serde_json::Value =
                serde_json::from_str(&data).map_err(|e| anyhow!("Cannot parse data: {:?}", e))?;

            let mut evaluator = Evaluator::from_path(
                policy.clone(),
                &PathBuf::from(policy),
                &burrego::opa::host_callbacks::DEFAULT_HOST_CALLBACKS,
            )?;

            let (major, minor) = evaluator.opa_abi_version()?;
            debug!(major, minor, "OPA Wasm ABI");

            let entrypoints = evaluator.entrypoints()?;
            debug!(?entrypoints, "OPA entrypoints");

            let not_implemented_builtins = evaluator.not_implemented_builtins()?;
            if !not_implemented_builtins.is_empty() {
                eprintln!("Cannot evaluate policy, these builtins are not yet implemented:");
                for b in not_implemented_builtins {
                    eprintln!("  - {}", b);
                }
                process::exit(1);
            }

            let entrypoint_id = match entrypoint.parse() {
                Ok(id) => id,
                _ => evaluator.entrypoint_id(&String::from(entrypoint))?,
            };

            let evaluation_res = evaluator.evaluate(entrypoint_id, &input_value, &data_value)?;
            println!("{}", serde_json::to_string_pretty(&evaluation_res)?);
            Ok(())
        }
    }
}

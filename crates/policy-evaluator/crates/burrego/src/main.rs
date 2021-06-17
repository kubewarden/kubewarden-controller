use anyhow::{anyhow, Result};
use clap::{clap_app, crate_name};
use std::process;

mod opa;
use opa::wasm::Evaluator;

fn main() -> Result<()> {
    let matches = clap_app!(
    (crate_name!()) =>
        (@arg ("input"): -i --("input") +takes_value "JSON string with the input")
        (@arg ("data"): -d --("data") +takes_value "JSON string with the data")
        (@arg ("entrypoint"): -e --("entrypoint") +takes_value "OPA entrypoint to evaluate")
        (@arg ("policy"): * "Path to the wasm file containing the policy")
    )
    .get_matches();

    let input: serde_json::Value = matches
        .value_of("input")
        .or(Some("{}"))
        .map(|i| serde_json::from_str(i).map_err(|e| anyhow!("Cannot parse input: {:?}", e)))
        .unwrap()?;

    let data: serde_json::Value = matches
        .value_of("data")
        .or(Some("{}"))
        .map(|d| serde_json::from_str(d).map_err(|e| anyhow!("Cannot parse data: {:?}", e)))
        .unwrap()?;

    let mut evaluator = Evaluator::new(matches.value_of("policy").unwrap())?;
    let (major, minor) = evaluator.opa_abi_version()?;
    println!("OPA Wasm ABI: {}.{}", major, minor);

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
    Ok(())
}

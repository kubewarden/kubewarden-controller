mod cli;

use policy_evaluator::policy_evaluator::PolicyEvaluator;

use anyhow::Result;
use std::process;

use std::fs::File;
use std::io::BufReader;

fn host_callback(
    id: u64,
    bd: &str,
    ns: &str,
    op: &str,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "Guest {} invoked '{}->{}:{}' with payload of {}",
        id,
        bd,
        ns,
        op,
        ::std::str::from_utf8(payload).unwrap()
    );
    Ok(b"Host result".to_vec())
}

fn main() {
    let matches = cli::app().get_matches();

    let policy_file = String::from(matches.value_of("policy").unwrap());
    let request_file = matches.value_of("request-file").unwrap();
    let settings_str = matches.value_of("settings").unwrap();

    let settings = match serde_json::from_str(&settings_str) {
        Ok(s) => s,
        Err(e) => {
            return fatal_error(format!("Error parsing settings: {:?}", e));
        }
    };

    let mut policy_evaluator = match PolicyEvaluator::new(policy_file, settings, host_callback) {
        Ok(p) => p,
        Err(e) => {
            return fatal_error(format!("Error creating policy evaluator: {:?}", e));
        }
    };

    let request = match read_request_file(request_file) {
        Ok(r) => r,
        Err(e) => {
            return fatal_error(format!(
                "Error reading request from file {}: {:?}",
                request_file, e
            ));
        }
    };

    let vr = policy_evaluator.validate(request);
    println!("{:?}", vr);
}

fn read_request_file(path: &str) -> Result<serde_json::Value> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let v = serde_json::from_reader(reader)?;

    Ok(v)
}

fn fatal_error(msg: String) {
    println!("{}", msg);
    process::exit(1);
}

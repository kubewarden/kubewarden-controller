use clap::{App, Arg};
use std::{
    net::SocketAddr,
    process,
    sync::{Arc, Barrier},
    thread,
};
use tokio::{runtime::Runtime, sync::mpsc::channel};

mod admission_review;
mod api;
mod registry;
mod server;
mod utils;
mod wasm_fetcher;
mod worker;

mod policies;
use policies::read_policies_file;

mod wasm;
use crate::wasm::EvalRequest;

fn main() {
    let matches = App::new("policy-server")
        .version("0.0.1")
        .about("Kubernetes admission controller powered by Chimera WASM policies")
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .takes_value(false)
                .help("Increase verbosity"),
        )
        .arg(
            Arg::with_name("address")
                .long("addr")
                .default_value("0.0.0.0")
                .help("Bind against ADDRESS"),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .default_value("3000")
                .help("Listen on PORT"),
        )
        .arg(
            Arg::with_name("workers")
                .long("workers")
                .env("CHIMERA_WORKERS")
                .help("Number of workers thread to create"),
        )
        .arg(
            Arg::with_name("cert-file")
                .long("cert-file")
                .default_value("")
                .env("CHIMERA_CERT_FILE")
                .help("Path to an X.509 certificate file for HTTPS"),
        )
        .arg(
            Arg::with_name("key-file")
                .long("key-file")
                .default_value("")
                .env("CHIMERA_KEY_FILE")
                .help("Path to an X.509 private key file for HTTPS"),
        )
        .arg(
            Arg::with_name("policies")
                .long("policies")
                .env("CHIMERA_POLICIES")
                .default_value("policies.yml")
                .help(
                    "YAML file holding the Chimera policies to be loaded and
                    their settings",
                ),
        )
        .arg(
            Arg::with_name("docker-config-json-path")
                .env("CHIMERA_DOCKER_CONFIG_JSON_PATH")
                .long("docker-config-json-path")
                .takes_value(true)
                .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details"),
        )
        .get_matches();

    let addr: SocketAddr = match format!(
        "{}:{}",
        matches.value_of("address").unwrap(),
        matches.value_of("port").unwrap()
    )
    .parse()
    {
        Ok(a) => a,
        Err(error) => {
            return fatal_error(format!("Error parsing arguments: {}", error));
        }
    };

    let cert_file = String::from(matches.value_of("cert-file").unwrap());
    let key_file = String::from(matches.value_of("key-file").unwrap());
    if cert_file.is_empty() != key_file.is_empty() {
        return fatal_error("Error parsing arguments: either both --cert-file and --key-file must be provided, or neither.".to_string());
    }

    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(error) => {
            return fatal_error(format!("Error initializing tokio runtime: {}", error));
        }
    };

    let policies_file = matches.value_of("policies").unwrap();
    let mut policies = match read_policies_file(policies_file) {
        Ok(ps) => ps,
        Err(e) => {
            return fatal_error(format!(
                "Error while loading policies from {}: {}",
                policies_file, e
            ));
        }
    };

    for (_, policy) in policies.iter_mut() {
        match rt.block_on(wasm_fetcher::fetch_wasm_module(
            &policy.url,
            matches
                .value_of("docker-config-json-path")
                .map(|json_config_path| json_config_path.into()),
        )) {
            Ok(path) => policy.wasm_module_path = path,
            Err(e) => {
                return fatal_error(format!("Error while fetching policy {}: {}", policy.url, e));
            }
        };
    }

    let (api_tx, api_rx) = channel::<EvalRequest>(32);
    let pool_size = matches.value_of("workers").map_or_else(num_cpus::get, |v| {
        usize::from_str_radix(v, 10).expect("error converting the number of workers")
    });

    let barrier = Arc::new(Barrier::new(pool_size + 1));
    let main_barrier = barrier.clone();

    let wasm_thread = thread::spawn(move || {
        let worker_pool = worker::WorkerPool::new(pool_size, policies.clone(), api_rx, barrier);

        worker_pool.run();
    });
    main_barrier.wait();

    let tls_acceptor = if cert_file.is_empty() {
        None
    } else {
        Some(server::new_tls_acceptor(&cert_file, &key_file).unwrap())
    };
    rt.block_on(server::run_server(&addr, tls_acceptor, api_tx));

    wasm_thread.join().unwrap();
}

fn fatal_error(msg: String) {
    println!("{}", msg);
    process::exit(1);
}

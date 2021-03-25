use clap::{App, Arg};
use std::{
    net::SocketAddr,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
};
use tokio::{runtime::Runtime, sync::mpsc::channel};

mod admission_review;
mod api;
mod registry;
mod server;
mod wasm_fetcher;
mod worker;

use policy_evaluator::policy::read_policies_file;

mod sources;
use sources::read_sources_file;

use std::fs;

mod wasm;
use crate::wasm::EvalRequest;

use crate::registry::config::{DockerConfig, DockerConfigRaw};

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
                .env("CHIMERA_BIND_ADDRESS")
                .help("Bind against ADDRESS"),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .default_value("3000")
                .env("CHIMERA_PORT")
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
            Arg::with_name("policies-download-dir")
                .long("policies-download-dir")
                .default_value(".")
                .env("CHIMERA_POLICIES_DOWNLOAD_DIR")
                .help("Download path for the policies"),
        )
        .arg(
            Arg::with_name("sources")
                .takes_value(true)
                .long("sources")
                .env("CHIMERA_SOURCES")
                .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
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

    let policies_file = matches.value_of("policies").unwrap_or(".");
    let mut policies = match read_policies_file(policies_file) {
        Ok(policies) => policies,
        Err(err) => {
            return fatal_error(format!(
                "Error while loading policies from {}: {}",
                policies_file, err
            ));
        }
    };

    let sources = matches
        .value_of("sources")
        .map(|sources_file| match read_sources_file(sources_file) {
            Ok(sources) => sources,
            Err(err) => {
                fatal_error(format!(
                    "Error while loading sources from {}: {}",
                    sources_file, err
                ));
                unreachable!();
            }
        })
        .unwrap_or_default();

    let docker_config_json_path = matches
        .value_of("docker-config-json-path")
        .map(|json_config_path| json_config_path.into());

    let docker_config: Option<DockerConfig> = docker_config_json_path
        .and_then(|docker_config_json_path: String| {
            fs::read_to_string(docker_config_json_path).ok()
        })
        .and_then(|contents| {
            serde_json::from_str(&contents)
                .map(|config: DockerConfigRaw| config.into())
                .ok()
        });

    let policies_download_dir = matches.value_of("policies-download-dir").unwrap();
    let policies_total = policies.len();
    for (c, policy) in policies.iter_mut() {
        println!("Downloading policy {}/{}", c, policies_total);
        match rt.block_on(wasm_fetcher::fetch_wasm_module(
            &policy.url,
            policies_download_dir,
            docker_config.clone(),
            &sources,
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

    // Barrier used to wait for all the workers to be ready.
    // The barrier prevents the web server from starting before the workers are
    // ready to process the incoming requests send by the Kubernetes.
    // This mechanism is used to create a Kubernetes HTTP readiness probe
    let barrier = Arc::new(Barrier::new(pool_size + 1));
    let main_barrier = barrier.clone();

    // The boot canary is a boolean that is set to false when one of more
    // workers can't be started. This kind of failures can happen when a
    // Wasm module is broken.
    let boot_canary = Arc::new(AtomicBool::new(true));
    let main_boot_canary = boot_canary.clone();

    let wasm_thread = thread::spawn(move || {
        let worker_pool =
            worker::WorkerPool::new(pool_size, policies.clone(), api_rx, barrier, boot_canary);
        worker_pool.run();
    });
    // wait for all the workers to be ready, then ensure none of them had issues
    // at boot time
    main_barrier.wait();
    if !main_boot_canary.load(Ordering::SeqCst) {
        return fatal_error(String::from("Couldn't init one of the workers"));
    }

    // All is good, we can start listening for incoming requests through the
    // web server
    let tls_acceptor = if cert_file.is_empty() {
        None
    } else {
        match server::new_tls_acceptor(&cert_file, &key_file) {
            Ok(t) => Some(t),
            Err(e) => {
                return fatal_error(format!("Error while creating tls acceptor: {:?}", e));
            }
        }
    };
    rt.block_on(server::run_server(&addr, tls_acceptor, api_tx));

    if let Err(e) = wasm_thread.join() {
        return fatal_error(format!("Error while waiting for worker threads: {:?}", e));
    }
}

fn fatal_error(msg: String) {
    println!("{}", msg);
    process::exit(1);
}

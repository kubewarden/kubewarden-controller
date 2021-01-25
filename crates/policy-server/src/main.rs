use clap::{App, Arg};
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::{net::SocketAddr, thread};
use std::process;
use tokio::{runtime::Runtime, sync::mpsc::channel};

mod admission_review;
mod api;
mod wasm;
mod wasm_fetcher;
mod worker;

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
                .env("CHIMERA_CERT_FILE")
                .help("TLS certificate to use"),
        )
        .arg(
            Arg::with_name("cert-key")
                .long("cert-key")
                .env("CHIMERA_CERT_KEY")
                .help("TLS key to use"),
        )
        .arg(
            Arg::with_name("wasm-uri")
                .long("wasm-uri")
                .env("CHIMERA_WASM_URI")
                .required(true)
                .help(
                    "Wasm URI (file:///some/local/program.wasm,
                    https://some-host.com/some/remote/program.wasm,
                    registry://localhost:5000/project/artifact:some-version)",
                ),
        )
        .arg(
            Arg::with_name("wasm-remote-insecure")
                .env("CHIMERA_WASM_REMOTE_INSECURE")
                .long("wasm-remote-insecure")
                .takes_value(false)
                .help("Do not verify remote TLS certificate. False by default"),
        )
        .arg(
            Arg::with_name("wasm-remote-non-tls")
                .env("CHIMERA_WASM_REMOTE_NON_TLS")
                .long("wasm-remote-non-tls")
                .takes_value(false)
                .help("Wasm remote endpoint is not using TLS. False by default"),
        )
        .get_matches();

    let addr: SocketAddr = match format!(
        "{}:{}",
        matches.value_of("address").unwrap(),
        matches.value_of("port").unwrap()
    )
    .parse() {
        Ok(a) => { a },
        Err(error) => {
            return fatal_error(format!("Error parsing arguments: {}", error));
        }
    };

    let rt = match Runtime::new() {
        Ok(r) => { r },
        Err(error) => {
            return fatal_error(format!("Error initializing tokio runtime: {}", error));
        }
    };

    let fetcher = match wasm_fetcher::parse_wasm_url(
        matches.value_of("wasm-uri").unwrap(),
        matches.is_present("wasm-remote-insecure"),
        matches.is_present("wasm-remote-non-tls"),
    ) {
        Ok(f) => { f },
        Err(error) => {
            return fatal_error(format!("Error parsing arguments: {}", error));
        }
    };
    let wasm_path = match rt.block_on(async { fetcher.fetch().await }) {
        Ok(p) =>p,
        Err(error) => { return fatal_error(format!("Error fetching WASM module: {}", error));}
    };

    let (api_tx, api_rx) = channel::<EvalRequest>(32);

    let mut wasm_modules = Vec::<String>::new();
    wasm_modules.push(wasm_path);

    let wasm_thread = thread::spawn(move || {
        let pool_size = matches.value_of("workers").
            map_or_else(|| num_cpus::get(), |v| usize::from_str_radix(v, 10).expect("error converting the number of workers"));
        let worker_pool = worker::WorkerPool::new(pool_size, wasm_modules.clone(), api_rx).unwrap();

        worker_pool.run();
    });

    rt.block_on( async {
        let make_svc = make_service_fn(|_conn| {
            let svc_tx = api_tx.clone();
            async move { 
                Ok::<_, hyper::Error>(service_fn(move |req| api::route(req, svc_tx.clone()))) }
        });

        let server = Server::bind(&addr).serve(make_svc);
        println!("Started server on {}", addr);

        if let Err(e) = server.await {
            eprintln!("server error: {}", e);
        }
    });

    wasm_thread.join().unwrap();
}

fn fatal_error(msg: String) {
    println!("{}", msg);
    process::exit(1);
}

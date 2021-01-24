use clap::{App, Arg};
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::{net::SocketAddr, thread};
use std::process;
use tokio::{runtime::Runtime, sync::mpsc};

mod admission_review;
mod api;
mod wasm;
mod wasm_fetcher;

#[tokio::main]
async fn main() {
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
    let wasm_path = match fetcher.fetch().await {
        Ok(p) => { p },
        Err(error) => {
            return fatal_error(format!("Error fetching WASM module: {}", error));
        }
    };

    let (tx, mut rx) = mpsc::channel::<wasm::EvalRequest>(32);

    let rt = Runtime::new().unwrap();
    let wasm_thread = thread::spawn(move || {
        let mut policy_evaluator = match wasm::PolicyEvaluator::new(&wasm_path) {
            Ok(e) => { e },
            Err(error) => {
                return fatal_error(format!("Error initializing policy evaluator for {}: {}", wasm_path, error));
            }
        };
        rt.block_on(async move {
            while let Some(req) = rx.recv().await {
                let resp = policy_evaluator.validate(req.req);
                let _ = req.resp_chan.send(resp);
            }
        });
    });

    let make_svc = make_service_fn(|_conn| {
        let svc_tx = tx.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| api::route(req, svc_tx.clone()))) }
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!("Started server on {}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    wasm_thread.join().unwrap();
}

fn fatal_error(msg: String) {
    println!("{}", msg);
    process::exit(1);
}

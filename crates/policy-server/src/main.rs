use async_stream::stream;
use clap::{App, Arg};
use core::task::{Context, Poll};
use futures_util::{future::TryFutureExt, stream::Stream};
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::{net::SocketAddr, thread};
use std::{io, process};
use std::fs::File;
use std::io::Read;
use std::pin::Pin;
use tokio::{net::{TcpListener, TcpStream}, runtime::Runtime, sync::mpsc::channel};
use tokio_native_tls::{native_tls, TlsAcceptor, TlsStream};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::x509::X509;

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

    let cert_file = String::from(matches.value_of("cert-file").unwrap());
    let key_file = String::from(matches.value_of("key-file").unwrap());
    if (cert_file == "" && key_file != "") || (cert_file != "" && key_file == "") {
        return fatal_error(format!("Error parsing arguments: either both --cert-file and --key-file must be provided, or neither."));
    }

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

    macro_rules! mk_svc_fn {
        ($tx:expr) => {
            make_service_fn(|_conn| {
                let svc_tx = $tx.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req| api::route(req, svc_tx.clone()))) }
            });
        };
    }

    rt.block_on( async {
        if cert_file == "" {
            let make_svc = mk_svc_fn!(api_tx);
            let server = Server::bind(&addr).serve(make_svc);
            println!("Started server on {}", addr);
            if let Err(e) = server.await {
                eprintln!("server error: {}", e);
            }
        } else {
            let tls_acceptor = new_tls_acceptor(&cert_file, &key_file).unwrap();
            let tcp = TcpListener::bind(&addr).await.unwrap();
            let incoming_tls_stream = stream! {
                loop {
                    let (socket, _) = tcp.accept().await?;
                    let stream = tls_acceptor.accept(socket).map_err(|e| {
                        println!("[!] Voluntary server halt due to client-connection error...");
                        error(format!("TLS Error: {:?}", e))
                    });
                    yield stream.await;
                }
            };

            let make_svc = mk_svc_fn!(api_tx);
            let server = Server::builder(HyperAcceptor {
                acceptor: Box::pin(incoming_tls_stream),
            }).serve(make_svc);

            println!("Started server on {}", addr);
            if let Err(e) = server.await {
                eprintln!("server error: {}", e);
            }
        }
    }
    );

    wasm_thread.join().unwrap();
}

fn fatal_error(msg: String) {
    println!("{}", msg);
    process::exit(1);
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

struct HyperAcceptor<'a> {
    acceptor: Pin<Box<dyn Stream<Item = Result<TlsStream<TcpStream>, io::Error>> + 'a>>,
}

impl hyper::server::accept::Accept for HyperAcceptor<'_> {
    type Conn = TlsStream<TcpStream>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}

fn new_tls_acceptor(cert_file: &str, key_file: &str) -> Result<TlsAcceptor, io::Error> {
    let mut cert_file = File::open(cert_file)?;
    let mut key_file = File::open(key_file)?;
    let mut cert = vec![];
    cert_file.read_to_end(&mut cert)?;
    let cert = X509::from_pem(&cert)?;
    let mut key = vec![];
    key_file.read_to_end(&mut key)?;
    let key = PKey::private_key_from_pem(&key)?;
    let pkcs_cert = Pkcs12::builder()
            .build("", "client", &key, &cert)?;
    let identity = native_tls::Identity::from_pkcs12(&pkcs_cert.to_der()?, "").unwrap();
    let tls_acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
    Ok(TlsAcceptor::from(tls_acceptor))
}

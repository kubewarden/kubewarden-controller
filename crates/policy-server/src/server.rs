use async_stream::stream;
use core::task::{Context, Poll};
use futures_util::{future::TryFutureExt, stream::Stream};
use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};
use std::{fs::File, io, io::Read, net::SocketAddr, pin::Pin};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};
use tokio_native_tls::{native_tls, TlsAcceptor, TlsStream};

use crate::api;
use crate::wasm::EvalRequest;

pub(crate) fn new_tls_acceptor(cert_file: &str, key_file: &str) -> Result<TlsAcceptor, io::Error> {
    let mut cert_file = File::open(cert_file)?;
    let mut key_file = File::open(key_file)?;
    let mut cert = vec![];
    cert_file.read_to_end(&mut cert)?;
    let cert = X509::from_pem(&cert)?;
    let mut key = vec![];
    key_file.read_to_end(&mut key)?;
    let key = PKey::private_key_from_pem(&key)?;
    let pkcs_cert = Pkcs12::builder().build("", "client", &key, &cert)?;
    let identity = native_tls::Identity::from_pkcs12(&pkcs_cert.to_der()?, "").unwrap();
    let tls_acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
    Ok(TlsAcceptor::from(tls_acceptor))
}

pub(crate) async fn run_server(
    addr: &SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
    api_tx: Sender<EvalRequest>,
) {
    macro_rules! mk_svc_fn {
        ($tx:expr) => {
            make_service_fn(|_conn| {
                let svc_tx = $tx.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req| api::route(req, svc_tx.clone())))
                }
            });
        };
    }

    match tls_acceptor {
        None => {
            let make_svc = mk_svc_fn!(api_tx);
            let server = Server::bind(&addr).serve(make_svc);
            println!("Started server on {}", addr);
            if let Err(e) = server.await {
                eprintln!("server error: {}", e);
            }
        }
        Some(tls_acceptor) => {
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
            })
            .serve(make_svc);

            println!("Started server on {}", addr);
            if let Err(e) = server.await {
                eprintln!("server error: {}", e);
            }
        }
    };
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

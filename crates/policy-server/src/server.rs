use anyhow::{anyhow, Result};
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
use tracing::{error, info};

use crate::api;
use crate::communication::EvalRequest;

pub(crate) fn new_tls_acceptor(cert_file: &str, key_file: &str) -> Result<TlsAcceptor> {
    let mut cert_file = File::open(cert_file)
        .map_err(|e| anyhow!("Error opening certificate file {}: {:?}", cert_file, e))?;
    let mut key_file = File::open(key_file)
        .map_err(|e| anyhow!("Error opening key file {}: {:?}", key_file, e))?;

    let mut cert = vec![];
    cert_file
        .read_to_end(&mut cert)
        .map_err(|e| anyhow!("Error reading cert file {:?}", e))?;
    let cert = X509::from_pem(&cert).map_err(|e| anyhow!("Error creating cert object {:?}", e))?;

    let mut key = vec![];
    key_file
        .read_to_end(&mut key)
        .map_err(|e| anyhow!("Error reading key file {:?}", e))?;
    let key = PKey::private_key_from_pem(&key)
        .map_err(|e| anyhow!("Error creating key object {:?}", e))?;

    let pkcs_cert = Pkcs12::builder()
        .build("", "client", &key, &cert)
        .map_err(|e| anyhow!("Error creating pkcs_cert object {:?}", e))?;
    let identity = native_tls::Identity::from_pkcs12(&pkcs_cert.to_der()?, "")
        .map_err(|e| anyhow!("Error creating tls identity object {:?}", e))?;
    let tls_acceptor = native_tls::TlsAcceptor::new(identity)
        .map_err(|e| anyhow!("Error creating tls acceptor object {:?}", e))?;

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
            info!(address = addr.to_string().as_str(), "started HTTP server");
            if let Err(e) = server.await {
                error!(error = e.to_string().as_str(), "HTTP server error");
            }
        }
        Some(tls_acceptor) => {
            let tcp = TcpListener::bind(&addr).await.unwrap();
            let incoming_tls_stream = stream! {
                loop {
                    let (socket, _) = tcp.accept().await?;
                    let stream = tls_acceptor.accept(socket).map_err(|e| {
                        error!("[!] Voluntary server halt due to client-connection error...");
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

            info!(address = addr.to_string().as_str(), "started HTTPS server");
            if let Err(e) = server.await {
                error!(error = e.to_string().as_str(), "HTTPS server error");
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

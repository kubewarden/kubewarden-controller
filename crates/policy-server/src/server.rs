use anyhow::{anyhow, Result};
use async_stream::stream;

use futures_util::future::TryFutureExt;
use hyper::{
    server::accept,
    service::{make_service_fn, service_fn},
    Server,
};
use rustls::server::ServerConfig;
use rustls_pemfile::{certs, rsa_private_keys};
use std::{io, io::Cursor, net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::mpsc::Sender};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::api;
use crate::communication::EvalRequest;

pub(crate) fn new_tls_acceptor(cert_file: &str, key_file: &str) -> Result<TlsAcceptor> {
    let mut cert_buff = Cursor::new(
        std::fs::read(cert_file)
            .map_err(|e| anyhow!("Error opening certificate file {}: {:?}", cert_file, e))?,
    );
    let cert = certs(&mut cert_buff)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    let mut key_buff = Cursor::new(
        std::fs::read(key_file)
            .map_err(|e| anyhow!("Error opening key file {}: {:?}", cert_file, e))?,
    );
    let key = rsa_private_keys(&mut key_buff)?;
    if key.len() != 1 {
        return Err(anyhow!("Key file has to contain only one private key"));
    }
    let key = rustls::PrivateKey(key.into_iter().next().unwrap());

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .expect("bad certificate/key");

    Ok(TlsAcceptor::from(Arc::new(server_config)))
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
            })
        };
    }

    match tls_acceptor {
        None => {
            let make_svc = mk_svc_fn!(api_tx);
            let server = Server::bind(addr).serve(make_svc);
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
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    yield stream.await;
                }
            };

            let acceptor = accept::from_stream(incoming_tls_stream);
            let make_svc = mk_svc_fn!(api_tx);
            let server = Server::builder(acceptor).serve(make_svc);

            info!(address = addr.to_string().as_str(), "started HTTPS server");
            if let Err(e) = server.await {
                error!(error = e.to_string().as_str(), "HTTPS server error");
            }
        }
    };
}

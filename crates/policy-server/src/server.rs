use std::net::SocketAddr;
use tokio::sync::mpsc::Sender;

use crate::communication::EvalRequest;

pub(crate) struct TlsConfig {
    pub cert_file: String,
    pub key_file: String,
}

pub(crate) async fn run_server(
    addr: &SocketAddr,
    tls_config: Option<TlsConfig>,
    api_tx: Sender<EvalRequest>,
) {
    let ip = addr.ip();
    let port = addr.port();

    let routes = filters::routes(api_tx);

    match tls_config {
        None => warp::serve(routes).run((ip, port)).await,
        Some(cfg) => {
            warp::serve(routes)
                .tls()
                .cert_path(cfg.cert_file)
                .key_path(cfg.key_file)
                .run((ip, port))
                .await
        }
    };
}

mod filters {
    use super::{EvalRequest, Sender};
    use warp::Filter;

    pub(crate) fn routes(
        api_tx: Sender<EvalRequest>,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        validate(api_tx.clone()).or(audit(api_tx)).or(readiness())
    }

    fn validate(
        api_tx: Sender<EvalRequest>,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        // POST /validate/:policy_id with JSON body
        warp::path!("validate" / String)
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || api_tx.clone()))
            .and_then(crate::api::validation)
    }

    fn audit(
        api_tx: Sender<EvalRequest>,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        // POST /audit/:policy_id with JSON body
        warp::path!("audit" / String)
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || api_tx.clone()))
            .and_then(crate::api::audit)
    }

    fn readiness() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        // GET /readiness
        warp::path!("readiness")
            .and(warp::get())
            .and_then(crate::api::readiness)
    }
}

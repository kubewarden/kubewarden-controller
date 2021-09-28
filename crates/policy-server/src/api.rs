use anyhow::anyhow;
use hyper::{Body, Method, Request, Response, StatusCode};
use policy_evaluator::validation_response::ValidationResponse;
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, span::Span, warn};

use crate::admission_review::AdmissionReview;
use crate::communication::EvalRequest;

pub(crate) async fn route(
    req: hyper::Request<hyper::Body>,
    tx: mpsc::Sender<EvalRequest>,
) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    match *req.method() {
        Method::POST => {
            let path = String::from(req.uri().path());
            if path.starts_with("/validate/") {
                handle_post_validate(req, path.trim_start_matches("/validate/").to_string(), tx)
                    .await
            } else {
                handle_not_found().await
            }
        }
        Method::GET => {
            let path = String::from(req.uri().path());
            if path == "/readiness" {
                handle_ready().await
            } else {
                handle_not_found().await
            }
        }
        _ => handle_not_found().await,
    }
}

// note about tracing: we are manually adding the `policy_id` field
// because otherwise the automatic "export" would cause the string to be
// double quoted. This would make searching by tag inside of Jaeger ugly.
// A concrete example: the automatic generation leads to the creation
// of `policy_id = "\"psp-capabilities\""` instead of `policy_id = "psp-capabilities"`
#[tracing::instrument(
    name = "validation",
    fields(
        request_uid=tracing::field::Empty,
        host=crate::cli::HOSTNAME.as_str(),
        policy_id=policy_id.as_str(),
        ),
    skip_all)]
async fn handle_post_validate(
    req: Request<Body>,
    policy_id: String,
    tx: mpsc::Sender<EvalRequest>,
) -> Result<Response<Body>, hyper::Error> {
    let raw = hyper::body::to_bytes(req.into_body()).await?;
    let raw_str = String::from_utf8(raw.to_vec())
        .unwrap_or_else(|_| String::from("cannot convert raw request into utf8"));

    let adm_rev = match AdmissionReview::new(raw) {
        Ok(ar) => {
            debug!(admission_review = %serde_json::to_string(&ar).unwrap().as_str());
            ar
        }
        Err(e) => {
            warn!(
                req = raw_str.as_str(),
                error = e.to_string().as_str(),
                "Bad AdmissionReview request"
            );

            let mut bad_req = Response::default();
            *bad_req.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(bad_req);
        }
    };

    // add request UID to the span context as one of its fields
    Span::current().record("request_uid", &adm_rev.uid.as_str());

    let (resp_tx, resp_rx) = oneshot::channel();
    let eval_req = EvalRequest {
        policy_id,
        req: adm_rev.request,
        resp_chan: resp_tx,
        parent_span: Span::current(),
    };
    if tx.send(eval_req).await.is_err() {
        error!("error while sending request from API to Worker pool");

        let mut internal_error = Response::default();
        *internal_error.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Ok(internal_error);
    }
    let res = resp_rx.await;

    match res {
        Ok(r) => match r {
            Some(vr) => {
                let json_payload = match build_ar_response(vr) {
                    Ok(j) => j,
                    Err(e) => {
                        error!(error = e.to_string().as_str(), "error building response");
                        let mut internal_error = Response::default();
                        *internal_error.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok(internal_error);
                    }
                };
                debug!(response = json_payload.as_str(), "policy evaluated");

                match Response::builder()
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .status(StatusCode::OK)
                    .body(hyper::Body::from(json_payload))
                {
                    Ok(builder) => Ok(builder),
                    Err(e) => {
                        error!(
                            error = e.to_string().as_str(),
                            "error while building response"
                        );
                        let mut internal_error = Response::default();
                        *internal_error.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        Ok(internal_error)
                    }
                }
            }
            None => {
                warn!("requested policy not known");
                let mut not_found = Response::default();
                *not_found.status_mut() = StatusCode::NOT_FOUND;
                Ok(not_found)
            }
        },
        Err(e) => {
            error!(
                error = e.to_string().as_str(),
                "cannot get WASM response from channel"
            );
            let mut internal_error = Response::default();
            *internal_error.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(internal_error)
        }
    }
}

fn build_ar_response(validation_response: ValidationResponse) -> anyhow::Result<String> {
    let reply = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": validation_response,
    });

    serde_json::to_string(&reply).map_err(|e| anyhow!("Error serializing response: {:?}", e))
}

#[tracing::instrument(fields(host=crate::cli::HOSTNAME.as_str()))]
async fn handle_not_found() -> Result<Response<Body>, hyper::Error> {
    info!("request not found");
    let mut not_found = Response::default();
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    Ok(not_found)
}

async fn handle_ready() -> Result<Response<Body>, hyper::Error> {
    // Always return HTTP OK
    // The main has a sync::Barrier that prevents the web server to listen to
    // incoming requests until all the Workers are ready

    let mut ready = Response::default();
    *ready.status_mut() = StatusCode::OK;
    Ok(ready)
}

use hyper::{Body, Method, Request, Response, StatusCode};
use serde_json::json;
use tokio::sync::{mpsc, oneshot};

use crate::admission_review::AdmissionReview;
use crate::wasm;

pub(crate) async fn route(
    req: hyper::Request<hyper::Body>,
    tx: mpsc::Sender<wasm::EvalRequest>,
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
        _ => handle_not_found().await,
    }
}

async fn handle_post_validate(
    req: Request<Body>,
    policy_id: String,
    tx: mpsc::Sender<wasm::EvalRequest>,
) -> Result<Response<Body>, hyper::Error> {
    let raw = hyper::body::to_bytes(req.into_body()).await?;

    let adm_rev = match AdmissionReview::new(raw) {
        Ok(ar) => ar,
        Err(e) => {
            //TODO: proper logging
            println!("Bad AdmissionReview request {}", e);
            let mut bad_req = Response::default();
            *bad_req.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(bad_req);
        }
    };

    let (resp_tx, resp_rx) = oneshot::channel();

    let eval_req = wasm::EvalRequest {
        policy_id,
        req: adm_rev.request,
        resp_chan: resp_tx,
    };
    tx.send(eval_req).await.unwrap();
    let res = resp_rx.await;

    match res {
        Ok(r) => match r {
            Some(vr) => {
                let json_payload = build_ar_response(adm_rev.uid, vr);
                let builder = Response::builder()
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .status(StatusCode::OK)
                    .body(hyper::Body::from(json_payload));
                Ok(builder.unwrap())
            }
            None => {
                let mut not_found = Response::default();
                *not_found.status_mut() = StatusCode::NOT_FOUND;
                Ok(not_found)
            }
        },
        Err(e) => {
            println!("Cannot get WASM response from channel: {}", e);
            let mut internl_error = Response::default();
            *internl_error.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(internl_error)
        }
    }
}

fn build_ar_response(review_uid: String, validation_response: wasm::ValidationResponse) -> String {
    let mut base = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": review_uid,
            "allowed": validation_response.accepted
        }
    });

    let reply = base.as_object_mut().unwrap();

    let mut status = serde_json::Map::new();
    if let Some(code) = validation_response.code {
        status.insert(String::from("code"), json!(code));
    }
    if let Some(message) = validation_response.message {
        status.insert(String::from("message"), json!(message));
    }

    if !status.is_empty() {
        let response = reply["response"].as_object_mut().unwrap();
        response.insert(String::from("status"), json!(status));
    }

    serde_json::to_string(&reply).unwrap()
}

async fn handle_not_found() -> Result<Response<Body>, hyper::Error> {
    let mut not_found = Response::default();
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    Ok(not_found)
}

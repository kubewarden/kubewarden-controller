use std::convert::Infallible;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, span::Span, warn};
use warp::http::StatusCode;

use super::{
    populate_span_with_admission_request_data, populate_span_with_policy_evaluation_results,
    ServerErrorResponse,
};
use crate::admission_review::AdmissionReview;
use crate::communication::EvalRequest;

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
        name=tracing::field::Empty,
        namespace=tracing::field::Empty,
        operation=tracing::field::Empty,
        subresource=tracing::field::Empty,
        kind_group=tracing::field::Empty,
        kind_version=tracing::field::Empty,
        kind=tracing::field::Empty,
        resource_group=tracing::field::Empty,
        resource_version=tracing::field::Empty,
        resource=tracing::field::Empty,
        allowed=tracing::field::Empty,
        mutated=tracing::field::Empty,
        response_code=tracing::field::Empty,
        response_message=tracing::field::Empty,
    ),
    skip_all)]
pub(crate) async fn validation(
    policy_id: String,
    admission_review: AdmissionReview,
    tx: mpsc::Sender<EvalRequest>,
) -> Result<impl warp::Reply, Infallible> {
    let adm_req = match admission_review.request {
        Some(ar) => {
            debug!(admission_review = %serde_json::to_string(&ar).unwrap().as_str());
            ar
        }
        None => {
            let message = String::from("No Request object defined inside AdmissionReview object");
            warn!(error = message.as_str(), "Bad AdmissionReview request");
            let error_reply = ServerErrorResponse { message };

            return Ok(warp::reply::with_status(
                warp::reply::json(&error_reply),
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    populate_span_with_admission_request_data(&adm_req);

    let (resp_tx, resp_rx) = oneshot::channel();
    let eval_req = EvalRequest {
        policy_id,
        req: adm_req,
        resp_chan: resp_tx,
        parent_span: Span::current(),
    };
    if tx.send(eval_req).await.is_err() {
        let message = String::from("error while sending request from API to Worker pool");
        error!("{}", message);

        let error_reply = ServerErrorResponse { message };
        return Ok(warp::reply::with_status(
            warp::reply::json(&error_reply),
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }
    let res = resp_rx.await;

    match res {
        Ok(r) => match r {
            Some(vr) => {
                populate_span_with_policy_evaluation_results(&vr);
                let admission_review = AdmissionReview::new_with_response(vr);
                debug!(response =? admission_review, "policy evaluated");

                Ok(warp::reply::with_status(
                    warp::reply::json(&admission_review),
                    StatusCode::OK,
                ))
            }
            None => {
                let message = String::from("requested policy not known");
                warn!("{}", message);

                let error_reply = ServerErrorResponse { message };
                Ok(warp::reply::with_status(
                    warp::reply::json(&error_reply),
                    StatusCode::NOT_FOUND,
                ))
            }
        },
        Err(e) => {
            error!(
                error = e.to_string().as_str(),
                "cannot get wasm response from channel"
            );

            let error_reply = ServerErrorResponse {
                message: String::from("broken channel"),
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_reply),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

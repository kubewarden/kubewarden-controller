use std::convert::Infallible;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, span::Span, warn};
use warp::http::StatusCode;

use super::{
    populate_span_with_admission_request_data, populate_span_with_policy_evaluation_results,
    ServerErrorResponse,
};
use crate::admission_review::AdmissionReview;
use crate::communication::{EvalRequest, RequestOrigin};

// note about tracing: we are manually adding the `policy_id` field
// because otherwise the automatic "export" would cause the string to be
// double quoted. This would make searching by tag inside of Jaeger ugly.
// A concrete example: the automatic generation leads to the creation
// of `policy_id = "\"psp-capabilities\""` instead of `policy_id = "psp-capabilities"`
#[tracing::instrument(
    name = "audit",
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
pub(crate) async fn audit(
    policy_id: String,
    admission_review: AdmissionReview,
    tx: mpsc::Sender<EvalRequest>,
) -> Result<impl warp::Reply, Infallible> {
    let request_origin = crate::communication::RequestOrigin::Audit;
    evaluate(policy_id, admission_review, tx, request_origin).await
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
    let request_origin = crate::communication::RequestOrigin::Validate;
    evaluate(policy_id, admission_review, tx, request_origin).await
}

pub(crate) async fn evaluate(
    policy_id: String,
    admission_review: AdmissionReview,
    tx: mpsc::Sender<EvalRequest>,
    request_origin: RequestOrigin,
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
        request_origin,
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

#[cfg(test)]
mod tests {
    use crate::admission_review::tests::build_admission_review;
    use policy_evaluator::admission_response::AdmissionResponse;
    use rstest::*;
    use warp::Reply;

    use super::*;

    #[rstest]
    #[case(RequestOrigin::Validate)]
    #[case(RequestOrigin::Audit)]
    #[tokio::test]
    async fn success(#[case] request_origin: RequestOrigin) {
        let (tx, mut rx) = mpsc::channel::<EvalRequest>(1);

        let policy_id = "test_policy".to_string();
        let admission_review = build_admission_review();
        let request_origin_spawn = request_origin.clone();

        tokio::spawn(async move {
            let response = match request_origin_spawn {
                RequestOrigin::Validate => validation(policy_id, admission_review, tx)
                    .await
                    .expect("validation should not fail")
                    .into_response(),
                RequestOrigin::Audit => audit(policy_id, admission_review, tx)
                    .await
                    .expect("validation should not fail")
                    .into_response(),
            };
            assert_eq!(response.status(), StatusCode::OK);
        });

        while let Some(eval_req) = rx.recv().await {
            match request_origin {
                RequestOrigin::Validate => {
                    assert!(matches!(
                        eval_req.request_origin,
                        crate::communication::RequestOrigin::Validate
                    ))
                }
                RequestOrigin::Audit => {
                    assert!(matches!(
                        eval_req.request_origin,
                        crate::communication::RequestOrigin::Audit
                    ))
                }
            };
            let admission_response = AdmissionResponse {
                uid: "test_uid".to_string(),
                allowed: true,
                ..Default::default()
            };
            eval_req
                .resp_chan
                .send(Some(admission_response))
                .expect("cannot send back evaluation response");
        }
    }

    #[rstest]
    #[case(RequestOrigin::Validate)]
    #[case(RequestOrigin::Audit)]
    #[tokio::test]
    async fn missing_admission_review_request(#[case] request_origin: RequestOrigin) {
        let (tx, mut rx) = mpsc::channel::<EvalRequest>(1);

        let policy_id = "test_policy".to_string();
        let mut admission_review = build_admission_review();
        admission_review.request = None;
        let request_origin_spawn = request_origin.clone();

        tokio::spawn(async move {
            let response = match request_origin_spawn {
                RequestOrigin::Validate => validation(policy_id, admission_review, tx)
                    .await
                    .expect("validation should not fail")
                    .into_response(),
                RequestOrigin::Audit => audit(policy_id, admission_review, tx)
                    .await
                    .expect("validation should not fail")
                    .into_response(),
            };
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });

        while let Some(eval_req) = rx.recv().await {
            match request_origin {
                RequestOrigin::Validate => {
                    assert!(matches!(
                        eval_req.request_origin,
                        crate::communication::RequestOrigin::Validate
                    ))
                }
                RequestOrigin::Audit => {
                    assert!(matches!(
                        eval_req.request_origin,
                        crate::communication::RequestOrigin::Audit
                    ))
                }
            };
            let admission_response = AdmissionResponse {
                uid: "test_uid".to_string(),
                allowed: true,
                ..Default::default()
            };
            eval_req
                .resp_chan
                .send(Some(admission_response))
                .expect("cannot send back evaluation response");
        }
    }

    #[rstest]
    #[case(RequestOrigin::Validate)]
    #[case(RequestOrigin::Audit)]
    #[tokio::test]
    async fn requested_policy_not_found(#[case] request_origin: RequestOrigin) {
        let (tx, mut rx) = mpsc::channel::<EvalRequest>(1);

        let policy_id = "test_policy".to_string();
        let admission_review = build_admission_review();
        let request_origin_spawn = request_origin.clone();

        tokio::spawn(async move {
            let response = match request_origin_spawn {
                RequestOrigin::Validate => validation(policy_id, admission_review, tx)
                    .await
                    .expect("validation should not fail")
                    .into_response(),
                RequestOrigin::Audit => audit(policy_id, admission_review, tx)
                    .await
                    .expect("validation should not fail")
                    .into_response(),
            };
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        });

        while let Some(eval_req) = rx.recv().await {
            match request_origin {
                RequestOrigin::Validate => {
                    assert!(matches!(
                        eval_req.request_origin,
                        crate::communication::RequestOrigin::Validate
                    ))
                }
                RequestOrigin::Audit => {
                    assert!(matches!(
                        eval_req.request_origin,
                        crate::communication::RequestOrigin::Audit
                    ))
                }
            };
            eval_req
                .resp_chan
                .send(None)
                .expect("cannot send back evaluation response");
        }
    }
}

use std::sync::Arc;

use anyhow::{Result, anyhow};
use kubewarden_policy_sdk::host_capabilities::{
    SigstoreVerificationInputV1, SigstoreVerificationInputV2,
    crypto_v1::CertificateVerificationRequest,
    kubernetes::{
        CanIRequest, GetResourceRequest, ListAllResourcesRequest, ListResourcesByNamespaceRequest,
    },
};
use tokio::sync::{mpsc, oneshot, oneshot::Receiver};
use tracing::{debug, error, warn};

use crate::callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse};
use crate::evaluation_context::EvaluationContext;

fn unknown_operation(
    namespace: &str,
    operation: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    error!(namespace, operation, "unknown operation");
    Err(format!("unknown operation: {}", operation).into())
}

fn unknown_namespace(namespace: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    error!(namespace, "unknown namespace");
    Err(format!("unknown namespace: {}", namespace).into())
}

/// The callback function used by waPC and Wasi policies to use host capabilities
pub(crate) fn host_callback(
    binding: &str,
    namespace: &str,
    operation: &str,
    payload: &[u8],
    eval_ctx: &Arc<EvaluationContext>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match binding {
        "kubewarden" => match namespace {
            "tracing" => match operation {
                "log" => {
                    if let Err(e) = eval_ctx.log(payload) {
                        error!(
                            payload = String::from_utf8_lossy(payload).to_string(),
                            error = e.to_string(),
                            "Cannot log event"
                        );
                    }
                    Ok(Vec::new())
                }
                _ => unknown_operation(namespace, operation),
            },
            "oci" => match operation {
                "v1/verify" => {
                    let req: SigstoreVerificationInputV1 = serde_json::from_slice(payload)?;
                    let req_type: CallbackRequestType = req.into();
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: req_type,
                        response_channel: tx,
                    };

                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                "v2/verify" => {
                    let req: SigstoreVerificationInputV2 = serde_json::from_slice(payload)?;
                    let req_type: CallbackRequestType = req.into();
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: req_type,
                        response_channel: tx,
                    };

                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                "v1/manifest_digest" => {
                    let image: String = serde_json::from_slice(payload)?;
                    debug!(
                        eval_ctx.policy_id,
                        binding, operation, image, "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::OciManifestDigest { image },
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                "v1/oci_manifest" => {
                    let image: String = serde_json::from_slice(payload)?;
                    debug!(
                        eval_ctx.policy_id,
                        binding, operation, image, "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::OciManifest { image },
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                "v1/oci_manifest_config" => {
                    let image: String = serde_json::from_slice(payload)?;
                    debug!(
                        eval_ctx.policy_id,
                        binding, operation, image, "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::OciManifestAndConfig { image },
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                _ => unknown_operation(namespace, operation),
            },
            "net" => match operation {
                "v1/dns_lookup_host" => {
                    let host: String = serde_json::from_slice(payload)?;
                    debug!(
                        eval_ctx.policy_id,
                        binding, operation, host, "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::DNSLookupHost { host },
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                _ => unknown_operation(namespace, operation),
            },
            "crypto" => match operation {
                "v1/is_certificate_trusted" => {
                    let req: CertificateVerificationRequest = serde_json::from_slice(payload)?;

                    debug!(
                        eval_ctx.policy_id,
                        binding,
                        operation,
                        ?req,
                        "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::from(req),
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                _ => unknown_operation(namespace, operation),
            },
            "kubernetes" => match operation {
                "list_resources_by_namespace" => {
                    let req: ListResourcesByNamespaceRequest = serde_json::from_slice(payload)?;

                    if !eval_ctx.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                        error!(
                            policy = eval_ctx.policy_id,
                            resource_requested = format!("{}/{}", req.api_version, req.kind),
                            resources_allowed = ?eval_ctx.ctx_aware_resources_allow_list,
                            "Policy tried to access a Kubernetes resource it doesn't have access to");
                        return Err(format!(
                                "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                                req.api_version,
                                req.kind).into());
                    }

                    debug!(
                        eval_ctx.policy_id,
                        binding,
                        operation,
                        ?req,
                        "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::from(req),
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                "list_resources_all" => {
                    let req: ListAllResourcesRequest = serde_json::from_slice(payload)?;
                    if !eval_ctx.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                        error!(
                            policy = eval_ctx.policy_id,
                            resource_requested = format!("{}/{}", req.api_version, req.kind),
                            resources_allowed = ?eval_ctx.ctx_aware_resources_allow_list,
                            "Policy tried to access a Kubernetes resource it doesn't have access to");
                        return Err(format!(
                                "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                                req.api_version,
                                req.kind).into());
                    }

                    debug!(
                        eval_ctx.policy_id,
                        binding,
                        operation,
                        ?req,
                        "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::from(req),
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                "get_resource" => {
                    let req: GetResourceRequest = serde_json::from_slice(payload)?;
                    if !eval_ctx.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                        error!(
                            policy = eval_ctx.policy_id,
                            resource_requested = format!("{}/{}", req.api_version, req.kind),
                            resources_allowed = ?eval_ctx.ctx_aware_resources_allow_list,
                            "Policy tried to access a Kubernetes resource it doesn't have access to");
                        return Err(format!(
                                "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                                req.api_version,
                                req.kind).into());
                    }

                    debug!(
                        eval_ctx.policy_id,
                        binding,
                        operation,
                        ?req,
                        "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::from(req),
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                "can_i" => {
                    let req: CanIRequest = serde_json::from_slice(payload)?;

                    debug!(
                        eval_ctx.policy_id,
                        binding,
                        namespace,
                        operation,
                        ?req,
                        "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::from(req),
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(
                        &eval_ctx.policy_id,
                        binding,
                        operation,
                        req,
                        rx,
                        eval_ctx,
                    )
                }
                _ => unknown_operation(namespace, operation),
            },
            _ => unknown_namespace(namespace),
        },
        "kubernetes" => match namespace {
            "ingresses" => {
                let req = CallbackRequestType::KubernetesListResourceAll {
                    api_version: "networking.k8s.io/v1".to_string(),
                    kind: "Ingress".to_string(),
                    label_selector: None,
                    field_selector: None,
                };

                warn!(
                    eval_ctx.policy_id,
                    ?req,
                    "Usage of deprecated `ClusterContext`"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: req,
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "namespaces" => {
                let req = CallbackRequestType::KubernetesListResourceAll {
                    api_version: "v1".to_string(),
                    kind: "Namespace".to_string(),
                    label_selector: None,
                    field_selector: None,
                };

                warn!(
                    eval_ctx.policy_id,
                    ?req,
                    "Usage of deprecated `ClusterContext`"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: req,
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "services" => {
                let req = CallbackRequestType::KubernetesListResourceAll {
                    api_version: "v1".to_string(),
                    kind: "Service".to_string(),
                    label_selector: None,
                    field_selector: None,
                };

                warn!(
                    eval_ctx.policy_id,
                    ?req,
                    "Usage of deprecated `ClusterContext`"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: req,
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            _ => unknown_namespace(namespace),
        },
        _ => {
            error!(binding, "unknown binding");
            Err(format!("unknown binding: {binding}").into())
        }
    }
}

fn send_request_and_wait_for_response(
    policy_id: &str,
    binding: &str,
    operation: &str,
    req: CallbackRequest,
    rx: Receiver<Result<CallbackResponse>>,
    eval_ctx: &EvaluationContext,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let cb_channel: mpsc::Sender<CallbackRequest> = if let Some(c) =
        eval_ctx.callback_channel.clone()
    {
        Ok(c)
    } else {
        error!(
            policy_id,
            binding, operation, "Cannot process Wasm guest request: callback channel not provided"
        );
        Err(anyhow!(
            "Cannot process Wasm guest request: callback channel not provided"
        ))
    }?;

    let send_result = cb_channel.try_send(req);
    if let Err(e) = send_result {
        return Err(format!("Error sending request over callback channel: {e:?}").into());
    }

    // wait for the response
    match rx.blocking_recv() {
        Ok(msg) => match msg {
            Ok(resp) => Ok(resp.payload),
            Err(e) => {
                error!(
                    policy_id,
                    binding,
                    operation,
                    error = ?e,
                    "callback evaluation failed"
                );
                Err(format!("Callback evaluation failure: {e:?}").into())
            }
        },
        Err(e) => {
            error!(
                policy_id,
                binding,
                operation,
                error = ?e,
                "Cannot process Wasm guest request: error obtaining response over callback channel"
            );
            Err("Error obtaining response over callback channel".into())
        }
    }
}

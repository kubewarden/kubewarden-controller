use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::host_capabilities::{
    crypto_v1::{CertificateVerificationRequest, CertificateVerificationResponse},
    kubernetes::{GetResourceRequest, ListAllResourcesRequest, ListResourcesByNamespaceRequest},
    SigstoreVerificationInputV1, SigstoreVerificationInputV2,
};
use tokio::sync::{mpsc, oneshot, oneshot::Receiver};
use tracing::{debug, error, warn};

use crate::callback_handler::verify_certificate;
use crate::callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse};
use crate::runtimes::wapc::mapping::get_policy;

pub(crate) fn host_callback(
    policy_id: u64,
    binding: &str,
    namespace: &str,
    operation: &str,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match binding {
        "kubewarden" => match namespace {
            "tracing" => match operation {
                "log" => {
                    let policy = get_policy(policy_id).map_err(|e| {
                        error!(
                            ?policy_id,
                            ?binding,
                            ?namespace,
                            ?operation,
                            error = ?e, "Cannot find requested policy");
                        e
                    })?;
                    if let Err(e) = policy.log(payload) {
                        let p =
                            String::from_utf8(payload.to_vec()).unwrap_or_else(|e| e.to_string());
                        error!(
                            payload = p.as_str(),
                            error = e.to_string().as_str(),
                            "Cannot log event"
                        );
                    }
                    Ok(Vec::new())
                }
                _ => {
                    error!(namespace, operation, "unknown operation");
                    Err(format!("unknown operation: {operation}").into())
                }
            },
            "oci" => match operation {
                "v1/verify" => {
                    let req: SigstoreVerificationInputV1 =
                        serde_json::from_slice(payload.to_vec().as_ref())?;
                    let req_type: CallbackRequestType = req.into();
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: req_type,
                        response_channel: tx,
                    };

                    send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
                }
                "v2/verify" => {
                    let req: SigstoreVerificationInputV2 =
                        serde_json::from_slice(payload.to_vec().as_ref())?;
                    let req_type: CallbackRequestType = req.into();
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: req_type,
                        response_channel: tx,
                    };

                    send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
                }
                "v1/manifest_digest" => {
                    let image: String = serde_json::from_slice(payload.to_vec().as_ref())?;
                    debug!(
                        policy_id,
                        binding,
                        operation,
                        image = image.as_str(),
                        "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::OciManifestDigest { image },
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
                }
                _ => {
                    error!("unknown operation: {}", operation);
                    Err(format!("unknown operation: {operation}").into())
                }
            },
            "net" => match operation {
                "v1/dns_lookup_host" => {
                    let host: String = serde_json::from_slice(payload.to_vec().as_ref())?;
                    debug!(
                        policy_id,
                        binding,
                        operation,
                        ?host,
                        "Sending request via callback channel"
                    );
                    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                    let req = CallbackRequest {
                        request: CallbackRequestType::DNSLookupHost { host },
                        response_channel: tx,
                    };
                    send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
                }
                _ => {
                    error!("unknown operation: {}", operation);
                    Err(format!("unknown operation: {operation}").into())
                }
            },
            "crypto" => match operation {
                "v1/is_certificate_trusted" => {
                    let req: CertificateVerificationRequest =
                        serde_json::from_slice(payload.to_vec().as_ref())?;
                    let response: CertificateVerificationResponse = match verify_certificate(req) {
                        Ok(b) => b.into(),
                        Err(e) => {
                            return Err(format!("Error when verifying certificate: {e}").into())
                        }
                    };
                    Ok(serde_json::to_vec(&response)?)
                }
                _ => {
                    error!(namespace, operation, "unknown operation");
                    Err(format!("unknown operation: {operation}").into())
                }
            },
            "kubernetes" => match operation {
                "list_resources_by_namespace" => {
                    let policy = get_policy(policy_id).map_err(|e| {
                        error!(
                            policy_id,
                            ?binding,
                            ?namespace,
                            ?operation,
                            error = ?e, "Cannot find requested policy");
                        e
                    })?;

                    let req: ListResourcesByNamespaceRequest =
                        serde_json::from_slice(payload.to_vec().as_ref())?;

                    if !policy.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                        error!(
                            policy = policy.id,
                            resource_requested = format!("{}/{}", req.api_version, req.kind),
                            resources_allowed = ?policy.ctx_aware_resources_allow_list,
                            "Policy tried to access a Kubernetes resource it doesn't have access to");
                        return Err(format!(
                                "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                                req.api_version,
                                req.kind).into());
                    }

                    debug!(
                        policy_id,
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
                    send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
                }
                "list_resources_all" => {
                    let policy = get_policy(policy_id).map_err(|e| {
                        error!(
                            policy_id,
                            ?binding,
                            ?namespace,
                            ?operation,
                            error = ?e, "Cannot find requested policy");
                        e
                    })?;

                    let req: ListAllResourcesRequest =
                        serde_json::from_slice(payload.to_vec().as_ref())?;
                    if !policy.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                        error!(
                            policy = policy.id,
                            resource_requested = format!("{}/{}", req.api_version, req.kind),
                            resources_allowed = ?policy.ctx_aware_resources_allow_list,
                            "Policy tried to access a Kubernetes resource it doesn't have access to");
                        return Err(format!(
                                "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                                req.api_version,
                                req.kind).into());
                    }

                    debug!(
                        policy_id,
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
                    send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
                }
                "get_resource" => {
                    let policy = get_policy(policy_id).map_err(|e| {
                        error!(
                            policy_id,
                            ?binding,
                            ?namespace,
                            ?operation,
                            error = ?e, "Cannot find requested policy");
                        e
                    })?;

                    let req: GetResourceRequest =
                        serde_json::from_slice(payload.to_vec().as_ref())?;
                    if !policy.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                        error!(
                            policy = policy.id,
                            resource_requested = format!("{}/{}", req.api_version, req.kind),
                            resources_allowed = ?policy.ctx_aware_resources_allow_list,
                            "Policy tried to access a Kubernetes resource it doesn't have access to");
                        return Err(format!(
                                "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                                req.api_version,
                                req.kind).into());
                    }

                    debug!(
                        policy_id,
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
                    send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
                }
                _ => {
                    error!(namespace, operation, "unknown operation");
                    Err(format!("unknown operation: {operation}").into())
                }
            },
            _ => {
                error!("unknown namespace: {}", namespace);
                Err(format!("unknown namespace: {namespace}").into())
            }
        },
        "kubernetes" => match namespace {
            "ingresses" => {
                let req = CallbackRequestType::KubernetesListResourceAll {
                    api_version: "networking.k8s.io/v1".to_string(),
                    kind: "Ingress".to_string(),
                    label_selector: None,
                    field_selector: None,
                };

                warn!(policy_id, ?req, "Usage of deprecated `ClusterContext`");
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: req,
                    response_channel: tx,
                };
                send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
            }
            "namespaces" => {
                let req = CallbackRequestType::KubernetesListResourceAll {
                    api_version: "v1".to_string(),
                    kind: "Namespace".to_string(),
                    label_selector: None,
                    field_selector: None,
                };

                warn!(policy_id, ?req, "Usage of deprecated `ClusterContext`");
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: req,
                    response_channel: tx,
                };
                send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
            }
            "services" => {
                let req = CallbackRequestType::KubernetesListResourceAll {
                    api_version: "v1".to_string(),
                    kind: "Service".to_string(),
                    label_selector: None,
                    field_selector: None,
                };

                warn!(policy_id, ?req, "Usage of deprecated `ClusterContext`");
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: req,
                    response_channel: tx,
                };
                send_request_and_wait_for_response(policy_id, binding, operation, req, rx)
            }
            _ => {
                error!("unknown namespace: {}", namespace);
                Err(format!("unknown namespace: {namespace}").into())
            }
        },
        _ => {
            error!("unknown binding: {}", binding);
            Err(format!("unknown binding: {binding}").into())
        }
    }
}

fn send_request_and_wait_for_response(
    policy_id: u64,
    binding: &str,
    operation: &str,
    req: CallbackRequest,
    mut rx: Receiver<Result<CallbackResponse>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let policy = get_policy(policy_id)?;

    let cb_channel: mpsc::Sender<CallbackRequest> = if let Some(c) = policy.callback_channel.clone()
    {
        Ok(c)
    } else {
        error!(
            policy_id,
            binding, operation, "Cannot process waPC request: callback channel not provided"
        );
        Err(anyhow!(
            "Cannot process waPC request: callback channel not provided"
        ))
    }?;

    let send_result = cb_channel.try_send(req);
    if let Err(e) = send_result {
        return Err(format!("Error sending request over callback channel: {e:?}").into());
    }

    // wait for the response
    loop {
        match rx.try_recv() {
            Ok(msg) => {
                return match msg {
                    Ok(resp) => Ok(resp.payload),
                    Err(e) => {
                        error!(
                            policy_id,
                            binding,
                            operation,
                            error = e.to_string().as_str(),
                            "callback evaluation failed"
                        );
                        Err(format!("Callback evaluation failure: {e:?}").into())
                    }
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                //  do nothing, keep waiting for a reply
            }
            Err(e) => {
                error!(
                    policy_id,
                    binding,
                    operation,
                    error = e.to_string().as_str(),
                    "Cannot process waPC request: error obtaining response over callback channel"
                );
                return Err("Error obtaining response over callback channel".into());
            }
        }
    }
}

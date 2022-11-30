use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use serde_json::json;
use std::{collections::HashMap, convert::TryFrom, sync::RwLock};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error};

pub(crate) struct Runtime<'a>(pub(crate) &'a mut wapc::WapcHost);

use crate::admission_response::AdmissionResponse;
use crate::callback_handler::verify_certificate;
use crate::callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse};
use crate::cluster_context::ClusterContext;
use crate::policy::Policy;
use crate::policy_evaluator::{PolicySettings, ValidateRequest};

use kubewarden_policy_sdk::host_capabilities::{
    crypto_v1::{CertificateVerificationRequest, CertificateVerificationResponse},
    SigstoreVerificationInputV1, SigstoreVerificationInputV2,
};
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use tokio::sync::oneshot::Receiver;

lazy_static! {
    pub(crate) static ref WAPC_POLICY_MAPPING: RwLock<HashMap<u64, Policy>> =
        RwLock::new(HashMap::with_capacity(64));
}

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
                    let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
                    let policy = policy_mapping.get(&policy_id).unwrap();
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
                    Err(format!("unknown operation: {}", operation).into())
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
                    Err(format!("unknown operation: {}", operation).into())
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
                    Err(format!("unknown operation: {}", operation).into())
                }
            },
            "crypto" => match operation {
                "v1/is_certificate_trusted" => {
                    let req: CertificateVerificationRequest =
                        serde_json::from_slice(payload.to_vec().as_ref())?;
                    let response: CertificateVerificationResponse = match verify_certificate(req) {
                        Ok(b) => b.into(),
                        Err(e) => {
                            return Err(format!("Error when verifying certificate: {}", e).into())
                        }
                    };
                    Ok(serde_json::to_vec(&response)?)
                }
                _ => {
                    error!(namespace, operation, "unknown operation");
                    Err(format!("unknown operation: {}", operation).into())
                }
            },
            _ => {
                error!("unknown namespace: {}", namespace);
                Err(format!("unknown namespace: {}", namespace).into())
            }
        },
        "kubernetes" => {
            let cluster_context = ClusterContext::get();
            match namespace {
                "ingresses" => Ok(cluster_context.ingresses().into()),
                "namespaces" => Ok(cluster_context.namespaces().into()),
                "services" => Ok(cluster_context.services().into()),
                _ => {
                    error!("unknown namespace: {}", namespace);
                    Err(format!("unknown namespace: {}", namespace).into())
                }
            }
        }
        _ => {
            error!("unknown binding: {}", binding);
            Err(format!("unknown binding: {}", binding).into())
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
    let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
    let policy = policy_mapping.get(&policy_id).unwrap();

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
        return Err(format!("Error sending request over callback channel: {:?}", e).into());
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
                        Err(format!("Callback evaluation failure: {:?}", e).into())
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

impl<'a> Runtime<'a> {
    pub fn validate(
        &mut self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> AdmissionResponse {
        let uid = request.uid();

        //NOTE: object is null for DELETE operations
        let req_obj = request.0.get("object");

        let validate_params = json!({
            "request": request,
            "settings": settings,
        });

        let validate_str = match serde_json::to_string(&validate_params) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    error = e.to_string().as_str(),
                    "cannot serialize validation params"
                );
                return AdmissionResponse::reject_internal_server_error(
                    uid.to_string(),
                    e.to_string(),
                );
            }
        };

        match self.0.call("validate", validate_str.as_bytes()) {
            Ok(res) => {
                let pol_val_resp: Result<PolicyValidationResponse> = serde_json::from_slice(&res)
                    .map_err(|e| anyhow!("cannot deserialize policy validation response: {:?}", e));
                pol_val_resp
                    .and_then(|pol_val_resp| {
                        AdmissionResponse::from_policy_validation_response(
                            uid.to_string(),
                            req_obj,
                            &pol_val_resp,
                        )
                    })
                    .unwrap_or_else(|e| {
                        error!(
                            error = e.to_string().as_str(),
                            "cannot build validation response from policy result"
                        );
                        AdmissionResponse::reject_internal_server_error(
                            uid.to_string(),
                            e.to_string(),
                        )
                    })
            }
            Err(e) => {
                error!(error = e.to_string().as_str(), "waPC communication error");
                AdmissionResponse::reject_internal_server_error(uid.to_string(), e.to_string())
            }
        }
    }

    pub fn validate_settings(&mut self, settings: String) -> SettingsValidationResponse {
        match self.0.call("validate_settings", settings.as_bytes()) {
            Ok(res) => {
                let vr: Result<SettingsValidationResponse> = serde_json::from_slice(&res)
                    .map_err(|e| anyhow!("cannot convert response: {:?}", e));
                vr.unwrap_or_else(|e| SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("error: {:?}", e)),
                })
            }
            Err(err) => SettingsValidationResponse {
                valid: false,
                message: Some(format!(
                    "Error invoking settings validation callback: {:?}",
                    err
                )),
            },
        }
    }

    pub fn protocol_version(&self) -> Result<ProtocolVersion> {
        match self.0.call("protocol_version", &[0; 0]) {
            Ok(res) => ProtocolVersion::try_from(res.clone()).map_err(|e| {
                anyhow!(
                    "Cannot create ProtocolVersion object from '{:?}': {:?}",
                    res,
                    e
                )
            }),
            Err(err) => Err(anyhow!(
                "Cannot invoke 'protocol_version' waPC function: {:?}",
                err
            )),
        }
    }
}

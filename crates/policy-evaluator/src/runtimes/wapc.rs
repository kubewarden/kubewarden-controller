use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::host_capabilities::{
    crypto_v1::{CertificateVerificationRequest, CertificateVerificationResponse},
    kubernetes::{GetResourceRequest, ListAllResourcesRequest, ListResourcesByNamespaceRequest},
    SigstoreVerificationInputV1, SigstoreVerificationInputV2,
};
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use lazy_static::lazy_static;
use serde_json::json;
use std::{collections::HashMap, convert::TryFrom, sync::RwLock};
use tokio::sync::oneshot::Receiver;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};
use wasmtime_provider::wasmtime;

use crate::admission_response::AdmissionResponse;
use crate::callback_handler::verify_certificate;
use crate::callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse};
use crate::policy::Policy;
use crate::policy_evaluator::{PolicySettings, ValidateRequest};

pub(crate) struct Runtime<'a>(pub(crate) &'a mut WapcStack);

lazy_static! {
    pub(crate) static ref WAPC_POLICY_MAPPING: RwLock<HashMap<u64, Policy>> =
        RwLock::new(HashMap::with_capacity(64));
}

/// Error message returned by wasmtime_provider when the guest execution
/// is interrupted because of epoch deadline is exceeded.
///
/// Unfortunately, wasmtime_provider doesn't return a typed error, hence we have
/// to look for this text
const WAPC_EPOCH_INTERRUPTION_ERR_MSG: &str = "guest code interrupted, execution deadline exceeded";

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
    let policy_mapping = WAPC_POLICY_MAPPING
        .read()
        .map_err(|e| anyhow!("cannot get READ access to WAPC_POLICY_MAPPING: {e}"))?;
    let policy = policy_mapping
        .get(&policy_id)
        .ok_or(anyhow!("cannot find policy with id {policy_id}"))?;

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

pub(crate) struct WapcStack {
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    epoch_deadlines: Option<crate::policy_evaluator_builder::EpochDeadlines>,
    wapc_host: wapc::WapcHost,
}

impl WapcStack {
    pub(crate) fn new(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<crate::policy_evaluator_builder::EpochDeadlines>,
    ) -> Result<Self> {
        let wapc_host = Self::setup_wapc_host(engine.clone(), module.clone(), epoch_deadlines)?;

        Ok(Self {
            engine,
            module,
            epoch_deadlines,
            wapc_host,
        })
    }

    /// Provision a new wapc_host. Useful for starting from a clean slate
    /// after an epoch deadline interruption is raised.
    ///
    /// This method takes care of de-registering the old wapc_host and
    /// registering the new one inside of the global WAPC_POLICY_MAPPING
    /// variable.
    pub(crate) fn reset(&mut self) -> Result<()> {
        // Create a new wapc_host
        let new_wapc_host = Self::setup_wapc_host(
            self.engine.clone(),
            self.module.clone(),
            self.epoch_deadlines,
        )?;
        let old_wapc_host_id = self.wapc_host.id();

        // Remove the old policy from WAPC_POLICY_MAPPING and add the new one
        // We need a write lock to do that
        {
            let mut map = WAPC_POLICY_MAPPING
                .write()
                .expect("cannot get write access to WAPC_POLICY_MAPPING");
            let policy = map.remove(&old_wapc_host_id).ok_or_else(|| {
                anyhow!("cannot find old waPC policy with id {}", old_wapc_host_id)
            })?;
            map.insert(new_wapc_host.id(), policy);
        }

        self.wapc_host = new_wapc_host;

        Ok(())
    }

    fn setup_wapc_host(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        epoch_deadlines: Option<crate::policy_evaluator_builder::EpochDeadlines>,
    ) -> Result<wapc::WapcHost> {
        let mut builder = wasmtime_provider::WasmtimeEngineProviderBuilder::new()
            .engine(engine)
            .module(module);
        if let Some(deadlines) = epoch_deadlines {
            builder = builder.enable_epoch_interruptions(deadlines.wapc_init, deadlines.wapc_func);
        }

        let engine_provider = builder.build()?;
        let wapc_host =
            wapc::WapcHost::new(Box::new(engine_provider), Some(Box::new(host_callback)))?;
        Ok(wapc_host)
    }

    pub fn wapc_host_id(&self) -> u64 {
        self.wapc_host.id()
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

        match self.0.wapc_host.call("validate", validate_str.as_bytes()) {
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
                if e.to_string()
                    .as_str()
                    .contains(WAPC_EPOCH_INTERRUPTION_ERR_MSG)
                {
                    // TL;DR: after code execution is interrupted because of an
                    // epoch deadline being reached, we have to reset the waPC host
                    // to ensure further invocations of the policy work as expected.
                    //
                    // The waPC host is using the wasmtime_provider, which internally
                    // uses a wasmtime::Engine and a wasmtime::Store.
                    // The Store keeps track of the stateful data of the policy. When an
                    // epoch deadline is reached, wasmtime::Engine stops the execution of
                    // the wasm guest. There's NO CLEANUP code called inside of the guest.
                    // It's like unplugging the power cord from a turned on computer.
                    //
                    // When the guest function is invoked again, the previous state stored
                    // inside of wasmtime::Store is used.
                    // That can lead to unexpected issues. For example, if the guest makes
                    // uses of a Mutex, something like that can happen (I've witnessed that):
                    //
                    // * Guest code 1st run:
                    //   - Mutex.lock
                    // * Host: interrupt code execution because of epoch deadline
                    // * Guest code 2nd run:
                    //   - The Mutex is still locked, because that's what is stored inside
                    //     of the wasmtime::Store
                    //   - Guest attempts to `lock` the Mutex -> error is raised
                    //
                    // The guest code will stay in this broken state forever. The only
                    // solution to that is to reinitialize the wasmtime::Store.
                    // It's hard to provide a facility for that inside of WapcHost, because
                    // epoch deadline is a feature provided only by the wasmtime backend.
                    // Hence it's easier to just recreate the wapc_host associated with this
                    // policy evaluator
                    if let Err(reset_err) = self.0.reset() {
                        error!(error = reset_err.to_string().as_str(), "cannot reset waPC stack - further calls to this policy can result in errors");
                    } else {
                        info!("wapc_host reset performed after timeout protection was triggered");
                    }
                }
                AdmissionResponse::reject_internal_server_error(uid.to_string(), e.to_string())
            }
        }
    }

    pub fn validate_settings(&mut self, settings: String) -> SettingsValidationResponse {
        match self
            .0
            .wapc_host
            .call("validate_settings", settings.as_bytes())
        {
            Ok(res) => {
                let vr: Result<SettingsValidationResponse> = serde_json::from_slice(&res)
                    .map_err(|e| anyhow!("cannot convert response: {:?}", e));
                vr.unwrap_or_else(|e| SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("error: {e:?}")),
                })
            }
            Err(err) => SettingsValidationResponse {
                valid: false,
                message: Some(format!(
                    "Error invoking settings validation callback: {err:?}"
                )),
            },
        }
    }

    pub fn protocol_version(&self) -> Result<ProtocolVersion> {
        match self.0.wapc_host.call("protocol_version", &[0; 0]) {
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

fn get_policy(policy_id: u64) -> Result<Policy> {
    let policy_mapping = WAPC_POLICY_MAPPING.read().map_err(|e| {
        anyhow!(
            "Cannot obtain read lock access to WAPC_POLICY_MAPPING: {}",
            e
        )
    })?;
    policy_mapping
        .get(&policy_id)
        .ok_or_else(|| anyhow!("Cannot find policy with ID {}", policy_id))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync, thread, time};

    #[test]
    fn wapc_epoch_interrutpion_error_msg() {
        // This unit test makes sure that waPC host error raised when a wasmtime
        // epoch_interruption happens contains the WAPC_EPOCH_INTERRUPTION_ERR_MSG
        // string
        //
        // The unit test is a bit "low-level", meaning the target are the
        // wapc libraries we consume, not the "high" level code we expose
        // as part of policy-evaluator.
        // This is done to make the whole testing process simple:
        // * No need to download a wasm module from a registry/commit a ~3Mb
        //   binary blob to this git repository
        // * Reduce the code being tested to the bare minimum

        let mut engine_conf = wasmtime::Config::default();
        engine_conf.epoch_interruption(true);
        let engine = wasmtime::Engine::new(&engine_conf).expect("cannot create wasmtime engine");

        let wat = include_bytes!("../../test_data/endless_wasm/wapc_endless_loop.wat");
        let module = wasmtime::Module::new(&engine, wat).expect("cannot compile WAT to wasm");

        // Create the wapc engine, the code will be interrupted after 10 ticks
        // happen. We produce 1 tick every 10 milliseconds, see below
        let wapc_engine_builder = wasmtime_provider::WasmtimeEngineProviderBuilder::new()
            .engine(engine.clone())
            .module(module)
            .enable_epoch_interruptions(10, 10);

        let wapc_engine = wapc_engine_builder
            .build()
            .expect("error creating wasmtime engine provider");
        let host = wapc::WapcHost::new(Box::new(wapc_engine), Some(Box::new(host_callback)))
            .expect("cannot create waPC host");

        // Create a lock to break the endless loop of the ticker thread
        let timer_lock = sync::Arc::new(sync::RwLock::new(false));
        let quit_lock = timer_lock.clone();

        // Start a thread that ticks the epoch timer of the wasmtime
        // engine. 1 tick equals 10 milliseconds
        thread::spawn(move || {
            let interval = time::Duration::from_millis(10);
            loop {
                thread::sleep(interval);
                engine.increment_epoch();
                if *quit_lock.read().unwrap() {
                    break;
                }
            }
        });

        // This triggers an endless loop inside of wasm
        // If the epoch_interruption doesn't work, this unit test
        // will never complete
        let res = host.call("run", "".as_bytes());

        // Tell the ticker thread to quit
        {
            let mut w = timer_lock.write().unwrap();
            *w = true;
        }

        // Ensure we got back an error from waPC, the error must
        // contain the WAPC_EPOCH_INTERRUPTION_ERR_MSG string
        let err = res.unwrap_err();
        assert!(err
            .to_string()
            .as_str()
            .contains(WAPC_EPOCH_INTERRUPTION_ERR_MSG));
    }
}

use std::fs::File;
use std::io::prelude::*;

use serde::{Deserialize, Serialize};

use wapc::WapcHost;
use wasmtime_provider::WasmtimeEngineProvider;

use tokio::sync::oneshot;

fn host_callback(
    id: u64,
    bd: &str,
    ns: &str,
    op: &str,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "Guest {} invoked '{}->{}:{}' with payload of {}",
        id,
        bd,
        ns,
        op,
        ::std::str::from_utf8(payload).unwrap()
    );
    Ok(b"Host result".to_vec())
}

pub(crate) struct PolicyEvaluator {
    wapc_host: WapcHost,
}

impl PolicyEvaluator {
    pub(crate) fn new(wasm_file: String) -> Result<PolicyEvaluator, anyhow::Error> {
        let mut f = File::open(wasm_file)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        let engine = WasmtimeEngineProvider::new(&buf, None);
        let host = WapcHost::new(Box::new(engine), host_callback)?;

        Ok(PolicyEvaluator { wapc_host: host })
    }

    pub(crate) fn validate(&mut self, request: String) -> ValidationResponse {
        match self.wapc_host.call("validate", request.as_bytes()) {
            Ok(res) => {
                let val_resp: ValidationResponse = serde_json::from_slice(&res)
                    .map_err(|e| {
                        //TODO: proper logging
                        println!("Cannot deserialize response: {}", e);
                        ValidationResponse {
                            accepted: false,
                            message: Some(String::from("internal server error")),
                            code: Some(hyper::StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                        }
                    })
                    .unwrap();
                val_resp
            }
            Err(e) => {
                //TODO: proper logging
                println!("Something went wrong with waPC: {}", e);
                ValidationResponse {
                    accepted: false,
                    message: Some(String::from("internal server error")),
                    code: Some(hyper::StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct EvalRequest {
    pub req: String,
    pub resp_chan: oneshot::Sender<ValidationResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ValidationResponse {
    pub accepted: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
}

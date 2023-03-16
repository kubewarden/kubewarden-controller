use super::ProxyMode;
use anyhow::{anyhow, Result};
use policy_evaluator::{
    callback_handler::CallbackHandlerBuilder,
    callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse},
    kube,
    policy_fetcher::{sources::Sources, verify::FulcioAndRekorData},
};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, fs::File, path::PathBuf};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Response {
    Success { payload: String },
    Error { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
struct Exchange {
    pub request: String,
    pub response: Response,
}

/// A proxy against a `policy_evaluator::CallbackHandler`
/// Can record guest requests, save them to file and reply them back
pub(crate) struct CallbackHandlerProxy {
    sources: Option<Sources>,
    fulcio_and_rekor_data: Option<FulcioAndRekorData>,
    kube_client: Option<kube::Client>,
    mode: ProxyMode,

    /// List of exchanges that happen between the policy and the
    /// host. This is populated only when the proxy is ran in
    /// `record` mode.
    ///
    /// Important, something can go wrong while acting as a proxy,
    /// hence we store `Result` objects inside of this vector.
    /// We deal with failures later on, when writing the session
    /// file.
    recorded_exchanges: Vec<Result<Exchange>>,

    rx: mpsc::Receiver<CallbackRequest>,
    tx: mpsc::Sender<CallbackRequest>,
    shutdown_channel: oneshot::Receiver<()>,
}

impl CallbackHandlerProxy {
    pub async fn new(
        mode: &ProxyMode,
        shutdown_channel: oneshot::Receiver<()>,
        sources: Option<Sources>,
        fulcio_and_rekor_data: Option<FulcioAndRekorData>,
        kube_client: Option<kube::Client>,
    ) -> Result<CallbackHandlerProxy> {
        // the channels used to interact with this callback handler.
        // consumers of these channels think they are interacting
        // with a regular `policy_evaluator` CallbackHandler, but
        // they are just talking with this proxy instance
        let (tx, rx) = mpsc::channel(200);

        Ok(Self {
            mode: mode.to_owned(),
            tx,
            rx,
            shutdown_channel,
            sources,
            fulcio_and_rekor_data,
            kube_client,
            recorded_exchanges: vec![],
        })
    }

    pub fn sender_channel(&self) -> mpsc::Sender<CallbackRequest> {
        self.tx.clone()
    }

    fn record_exchange(
        &mut self,
        request: Result<String>,
        response: std::result::Result<&CallbackResponse, &anyhow::Error>,
    ) {
        let exchange: Result<Exchange> = request
            .map(|req_str| {
                // the request is `Ok`. We have to convert the
                // response payload now
                response.map_or_else(
                    |resp_err| {
                        // host replied with an error (like trying to obtain the
                        // sigstore signature of an unsigned image). This is fine
                        Ok(Exchange {
                            request: req_str.clone(),
                            response: Response::Error {
                                message: resp_err.to_string(),
                            },
                        })
                    },
                    |resp| {
                        Ok(Exchange {
                            request: req_str.clone(),
                            response: Response::Success {
                                payload: String::from_utf8(resp.payload.clone()).map_err(|e| {
                                    anyhow!("cannot convert response payload to utf8: {}", e)
                                })?,
                            },
                        })
                    },
                )
            })
            .and_then(|exchange| {
                // the previous step returns a Result<Result<Exchange>>
                // because something can go wrong while converting the Response
                // payload (a Vec<u8>) to a UTF8 string.
                // This converts a Ok(Result<Exchange>) into a Result<Exchange>.
                // The conversion error would not be discarded.
                //
                // Note: we do this conversion because we want the final session
                // yaml file to be human readable. Shoving a Vec<u8> in there
                // would not help
                exchange
            });

        self.recorded_exchanges.push(exchange);
    }

    /// Write all the captured exchange messages to a file
    /// An error message is print to the stderr if there was some
    /// recording error
    fn dump_records(&self, destination: &PathBuf) {
        let errors: Vec<&anyhow::Error> = self
            .recorded_exchanges
            .iter()
            .filter_map(|exchange| exchange.as_ref().err())
            .collect();

        if !errors.is_empty() {
            error!(errors = ?errors, "Cannot record communication between host and policy, something went wrong while capturing the exchange");
        } else {
            let exchanges: Vec<&Exchange> = self
                .recorded_exchanges
                .iter()
                .filter_map(|exchange| exchange.as_ref().ok())
                .collect();
            match File::create(destination) {
                Err(e) => error!(e = ?e, ?destination, "Cannot save context aware session to file"),
                Ok(file) => match serde_yaml::to_writer(file, &exchanges) {
                    Ok(_) => info!(?destination, "Context aware session saved to file"),
                    Err(e) => error!(error = ?e, "Cannot save context aware session to file"),
                },
            }
        }
    }

    pub async fn loop_eval(&mut self) {
        match &self.mode {
            ProxyMode::Record { destination: _ } => self.loop_eval_recoder().await,
            ProxyMode::Replay { source: _ } => self.loop_eval_replay().await,
        }
    }

    /// The code used by the handler when running in `replay` mode
    async fn loop_eval_replay(&mut self) {
        // Note: in some cases we use `expect` here to panic at runtime.
        // We want the execution to be aborted if something
        // goes wrong here when dealing with channel message passing,
        // there's no nice way to handle errors here.

        let mut exchanges: VecDeque<Exchange> = if let ProxyMode::Replay { source } = &self.mode {
            let file = File::open(source).unwrap_or_else(|_| {
                panic!("Cannot open host capabilities interactions file {source:?}")
            });
            serde_yaml::from_reader(file)
                .unwrap_or_else(|_| panic!("cannot deserialize contents of {source:?}"))
        } else {
            // this should never happen
            unreachable!()
        };

        loop {
            tokio::select! {
                // place the shutdown check before the message evaluation,
                // as recommended by tokio's documentation about select!
                _ = &mut self.shutdown_channel => {
                    if !exchanges.is_empty() {
                        warn!(leftovers = ?exchanges, "Some of the recorded exchanges have not been replayed");
                    }
                    return;
                },
                maybe_req = self.rx.recv() => {
                    if let Some(req) = maybe_req {
                        let response = Self::produce_recorded_response(&req, &mut exchanges);

                        req.response_channel.send(response).expect("Cannot send back response to policy");
                    }
                }
            }
        }
    }

    fn produce_recorded_response(
        req: &CallbackRequest,
        exchanges: &mut VecDeque<Exchange>,
    ) -> Result<CallbackResponse> {
        match exchanges.pop_front() {
            None => Err(anyhow!("the list of recorded responses is empty")),
            Some(exchange) => {
                let expected_request: CallbackRequestType = serde_yaml::from_str(&exchange.request)
                    .expect("Cannot deserialize recorded request into `CallbackRequestType`");
                if expected_request == req.request {
                    match exchange.response {
                        Response::Success { payload } => Ok(CallbackResponse {
                            payload: payload.into_bytes(),
                        }),
                        Response::Error { message } => Err(anyhow!("{message}")),
                    }
                } else {
                    Err(anyhow!(
                        "Replay error: unexpected request. Was expecting {:?}, got {:?} instead",
                        expected_request,
                        req.request
                    ))
                }
            }
        }
    }

    /// The code used by the handler when running in `record` mode
    async fn loop_eval_recoder(&mut self) {
        // This is a channel used to stop the tokio task that is run
        // inside of the CallbackHandler
        let (callback_handler_shutdown_channel_tx, callback_handler_shutdown_channel_rx) =
            oneshot::channel();

        // Build the real CallbackHandler
        let mut callback_handler_builder =
            CallbackHandlerBuilder::new(callback_handler_shutdown_channel_rx)
                .registry_config(self.sources.clone())
                .fulcio_and_rekor_data(self.fulcio_and_rekor_data.as_ref());
        if let Some(kc) = &self.kube_client {
            callback_handler_builder = callback_handler_builder.kube_client(kc.to_owned());
        }

        let mut callback_handler = callback_handler_builder
            .build()
            .expect("cannot build callback handler");
        let callback_handler_sender = callback_handler.sender_channel();

        // Spawn the tokio task used by the real CallbackHandler
        tokio::spawn(async move {
            callback_handler.loop_eval().await;
        });

        // loop of the proxy handler
        loop {
            tokio::select! {
                // place the shutdown check before the message evaluation,
                // as recommended by tokio's documentation about select!
                _ = &mut self.shutdown_channel => {
                    match &self.mode {
                        ProxyMode::Record{destination} =>  self.dump_records(destination),
                        _ => unreachable!()
                    }
                    if let Err(e) = callback_handler_shutdown_channel_tx.send(()) {
                        error!(error = ?e, "Cannot shutdown the real callback_handler");
                    }
                    return;
                },
                maybe_req = self.rx.recv() => {
                    // Note: in some cases we use `expect` here to panic at runtime.
                    // We want the execution to be aborted if something
                    // goes wrong here when dealing with channel message passing,
                    // there's no nice way to handle errors here.

                    if let Some(req) = maybe_req {
                        let request = serde_yaml::to_string(&req.request)
                            .map_err(|e| {
                                // the recording is compromised, but we will
                                // not panic here. We record the error and keep
                                // going with the policy execution.
                                // We will inform the user once policy execution
                                // is done and the session file is created.
                                // See `dump_records` method
                                anyhow!("cannot convert request to yaml: {}", e)
                            });

                        // Create a CallbackRequest object based on the incoming
                        // request. This is sent to the real CallbackHandler,
                        // we have to provide a different `response_channel`
                        // because we want to intercept the response
                        let (response_tx, response_rx) = oneshot::channel::<Result<CallbackResponse>>();
                        let proxy_req = CallbackRequest {
                            request: req.request,
                            response_channel: response_tx,
                        };

                        // forward the message to the real CallbackHandler,
                        // here we panic if the message cannot be sent. There's
                        // no purpose in going forward if the communication
                        // with the real CallbackHandler doesn't work
                        callback_handler_sender
                            .send(proxy_req)
                            .await
                            .expect("cannot forward request to real callback handler");

                        // same here, if we cannot get a response from the
                        // real CallbackHandler there's no reason to keep
                        // going. We can interrupt the execution if something
                        // goes wrong.
                        let response = response_rx
                            .await
                            .expect("failure while waiting for response from real callback_handler");

                        self.record_exchange(request, response.as_ref());

                        // Send back the response to the policy. Also in this
                        // case there's no nice way to recover from this error.
                        // We can interrupt the execution if something goes wrong.
                        req.response_channel
                            .send(response)
                            .expect("Cannot send back response to policy");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_response_no_more_records() {
        let mut exchanges: VecDeque<Exchange> = VecDeque::new();

        let (response_tx, _) = oneshot::channel::<Result<CallbackResponse>>();
        let request = CallbackRequest {
            request: CallbackRequestType::DNSLookupHost {
                host: "kubewarden.io".to_string(),
            },
            response_channel: response_tx,
        };

        let response = CallbackHandlerProxy::produce_recorded_response(&request, &mut exchanges);
        assert!(response.is_err());
        let err = response.unwrap_err();

        // we cannot return specialized errros because of the waPC contract
        // hence we have to unfortunately look at the error string
        assert!(err.to_string().as_str().contains("empty"));
    }

    #[test]
    fn record_response_unexpected_request() {
        let expected_request = CallbackRequestType::OciManifestDigest {
            image: "busybox".to_string(),
        };
        let expected_exchange = Exchange {
            request: serde_yaml::to_string(&expected_request)
                .expect("cannot serialize expected request"),
            response: Response::Success {
                payload: "not relevant".to_string(),
            },
        };

        let mut exchanges: VecDeque<Exchange> = VecDeque::new();
        exchanges.push_front(expected_exchange);

        let (response_tx, _) = oneshot::channel::<Result<CallbackResponse>>();
        let request = CallbackRequest {
            request: CallbackRequestType::DNSLookupHost {
                host: "kubewarden.io".to_string(),
            },
            response_channel: response_tx,
        };

        let response = CallbackHandlerProxy::produce_recorded_response(&request, &mut exchanges);
        assert!(response.is_err());
        let err = response.unwrap_err();

        // we cannot return specialized errros because of the waPC contract
        // hence we have to unfortunately look at the error string
        assert!(err.to_string().as_str().contains("unexpected request"));
    }

    #[test]
    fn record_response_replay_successful_response() {
        let request = CallbackRequestType::OciManifestDigest {
            image: "busybox".to_string(),
        };
        let expected_payload = "hello world".to_string();
        let exchange = Exchange {
            request: serde_yaml::to_string(&request).expect("cannot serialize request"),
            response: Response::Success {
                payload: expected_payload.clone(),
            },
        };

        let mut exchanges: VecDeque<Exchange> = VecDeque::new();
        exchanges.push_front(exchange);

        let (response_tx, _) = oneshot::channel::<Result<CallbackResponse>>();
        let request = CallbackRequest {
            request,
            response_channel: response_tx,
        };

        let response = CallbackHandlerProxy::produce_recorded_response(&request, &mut exchanges)
            .expect("should not be an error");
        assert_eq!(response.payload, expected_payload.into_bytes());
    }

    #[test]
    fn record_response_replay_errored_response() {
        let request = CallbackRequestType::OciManifestDigest {
            image: "busybox".to_string(),
        };
        let expected_err_msg = "something went wrong".to_string();
        let exchange = Exchange {
            request: serde_yaml::to_string(&request).expect("cannot serialize request"),
            response: Response::Error {
                message: expected_err_msg.clone(),
            },
        };

        let mut exchanges: VecDeque<Exchange> = VecDeque::new();
        exchanges.push_front(exchange);

        let (response_tx, _) = oneshot::channel::<Result<CallbackResponse>>();
        let request = CallbackRequest {
            request,
            response_channel: response_tx,
        };

        let response = CallbackHandlerProxy::produce_recorded_response(&request, &mut exchanges);
        assert!(response.is_err());
        let err = response.unwrap_err();
        assert_eq!(err.to_string(), expected_err_msg);
    }
}

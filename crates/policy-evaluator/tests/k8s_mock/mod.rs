mod fixtures;

use hyper::{http, Body, Request, Response};
use serde::Serialize;
use tower_test::mock::{Handle, SendResponse};

pub(crate) async fn wapc_and_wasi_scenario(handle: Handle<Request<Body>, Response<Body>>) {
    tokio::spawn(async move {
        let mut handle = handle;

        loop {
            let (request, send) = handle.next_request().await.expect("service not called");

            match (request.method(), request.uri().path()) {
                (&http::Method::GET, "/api/v1") => {
                    send_response(send, fixtures::v1_resource_list());
                }
                (&http::Method::GET, "/apis/apps/v1") => {
                    send_response(send, fixtures::apps_v1_resource_list());
                }
                (&http::Method::GET, "/api/v1/namespaces") => {
                    send_response(send, fixtures::namespaces());
                }
                (&http::Method::GET, "/apis/apps/v1/namespaces/customer-1/deployments") => {
                    send_response(send, fixtures::deployments());
                }
                (&http::Method::GET, "/api/v1/namespaces/customer-1/services/api-auth-service") => {
                    send_response(send, fixtures::api_auth_service());
                }
                _ => {
                    panic!("unexpected request: {:?}", request);
                }
            }
        }
    });
}

pub(crate) async fn rego_scenario(handle: Handle<Request<Body>, Response<Body>>) {
    tokio::spawn(async move {
        let mut handle = handle;

        loop {
            let (request, send) = handle.next_request().await.expect("service not called");

            match (request.method(), request.uri().path()) {
                (&http::Method::GET, "/api/v1") => {
                    send_response(send, fixtures::v1_resource_list());
                }
                (&http::Method::GET, "/apis/apps/v1") => {
                    send_response(send, fixtures::apps_v1_resource_list());
                }
                (&http::Method::GET, "/api/v1/namespaces") => {
                    send_response(send, fixtures::namespaces());
                }
                (&http::Method::GET, "/apis/apps/v1/deployments") => {
                    send_response(send, fixtures::deployments());
                }
                (&http::Method::GET, "/api/v1/services") => {
                    send_response(send, fixtures::services());
                }

                _ => {
                    panic!("unexpected request: {:?}", request);
                }
            }
        }
    });
}

fn send_response<T: Serialize>(send: SendResponse<Response<Body>>, response: T) {
    let response = serde_json::to_vec(&response).unwrap();
    send.send_response(Response::builder().body(Body::from(response)).unwrap());
}

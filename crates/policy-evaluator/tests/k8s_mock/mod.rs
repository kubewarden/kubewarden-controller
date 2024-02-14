mod fixtures;

use std::collections::HashMap;

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
            let url = url::Url::parse(&format!("https://localhost{}", request.uri()))
                .expect("cannot parse incoming request");

            let query_params: HashMap<String, String> = url.query_pairs().into_owned().collect();
            let is_watch_request = query_params.contains_key("watch");
            let watch_resource_version = query_params.get("resourceVersion");

            match (request.method(), request.uri().path(), is_watch_request) {
                (&http::Method::GET, "/api/v1", false) => {
                    send_response(send, fixtures::v1_resource_list());
                }
                (&http::Method::GET, "/apis/apps/v1", false) => {
                    send_response(send, fixtures::apps_v1_resource_list());
                }
                (&http::Method::GET, "/api/v1/namespaces", false) => {
                    send_response(send, fixtures::namespaces());
                }
                (&http::Method::GET, "/api/v1/namespaces", true) => {
                    send_response(
                        send,
                        fixtures::namespaces_watch_bookmark(watch_resource_version.unwrap()),
                    );
                }
                (&http::Method::GET, "/apis/apps/v1/deployments", false) => {
                    send_response(send, fixtures::deployments());
                }
                (&http::Method::GET, "/apis/apps/v1/deployments", true) => {
                    send_response(
                        send,
                        fixtures::deployments_watch_bookmark(watch_resource_version.unwrap()),
                    );
                }
                (&http::Method::GET, "/api/v1/services", false) => {
                    send_response(send, fixtures::services());
                }
                (&http::Method::GET, "/api/v1/services", true) => {
                    send_response(
                        send,
                        fixtures::services_watch_bookmark(watch_resource_version.unwrap()),
                    );
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

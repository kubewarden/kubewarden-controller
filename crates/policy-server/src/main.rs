use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::{net::SocketAddr, thread};
use tokio::sync::mpsc;

mod admission_review;
mod api;
mod wasm;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let (tx, mut rx) = mpsc::channel::<wasm::EvalRequest>(32);

    let handle = tokio::runtime::Handle::current();

    let wasm_thread = thread::spawn(move || {
        let mut policy_evaluator = wasm::PolicyEvaluator::new(String::from("guest.wasm")).unwrap();
        handle.block_on(async move {
            while let Some(req) = rx.recv().await {
                let resp = policy_evaluator.validate(req.req);
                let _ = req.resp_chan.send(resp);
            }
        });
    });

    let make_svc = make_service_fn(|_conn| {
        let svc_tx = tx.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| api::route(req, svc_tx.clone()))) }
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!("Started server on {}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    wasm_thread.join().unwrap();
}

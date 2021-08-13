pub(crate) struct DefaultHostCallbacks;

impl DefaultHostCallbacks {
    pub(crate) fn opa_abort(msg: serde_json::Value) {
        println!("OPA abort with message: {:?}", msg);
        std::process::exit(1);
    }

    pub(crate) fn opa_println(msg: serde_json::Value) {
        println!("Message coming from the policy: {:?}", msg);
    }
}

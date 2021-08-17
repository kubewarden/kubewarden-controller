pub(crate) struct DefaultHostCallbacks;

impl DefaultHostCallbacks {
    pub(crate) fn opa_abort(msg: String) {
        println!("OPA abort with message: {:?}", msg);
        std::process::exit(1);
    }

    pub(crate) fn opa_println(msg: String) {
        println!("Message coming from the policy: {:?}", msg);
    }
}

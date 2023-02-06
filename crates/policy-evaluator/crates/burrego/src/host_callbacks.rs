/// HostCallback is a type that references a pointer to a function
/// that can be stored and then invoked by burrego when the Open
/// Policy Agent Wasm target invokes certain Wasm imports.
pub type HostCallback = fn(&str);

/// HostCallbacks defines a set of pluggable host implementations of
/// OPA documented imports:
/// https://www.openpolicyagent.org/docs/latest/wasm/#imports
#[derive(Clone)]
pub struct HostCallbacks {
    pub opa_abort: HostCallback,
    pub opa_println: HostCallback,
}

impl Default for HostCallbacks {
    fn default() -> HostCallbacks {
        HostCallbacks {
            opa_abort: default_opa_abort,
            opa_println: default_opa_println,
        }
    }
}

fn default_opa_abort(msg: &str) {
    eprintln!("OPA abort with message: {msg:?}");
}

fn default_opa_println(msg: &str) {
    println!("Message coming from the policy: {msg:?}");
}

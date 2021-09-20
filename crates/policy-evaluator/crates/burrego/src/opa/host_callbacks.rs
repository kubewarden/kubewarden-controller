use lazy_static::lazy_static;

lazy_static! {
    pub static ref DEFAULT_HOST_CALLBACKS: HostCallbacks = HostCallbacks::default();
}

/// HostCallback is a type that references a pointer to a function
/// that can be stored and then invoked by burrego when the Open
/// Policy Agent Wasm target invokes certain Wasm imports.
pub type HostCallback = Box<dyn Fn(String) + Send + Sync + 'static>;

/// HostCallbacks defines a set of pluggable host implementations of
/// OPA documented imports:
/// https://www.openpolicyagent.org/docs/latest/wasm/#imports
pub struct HostCallbacks {
    pub opa_abort: HostCallback,
    pub opa_println: HostCallback,
}

use lazy_static::lazy_static;

use crate::opa::default_host_callbacks::DefaultHostCallbacks;

lazy_static! {
    pub static ref DEFAULT_HOST_CALLBACKS: HostCallbacks = HostCallbacks::default();
}

pub type HostCallback = Box<dyn Fn(serde_json::Value) + Send + Sync + 'static>;

pub struct HostCallbacks {
    pub opa_abort: HostCallback,
    pub opa_println: HostCallback,
}

impl Default for HostCallbacks {
    fn default() -> HostCallbacks {
        HostCallbacks {
            opa_abort: Box::new(DefaultHostCallbacks::opa_abort),
            opa_println: Box::new(DefaultHostCallbacks::opa_println),
        }
    }
}

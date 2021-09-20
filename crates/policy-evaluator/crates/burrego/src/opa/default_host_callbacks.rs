pub(crate) struct DefaultHostCallbacks;

use crate::opa::host_callbacks::HostCallbacks;

impl Default for HostCallbacks {
    fn default() -> HostCallbacks {
        HostCallbacks {
            opa_abort: Box::new(DefaultHostCallbacks::opa_abort),
            opa_println: Box::new(DefaultHostCallbacks::opa_println),
        }
    }
}

impl DefaultHostCallbacks {
    pub(crate) fn opa_abort(msg: String) {
        println!("OPA abort with message: {:?}", msg);
    }

    pub(crate) fn opa_println(msg: String) {
        println!("Message coming from the policy: {:?}", msg);
    }
}

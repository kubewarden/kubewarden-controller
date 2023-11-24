/// This module provides helper functions and data structures used to keep track of the waPC
/// policies being instantiated. This is all modelled to optimize the Policy Server scenario,
/// although everything works fine also with kwctl.
///
///
/// ## The problem
///
/// In the Policy Server scenario, we have multiple workers. Each one of them living inside of
/// their own dedicated thread.
///
/// Given a unique list of waPC policies, a worker will instantiate only one wapc runtime per
/// policy. This is done to reduce the amount of memory consumed by Policy Server.
/// Later, when inside of the [`host_callback`](crate::runtimes::wapc::callback::host_callback) function,
/// we receive a `wapc_id` and the details about an operation that has to be run by the Wasm
/// host. When that happens, we need to access some auxiliary information about the policy being
/// evaluated. For example, if a policy is requesting "list all the Kubernetes Secret objects
/// inside of the `kube-system` Namespace", we need to know if the administrator granted access to
/// Kubernetes Secret to the policy.
/// The auxiliary information are stored inside of a `EvaluationContext` object.
///
/// ## The data structures
///
/// This module defines two global variables that hold all the information required by `host_callback` to
/// obtain the `EvaluationContext` instance associated with a waPC policy. All of that by just
/// doing a series of lookups based on the `wapc_id` associated with the policy.
///
/// The `WAPC_ID_TO_WORKER_ID` structure contains the relationship waPC policy -> worker.
/// Given a waPC policy ID, we can discover to which worker it belongs.
/// Then, using the `WORKER_ID_TO_CTX` structure, we find the `EvaluationContext` associated with a
/// certain worker.
///
/// ## Workflow
///
/// ### Policy registration
///
/// As soon as a waPC policy is created, the following information have to be inserted into the
/// registry:
///   - wapc ID
///   - ID of the worker that owns the policy
///   - The first `EvaluationContext` to be used
///
/// ### Validate request/settings
///
/// Prior to invoking the `validate`/`validate_settings` functions exposed by a policy, the worker
/// must inform the registry about the `EvaluationContext` that it's going to be used during the
/// evaluation. This ensures the `host_callback`, if ever called by policy, obtains the right
/// auxiliary information.
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};
use tracing::debug;

use crate::evaluation_context::EvaluationContext;

lazy_static! {
    /// A map with wapc_id as key, and the worker_id as value. It allows us to know to which
    /// worker a waPC policy belongs. When inside of the
    /// [`host_callback`](crate::runtimes::wapc::callback::host_callback) function,
    /// we need to know the `EvaluationContext` to be used
    static ref WAPC_ID_TO_WORKER_ID: RwLock<HashMap<u64, u64>> = RwLock::new(HashMap::new());

    /// A Map with worker_id as key, and the current `EvaluationContext` as value
    static ref WORKER_ID_TO_CTX: RwLock<HashMap<u64, Arc<RwLock<EvaluationContext>>>> =
        RwLock::new(HashMap::new());

    /// A Map with worker_id as key, and a counter as value. This is used to keep track of how
    /// many waPC policies are currently assigned to a worker. This is used to garbage collect
    /// entries inside of the WORKER_ID_TO_CTX map. More details inside of the `unregister_policy`
    /// function below
    static ref WORKER_ID_TO_ACTIVE_POLICIES_COUNTER: RwLock<HashMap<u64, Arc<AtomicU64>>> = RwLock::new(HashMap::new());
}

/// Register a waPC policy inside of the global registry
pub(crate) fn register_policy(
    wapc_id: u64,
    worker_id: u64,
    eval_ctx: Arc<RwLock<EvaluationContext>>,
) {
    let mut map = WAPC_ID_TO_WORKER_ID.write().unwrap();
    map.insert(wapc_id, worker_id);
    debug!(
        wapc_id,
        worker_id, "registered waPC policy inside of global registry"
    );

    let mut map = WORKER_ID_TO_CTX.write().unwrap();
    map.insert(worker_id, eval_ctx);
    debug!(worker_id, "registered evaluation context");

    let mut map = WORKER_ID_TO_ACTIVE_POLICIES_COUNTER.write().unwrap();
    map.entry(worker_id)
        .and_modify(|counter| {
            let _ = counter.fetch_add(1, Ordering::Relaxed);
        })
        .or_insert(Arc::new(AtomicU64::new(1)));
}

/// Set the evaluation context used by worker. To be invoked **before** starting a policy
/// `validate` or `validate_settings` operation
pub(crate) fn set_worker_ctx(worker_id: u64, evaluation_context: &EvaluationContext) {
    let map = WORKER_ID_TO_CTX.read().unwrap();
    let mut ctx = map
        .get(&worker_id)
        .expect("cannot find worker")
        .write()
        .unwrap();
    ctx.copy_from(evaluation_context);
}

/// Removes a policy from the registry. To be used only when the policy is no longer being used
pub(crate) fn unregister_policy(wapc_id: u64) {
    let mut map = WAPC_ID_TO_WORKER_ID.write().unwrap();
    let worker_id = match map.remove(&wapc_id) {
        Some(id) => id,
        None => {
            // Should not happen, the policy has already been dropped or wasn't known
            return;
        }
    };

    let mut map = WORKER_ID_TO_ACTIVE_POLICIES_COUNTER.write().unwrap();
    let counter = match map.get_mut(&worker_id) {
        Some(counter) => counter,
        None => {
            // Should not happen, the worker_id has already been unregistered
            return;
        }
    };

    let active_policies_for_worker = counter.fetch_sub(1, Ordering::Relaxed);
    if active_policies_for_worker == 0 {
        // We can remove the worker entry from WORKER_ID_TO_CTX, which will release the
        // reference made against the EvaluationContext, avoiding a memory leak of this struct
        let _ = WORKER_ID_TO_CTX.write().unwrap().remove(&worker_id);
    }
}

/// Find which worker owns the given waPC policy
pub(crate) fn get_worker_id(wapc_id: u64) -> Result<u64> {
    let mapping = WAPC_ID_TO_WORKER_ID.read().unwrap();

    mapping
        .get(&wapc_id)
        .ok_or_else(|| anyhow!("cannot find policy with ID {}", wapc_id))
        .cloned()
}

/// Given a waPC policy ID, find the evaluation context associated with it
pub(crate) fn get_eval_ctx(wapc_id: u64) -> EvaluationContext {
    let worker_id = {
        let map = WAPC_ID_TO_WORKER_ID.read().unwrap();

        map.get(&wapc_id)
            .expect("cannot find policy inside of WAPC_ID_TO_WORKER_ID")
            .to_owned()
    };

    let map = WORKER_ID_TO_CTX.read().unwrap();
    let ctx = map
        .get(&worker_id)
        .expect("cannot find worker")
        .read()
        .unwrap();
    ctx.to_owned()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use test_context::{test_context, TestContext};

    pub(crate) fn is_wapc_instance_registered(wapc_id: u64) -> bool {
        let map = WAPC_ID_TO_WORKER_ID.read().unwrap();
        map.contains_key(&wapc_id)
    }

    struct TestCtx {
        evaluation_context: Arc<RwLock<EvaluationContext>>,
    }

    impl TestContext for TestCtx {
        fn setup() -> TestCtx {
            let evaluation_context = Arc::new(RwLock::new(EvaluationContext {
                policy_id: "test".to_string(),
                callback_channel: None,
                ctx_aware_resources_allow_list: BTreeSet::new(),
            }));

            TestCtx { evaluation_context }
        }

        fn teardown(self) {
            // wipe all the registries
            WAPC_ID_TO_WORKER_ID.write().unwrap().clear();
            WORKER_ID_TO_CTX.write().unwrap().clear();
            WORKER_ID_TO_ACTIVE_POLICIES_COUNTER
                .write()
                .unwrap()
                .clear();
        }
    }

    fn verify_registry_contents(
        wapc_id: u64,
        expected_worker_id: u64,
        expected_worker_policy_counter: u64,
        expected_eval_ctx_policy_id: &str,
    ) {
        assert_eq!(expected_worker_id, get_worker_id(wapc_id).unwrap());

        let actual_ctx = get_eval_ctx(wapc_id);
        assert_eq!(
            expected_eval_ctx_policy_id.to_string(),
            actual_ctx.policy_id
        );

        let map = WORKER_ID_TO_ACTIVE_POLICIES_COUNTER.read().unwrap();
        let policy_counter = map.get(&expected_worker_id).unwrap();
        assert_eq!(
            expected_worker_policy_counter,
            policy_counter.load(Ordering::Relaxed)
        );
    }

    #[test_context(TestCtx)]
    fn register_policy_initializes_internal_structures(test_ctx: &mut TestCtx) {
        let wapc_id = 1;
        let worker_a_id = 100;
        let expected_policy_id = test_ctx
            .evaluation_context
            .clone()
            .read()
            .unwrap()
            .policy_id
            .clone();
        register_policy(wapc_id, worker_a_id, test_ctx.evaluation_context.clone());
        verify_registry_contents(wapc_id, worker_a_id, 1, &expected_policy_id);

        // register another policy against the same worker
        let wapc_id = 2;
        register_policy(wapc_id, worker_a_id, test_ctx.evaluation_context.clone());
        verify_registry_contents(wapc_id, 100, 2, &expected_policy_id);

        // register another policy against a new worker
        let new_wapc_id = 3;
        let worker_b_id = 200;
        register_policy(
            new_wapc_id,
            worker_b_id,
            test_ctx.evaluation_context.clone(),
        );
        verify_registry_contents(new_wapc_id, worker_b_id, 1, &expected_policy_id);
        verify_registry_contents(wapc_id, worker_a_id, 2, &expected_policy_id);
    }

    #[test_context(TestCtx)]
    fn change_worker_context(test_ctx: &mut TestCtx) {
        let wapc_id = 1;
        let worker_id = 100;
        let expected_policy_id = test_ctx
            .evaluation_context
            .clone()
            .read()
            .unwrap()
            .policy_id
            .clone();
        register_policy(wapc_id, worker_id, test_ctx.evaluation_context.clone());
        verify_registry_contents(wapc_id, worker_id, 1, &expected_policy_id);

        let new_policy_id = "a new one".to_string();
        let mut new_evaluation_context: EvaluationContext = {
            // the fixture returns a RWLock, we just need a plain EvaluationContext that we can
            // change
            test_ctx.evaluation_context.clone().write().unwrap().clone()
        };

        new_evaluation_context.policy_id = new_policy_id.clone();
        set_worker_ctx(worker_id, &new_evaluation_context);
        verify_registry_contents(wapc_id, worker_id, 1, &new_policy_id);
    }

    #[test_context(TestCtx)]
    fn test_unregister_policies(test_ctx: &mut TestCtx) {
        let worker_id = 100;
        let num_of_policies = 10;
        for wapc_id in 0..num_of_policies {
            register_policy(wapc_id, worker_id, test_ctx.evaluation_context.clone());
        }

        {
            // ensure the read lock goes out of scope
            let map = WORKER_ID_TO_ACTIVE_POLICIES_COUNTER.read().unwrap();
            let counter = map.get(&worker_id).unwrap().load(Ordering::Relaxed);
            assert_eq!(counter, num_of_policies);
        }

        // start dropping the policies, one by one
        let mut expected_number_of_policies = num_of_policies;
        for wapc_id in 0..num_of_policies {
            unregister_policy(wapc_id);
            expected_number_of_policies -= 1;

            {
                // ensure the read lock goes out of scope
                let map = WORKER_ID_TO_ACTIVE_POLICIES_COUNTER.read().unwrap();
                let counter = map.get(&worker_id).unwrap().load(Ordering::Relaxed);
                assert_eq!(counter, expected_number_of_policies);
            }
        }

        // the worker should have 0 policies associated
        let map = WORKER_ID_TO_ACTIVE_POLICIES_COUNTER.read().unwrap();
        let counter = map.get(&worker_id).unwrap().load(Ordering::Relaxed);
        assert_eq!(counter, 0);

        // the structure holding the worker_id => ctx should not have any reference to
        // the worker id
        let map = WORKER_ID_TO_CTX.read().unwrap();
        assert!(map.get(&worker_id).is_none());
    }
}

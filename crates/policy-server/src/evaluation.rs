pub(crate) mod errors;
mod evaluation_environment;
mod policy_evaluation_settings;
pub(crate) mod precompiled_policy;

// This is required to mock the `EvaluationEnvironment` inside of our tests
#[mockall_double::double]
pub(crate) use evaluation_environment::EvaluationEnvironment;

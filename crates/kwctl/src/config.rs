pub(crate) mod policy_definition;
pub(crate) mod pull_and_run;
pub(crate) mod sources;
pub(crate) mod verification;

#[derive(Default)]
pub(crate) enum HostCapabilitiesMode {
    #[default]
    Direct,
    Proxy(crate::callback_handler::ProxyMode),
}

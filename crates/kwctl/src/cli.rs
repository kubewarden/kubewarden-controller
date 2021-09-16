use clap::{clap_app, crate_authors, crate_description, crate_name, crate_version, AppSettings};
use itertools::Itertools;
use lazy_static::lazy_static;
use policy_evaluator::burrego::opa::builtins as opa_builtins;

lazy_static! {
    static ref VERSION_AND_BUILTINS: String = {
        let builtins: String = opa_builtins::get_builtins()
            .keys()
            .sorted()
            .map(|builtin| format!("  - {}", builtin))
            .join("\n");

        format!(
            "{}\n\nOpen Policy Agent/Gatekeeper implemented builtins:\n{}",
            crate_version!(),
            builtins,
        )
    };
}

pub fn build_cli() -> clap::App<'static, 'static> {
    clap_app!(
        (crate_name!()) =>
            (author: crate_authors!(",\n"))
            (about: crate_description!())
            (@arg verbose: -v "Increase verbosity")
            (@subcommand policies =>
             (about: "Lists all downloaded policies")
            )
            (@subcommand pull =>
             (about: "Pulls a Kubewarden policy from a given URI")
             (@arg ("docker-config-json-path"): --("docker-config-json-path") +takes_value "Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
             (@arg ("sources-path"): --("sources-path") +takes_value "YAML file holding source information (https, registry insecure hosts, custom CA's...)")
             (@arg ("output-path"): -o --("output-path") +takes_value "Output file. If not provided will be downloaded to the Kubewarden store")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://, https://, file://")
            )
            (@subcommand push =>
             (about: "Pushes a Kubewarden policy to an OCI registry")
             (@arg ("docker-config-json-path"): --("docker-config-json-path") +takes_value "Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
             (@arg ("force"): -f --("force") "push also a policy that is not annotated")
             (@arg ("sources-path"): --("sources-path") +takes_value "YAML file holding source information (https, registry insecure hosts, custom CA's...)")
             (@arg ("policy"): * "Policy to push. Can be the path to a local file, or a policy URI")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://")
            )
            (@subcommand rm =>
             (about: "Removes a Kubewarden policy from the store")
             (@arg ("uri"): * "Policy URI")
            )
            (@subcommand run =>
             (about: "Runs a Kubewarden policy from a given URI")
             (@arg ("docker-config-json-path"): --("docker-config-json-path") +takes_value "Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
             (@arg ("sources-path"): --("sources-path") +takes_value "YAML file holding source information (https, registry insecure hosts, custom CA's...)")
             (@arg ("request-path"): * -r --("request-path") +takes_value "File containing the Kubernetes admission request object in JSON format")
             (@arg ("settings-path"): -s --("settings-path") +takes_value "File containing the settings for this policy")
             (@arg ("settings-json"): --("settings-json") +takes_value "JSON string containing the settings for this policy")
             (@arg ("execution-mode"): -e --("execution-mode") +takes_value "The runtime to use to execute this policy")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory")
            )
            (@subcommand annotate =>
             (about: "Add Kubewarden metadata to a WebAssembly module")
             (@arg ("metadata-path"): * -m --("metadata-path") +takes_value "File containing the metadata")
             (@arg ("wasm-path"): * "Path to WebAssembly module to be annotated")
             (@arg ("output-path"): * -o --("output-path") +takes_value "Output file")
            )
            (@subcommand inspect =>
             (about: "Inspect Kubewarden policy")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://, https://, file://")
             (@arg ("output"): -o --("output") +takes_value "output format. One of: yaml")
            )
            (@subcommand manifest =>
             (about: "Scaffold a Kubernetes resource")
             (@arg ("settings-path"): -s --("settings-path") +takes_value "File containing the settings for this policy")
             (@arg ("settings-json"): --("settings-json") +takes_value "JSON string containing the settings for this policy")
             (@arg ("type"): * -t --("type") +takes_value "Kubewarden Custom Resource type. Valid values: ClusterAdmissionPolicy")
             (@arg ("uri"): * "Policy URI. Supported schemes: registry://, https://, file://")
            )
            (@subcommand completions =>
             (about: "Generate shell completions")
             (@arg ("shell"): * -s --("shell") +takes_value "Shell type: bash, fish, zsh, elvish, powershell")
            )
    )
        .long_version(VERSION_AND_BUILTINS.as_str())
        .setting(AppSettings::SubcommandRequiredElseHelp)
}

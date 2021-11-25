use clap::{
    crate_authors, crate_description, crate_name, crate_version, App, AppSettings, Arg, SubCommand,
};
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
    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("verbose").short("v").help("Increase verbosity"))
        .subcommand(
            SubCommand::with_name("policies")
                .about("Lists all downloaded policies")
        )
        .subcommand(
            SubCommand::with_name("pull")
                .about("Pulls a Kubewarden policy from a given URI")
                .arg(
                    Arg::with_name("docker-config-json-path")
                    .long("docker-config-json-path")
                    .takes_value(true)
                    .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
                )
                .arg(
                    Arg::with_name("sources-path")
                    .long("sources-path")
                    .takes_value(true)
                    .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)")
                )
                .arg(
                    Arg::with_name("verification-key")
                    .short("k")
                    .long("verification-key")
                    .multiple(true)
                    .number_of_values(1)
                    .takes_value(true)
                    .help("Path to key used to verify the policy. Can be repeated multiple times")
                )
                .arg(
                    Arg::with_name("verification-annotation")
                    .short("a")
                    .long("verification-annotation")
                    .multiple(true)
                    .number_of_values(1)
                    .takes_value(true)
                    .help("Annotation in key=value format. Can be repeated multiple times")
                )
                .arg(
                    Arg::with_name("output-path")
                    .short("o")
                    .long("output-path")
                    .takes_value(true)
                    .help("Output file. If not provided will be downloaded to the Kubewarden store")
                )
                .arg(
                    Arg::with_name("uri")
                        .required(true)
                        .index(1)
                        .help("Policy URI. Supported schemes: registry://, https://, file://")
                )
        )
        .subcommand(
            SubCommand::with_name("verify")
                .about("Verify a Kubewarden policy from a given URI using Sigstore")
                .arg(
                    Arg::with_name("docker-config-json-path")
                    .long("docker-config-json-path")
                    .takes_value(true)
                    .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
                )
                .arg(
                    Arg::with_name("sources-path")
                    .long("sources-path")
                    .takes_value(true)
                    .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)")
                )
                .arg(
                    Arg::with_name("verification-key")
                    .short("k")
                    .long("verification-key")
                    .multiple(true)
                    .number_of_values(1)
                    .takes_value(true)
                    .required(true)
                    .help("Path to key used to verify the policy. Can be repeated multiple times")
                )
                .arg(
                    Arg::with_name("verification-annotation")
                    .short("a")
                    .long("verification-annotation")
                    .multiple(true)
                    .number_of_values(1)
                    .takes_value(true)
                    .help("Annotation in key=value format. Can be repeated multiple times")
                )
                .arg(
                    Arg::with_name("uri")
                        .required(true)
                        .index(1)
                        .help("Policy URI. Supported schemes: registry://")
                )
        )
        .subcommand(
            SubCommand::with_name("push")
                .about("Pushes a Kubewarden policy to an OCI registry")
                .arg(
                    Arg::with_name("docker-config-json-path")
                    .long("docker-config-json-path")
                    .takes_value(true)
                    .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
                )
                .arg(
                    Arg::with_name("sources-path")
                    .long("sources-path")
                    .takes_value(true)
                    .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)")
                )
                .arg(
                    Arg::with_name("force")
                    .short("f")
                    .long("force")
                    .help("Push also a policy that is not annotated")
                )
               .arg(
                    Arg::with_name("policy")
                        .required(true)
                        .index(1)
                        .help("Policy to push. Can be the path to a local file, or a policy URI")
                )
               .arg(
                    Arg::with_name("uri")
                        .required(true)
                        .index(2)
                        .help("Policy URI. Supported schemes: registry://")
                )
        )
        .subcommand(
            SubCommand::with_name("rm")
                .about("Removes a Kubewarden policy from the store")
                .arg(
                    Arg::with_name("uri")
                        .required(true)
                        .index(1)
                        .help("Policy URI")
                )
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Runs a Kubewarden policy from a given URI")
                .arg(
                    Arg::with_name("docker-config-json-path")
                    .long("docker-config-json-path")
                    .takes_value(true)
                    .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details")
                )
                .arg(
                    Arg::with_name("sources-path")
                    .long("sources-path")
                    .takes_value(true)
                    .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)")
                )
                .arg(
                    Arg::with_name("request-path")
                    .long("request-path")
                    .short("r")
                    .required(true)
                    .takes_value(true)
                    .help("File containing the Kubernetes admission request object in JSON format")
                )
                .arg(
                    Arg::with_name("settings-path")
                    .long("settings-path")
                    .short("s")
                    .takes_value(true)
                    .help("File containing the settings for this policy")
                )
                .arg(
                    Arg::with_name("settings-json")
                    .long("settings-json")
                    .takes_value(true)
                    .help("JSON string containing the settings for this policy")
                )
                .arg(
                    Arg::with_name("verification-key")
                    .short("k")
                    .long("verification-key")
                    .multiple(true)
                    .number_of_values(1)
                    .takes_value(true)
                    .help("Path to key used to verify the policy. Can be repeated multiple times")
                )
                .arg(
                    Arg::with_name("verification-annotation")
                    .short("a")
                    .long("verification-annotation")
                    .multiple(true)
                    .number_of_values(1)
                    .takes_value(true)
                    .help("Annotation in key=value format. Can be repeated multiple times")
                )
                .arg(
                    Arg::with_name("execution-mode")
                    .long("execution-mode")
                    .short("e")
                    .takes_value(true)
                    .possible_values(&["opa","gatekeeper", "kubewarden"])
                    .help("The runtime to use to execute this policy")
                )
                .arg(
                    Arg::with_name("uri")
                        .required(true)
                        .index(1)
                        .help("Policy URI. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory")
                )
        )
        .subcommand(
            SubCommand::with_name("annotate")
                .about("Add Kubewarden metadata to a WebAssembly module")
                .arg(
                    Arg::with_name("metadata-path")
                    .long("metadata-path")
                    .short("m")
                    .required(true)
                    .takes_value(true)
                    .help("File containing the metadata")
                )
                .arg(
                    Arg::with_name("output-path")
                    .long("output-path")
                    .short("o")
                    .required(true)
                    .takes_value(true)
                    .help("Output file")
                )
                .arg(
                    Arg::with_name("wasm-path")
                    .long("wasm-path")
                    .required(true)
                    .index(1)
                    .help("Path to WebAssembly module to be annotated")
                )
        )
        .subcommand(
            SubCommand::with_name("inspect")
                .about("Inspect Kubewarden policy")
                .arg(
                    Arg::with_name("output")
                    .long("output")
                    .short("o")
                    .takes_value(true)
                    .possible_values(&["yaml"])
                    .help("Output format")
                )
                .arg(
                    Arg::with_name("uri")
                        .required(true)
                        .index(1)
                        .help("Policy URI. Supported schemes: registry://, https://, file://")
                )
        )
        .subcommand(
            SubCommand::with_name("manifest")
                .about("Scaffold a Kubernetes resource")
                .arg(
                    Arg::with_name("settings-path")
                    .long("settings-path")
                    .short("s")
                    .takes_value(true)
                    .help("File containing the settings for this policy")
                )
                .arg(
                    Arg::with_name("settings-json")
                    .long("settings-json")
                    .takes_value(true)
                    .help("JSON string containing the settings for this policy")
                )
                .arg(
                    Arg::with_name("type")
                    .long("type")
                    .short("t")
                    .required(true)
                    .takes_value(true)
                    .possible_values(&["ClusterAdmissionPolicy"])
                    .help("Kubewarden Custom Resource type")
                )
                .arg(
                    Arg::with_name("uri")
                        .required(true)
                        .index(1)
                        .help("Policy URI. Supported schemes: registry://, https://, file://")
                )
        )
        .subcommand(
            SubCommand::with_name("completions")
                .about("Generate shell completions")
                .arg(
                    Arg::with_name("shell")
                    .long("shell")
                    .short("s")
                    .takes_value(true)
                    .required(true)
                    .possible_values(&["bash", "fish", "zsh", "elvish", "powershell"])
                    .help("Shell type")
                )
        )
        .long_version(VERSION_AND_BUILTINS.as_str())
        .setting(AppSettings::SubcommandRequiredElseHelp)
}

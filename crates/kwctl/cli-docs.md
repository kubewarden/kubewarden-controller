# Command-Line Help for `kwctl`

This document contains the help content for the `kwctl` command-line program.

**Command Overview:**

* [`kwctl`↴](#kwctl)
* [`kwctl annotate`↴](#kwctl-annotate)
* [`kwctl bench`↴](#kwctl-bench)
* [`kwctl completions`↴](#kwctl-completions)
* [`kwctl digest`↴](#kwctl-digest)
* [`kwctl docs`↴](#kwctl-docs)
* [`kwctl info`↴](#kwctl-info)
* [`kwctl inspect`↴](#kwctl-inspect)
* [`kwctl load`↴](#kwctl-load)
* [`kwctl policies`↴](#kwctl-policies)
* [`kwctl pull`↴](#kwctl-pull)
* [`kwctl push`↴](#kwctl-push)
* [`kwctl rm`↴](#kwctl-rm)
* [`kwctl run`↴](#kwctl-run)
* [`kwctl save`↴](#kwctl-save)
* [`kwctl scaffold`↴](#kwctl-scaffold)
* [`kwctl scaffold admission-request`↴](#kwctl-scaffold-admission-request)
* [`kwctl scaffold artifacthub`↴](#kwctl-scaffold-artifacthub)
* [`kwctl scaffold manifest`↴](#kwctl-scaffold-manifest)
* [`kwctl scaffold vap`↴](#kwctl-scaffold-vap)
* [`kwctl scaffold verification-config`↴](#kwctl-scaffold-verification-config)
* [`kwctl verify`↴](#kwctl-verify)

## `kwctl`

Tool to manage Kubewarden policies

**Usage:** `kwctl [OPTIONS] <COMMAND>`

###### **Subcommands:**

* `annotate` — Add Kubewarden metadata to a WebAssembly module
* `bench` — Benchmarks a Kubewarden policy
* `completions` — Generate shell completions
* `digest` — Fetch digest from the OCI manifest of a policy
* `docs` — Generates the markdown documentation for kwctl commands
* `info` — Display system information
* `inspect` — Inspect Kubewarden policy
* `load` — load policies from a tar.gz file
* `policies` — Lists all downloaded policies
* `pull` — Pulls a Kubewarden policy from a given URI
* `push` — Pushes a Kubewarden policy to an OCI registry
* `rm` — Removes a Kubewarden policy from the store
* `run` — Runs a Kubewarden policy from a given URI
* `save` — save policies to a tar.gz file
* `scaffold` — Scaffold a Kubernetes resource or configuration file
* `verify` — Verify a Kubewarden policy from a given URI using Sigstore

###### **Options:**

* `-v`, `--verbose <VERBOSE>` — Increase verbosity
* `--no-color <NO-COLOR>` — Disable colorful output



## `kwctl annotate`

Add Kubewarden metadata to a WebAssembly module

**Usage:** `kwctl annotate [OPTIONS] --metadata-path <PATH> --output-path <PATH> <wasm-path>`

###### **Arguments:**

* `<WASM-PATH>` — Path to WebAssembly module to be annotated

###### **Options:**

* `-m`, `--metadata-path <PATH>` — File containing the metadata
* `-o`, `--output-path <PATH>` — Output file
* `-u`, `--usage-path <PATH>` — File containing the usage information of the policy



## `kwctl bench`

Benchmarks a Kubewarden policy

**Usage:** `kwctl bench [OPTIONS] --request-path <PATH> <uri_or_sha_prefix>`

###### **Arguments:**

* `<URI_OR_SHA_PREFIX>` — Policy URI or SHA prefix. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory.

###### **Options:**

* `--allow-context-aware <ALLOW-CONTEXT-AWARE>` — Grant access to the Kubernetes resources defined inside of the policy's `contextAwareResources` section. Warning: review the list of resources carefully to avoid abuses. Disabled by default
* `--cert-email <VALUE>` — Expected email in Fulcio certificate
* `--cert-oidc-issuer <VALUE>` — Expected OIDC issuer in Fulcio certificates
* `--disable-wasmtime-cache <DISABLE-WASMTIME-CACHE>` — Turn off usage of wasmtime cache
* `--docker-config-json-path <PATH>` — Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details
* `--dump-results-to-disk <DUMP_RESULTS_TO_DISK>` — Puts results in target/tiny-bench/label/.. if target can be found. used for comparing previous runs
* `-e`, `--execution-mode <MODE>` — The runtime to use to execute this policy

  Possible values: `opa`, `gatekeeper`, `kubewarden`, `wasi`

* `--fulcio-cert-path <PATH>` — Path to the Fulcio certificate. Can be repeated multiple times
* `--github-owner <VALUE>` — GitHub owner expected in the certificates generated in CD pipelines
* `--github-repo <VALUE>` — GitHub repository expected in the certificates generated in CD pipelines
* `--measurement-time <SECONDS>` — How long the bench ‘should’ run, num_samples is prioritized so benching will take longer to be able to collect num_samples if the code to be benched is slower than this time limit allowed
* `--num-resamples <NUM>` — How many resamples should be done
* `--num-samples <NUM>` — How many resamples should be done. Recommended at least 50, above 100 doesn’t seem to yield a significantly different result
* `--raw <RAW>` — Validate a raw request

  Default value: `false`
* `--record-host-capabilities-interactions <FILE>` — Record all the policy and host capabilities
   communications to the given file.
   Useful to be combined later with '--replay-host-capabilities-interactions' flag
* `--rekor-public-key-path <PATH>` — Path to the Rekor public key
* `--replay-host-capabilities-interactions <FILE>` — During policy and host capabilities exchanges
   the host replays back the answers found inside of the provided file.
   This is useful to test policies in a reproducible way, given no external
   interactions with OCI registries, DNS, Kubernetes are performed.
* `-r`, `--request-path <PATH>` — File containing the Kubernetes admission request object in JSON format
* `--settings-json <VALUE>` — JSON string containing the settings for this policy
* `-s`, `--settings-path <PATH>` — File containing the settings for this policy
* `--sources-path <PATH>` — YAML file holding source information (https, registry insecure hosts, custom CA's...)
* `-a`, `--verification-annotation <KEY=VALUE>` — Annotation in key=value format. Can be repeated multiple times
* `--verification-config-path <PATH>` — YAML file holding verification config information (signatures, public keys...)
* `-k`, `--verification-key <PATH>` — Path to key used to verify the policy. Can be repeated multiple times
* `--warm-up-time <SECONDS>` — How long the bench should warm up



## `kwctl completions`

Generate shell completions

**Usage:** `kwctl completions --shell <VALUE>`

###### **Options:**

* `-s`, `--shell <VALUE>` — Shell type

  Possible values: `bash`, `elvish`, `fish`, `powershell`, `zsh`




## `kwctl digest`

Fetch digest from the OCI manifest of a policy

**Usage:** `kwctl digest [OPTIONS] <uri>`

###### **Arguments:**

* `<URI>` — Policy URI

###### **Options:**

* `--docker-config-json-path <PATH>` — Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details
* `--sources-path <PATH>` — YAML file holding source information (https, registry insecure hosts, custom CA's...)



## `kwctl docs`

Generates the markdown documentation for kwctl commands

**Usage:** `kwctl docs --output <FILE>`

###### **Options:**

* `-o`, `--output <FILE>` — path where the documentation file will be stored



## `kwctl info`

Display system information

**Usage:** `kwctl info`



## `kwctl inspect`

Inspect Kubewarden policy

**Usage:** `kwctl inspect [OPTIONS] <uri_or_sha_prefix>`

###### **Arguments:**

* `<URI_OR_SHA_PREFIX>` — Policy URI or SHA prefix. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory.

###### **Options:**

* `--docker-config-json-path <PATH>` — Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details
* `-o`, `--output <FORMAT>` — Output format

  Possible values: `yaml`

* `--show-signatures <SHOW-SIGNATURES>` — Show sigstore signatures
* `--sources-path <PATH>` — YAML file holding source information (https, registry insecure hosts, custom CA's...)



## `kwctl load`

load policies from a tar.gz file

**Usage:** `kwctl load --input <input>`

###### **Options:**

* `--input <INPUT>` — load policies from tarball



## `kwctl policies`

Lists all downloaded policies

**Usage:** `kwctl policies`



## `kwctl pull`

Pulls a Kubewarden policy from a given URI

**Usage:** `kwctl pull [OPTIONS] <uri>`

###### **Arguments:**

* `<URI>` — Policy URI. Supported schemes: registry://, https://, file://

###### **Options:**

* `--cert-email <VALUE>` — Expected email in Fulcio certificate
* `--cert-oidc-issuer <VALUE>` — Expected OIDC issuer in Fulcio certificates
* `--docker-config-json-path <DOCKER_CONFIG>` — Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details
* `--fulcio-cert-path <PATH>` — Path to the Fulcio certificate. Can be repeated multiple times
* `--github-owner <VALUE>` — GitHub owner expected in the certificates generated in CD pipelines
* `--github-repo <VALUE>` — GitHub repository expected in the certificates generated in CD pipelines
* `-o`, `--output-path <PATH>` — Output file. If not provided will be downloaded to the Kubewarden store
* `--rekor-public-key-path <PATH>` — Path to the Rekor public key. Can be repeated multiple times
* `--sources-path <PATH>` — YAML file holding source information (https, registry insecure hosts, custom CA's...)
* `-a`, `--verification-annotation <KEY=VALUE>` — Annotation in key=value format. Can be repeated multiple times
* `--verification-config-path <PATH>` — YAML file holding verification config information (signatures, public keys...)
* `-k`, `--verification-key <PATH>` — Path to key used to verify the policy. Can be repeated multiple times



## `kwctl push`

Pushes a Kubewarden policy to an OCI registry

**Usage:** `kwctl push [OPTIONS] <policy> <uri>`

###### **Arguments:**

* `<POLICY>` — Policy to push. Can be the path to a local file, a policy URI or the SHA prefix of a policy in the store.
* `<URI>` — Policy URI. Supported schemes: registry://

###### **Options:**

* `--docker-config-json-path <PATH>` — Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details
* `-f`, `--force <FORCE>` — Push also a policy that is not annotated
* `-o`, `--output <PATH>` — Output format

  Default value: `text`

  Possible values: `text`, `json`

* `--sources-path <PATH>` — YAML file holding source information (https, registry insecure hosts, custom CA's...)



## `kwctl rm`

Removes a Kubewarden policy from the store

**Usage:** `kwctl rm <uri_or_sha_prefix>`

###### **Arguments:**

* `<URI_OR_SHA_PREFIX>` — Policy URI or SHA prefix



## `kwctl run`

Runs a Kubewarden policy from a given URI

**Usage:** `kwctl run [OPTIONS] --request-path <PATH> <uri_or_sha_prefix>`

###### **Arguments:**

* `<URI_OR_SHA_PREFIX>` — Policy URI or SHA prefix. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory.

###### **Options:**

* `--allow-context-aware <ALLOW-CONTEXT-AWARE>` — Grant access to the Kubernetes resources defined inside of the policy's `contextAwareResources` section. Warning: review the list of resources carefully to avoid abuses. Disabled by default
* `--cert-email <VALUE>` — Expected email in Fulcio certificate
* `--cert-oidc-issuer <VALUE>` — Expected OIDC issuer in Fulcio certificates
* `--disable-wasmtime-cache <DISABLE-WASMTIME-CACHE>` — Turn off usage of wasmtime cache
* `--docker-config-json-path <PATH>` — Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details
* `-e`, `--execution-mode <MODE>` — The runtime to use to execute this policy

  Possible values: `opa`, `gatekeeper`, `kubewarden`, `wasi`

* `--fulcio-cert-path <PATH>` — Path to the Fulcio certificate. Can be repeated multiple times
* `--github-owner <VALUE>` — GitHub owner expected in the certificates generated in CD pipelines
* `--github-repo <VALUE>` — GitHub repository expected in the certificates generated in CD pipelines
* `--raw <RAW>` — Validate a raw request

  Default value: `false`
* `--record-host-capabilities-interactions <FILE>` — Record all the policy and host capabilities
   communications to the given file.
   Useful to be combined later with '--replay-host-capabilities-interactions' flag
* `--rekor-public-key-path <PATH>` — Path to the Rekor public key
* `--replay-host-capabilities-interactions <FILE>` — During policy and host capabilities exchanges
   the host replays back the answers found inside of the provided file.
   This is useful to test policies in a reproducible way, given no external
   interactions with OCI registries, DNS, Kubernetes are performed.
* `-r`, `--request-path <PATH>` — File containing the Kubernetes admission request object in JSON format
* `--settings-json <VALUE>` — JSON string containing the settings for this policy
* `-s`, `--settings-path <PATH>` — File containing the settings for this policy
* `--sources-path <PATH>` — YAML file holding source information (https, registry insecure hosts, custom CA's...)
* `-a`, `--verification-annotation <KEY=VALUE>` — Annotation in key=value format. Can be repeated multiple times
* `--verification-config-path <PATH>` — YAML file holding verification config information (signatures, public keys...)
* `-k`, `--verification-key <PATH>` — Path to key used to verify the policy. Can be repeated multiple times



## `kwctl save`

save policies to a tar.gz file

**Usage:** `kwctl save --output <FILE> <policies>...`

###### **Arguments:**

* `<POLICIES>` — list of policies to save

###### **Options:**

* `-o`, `--output <FILE>` — path where the file will be stored



## `kwctl scaffold`

Scaffold a Kubernetes resource or configuration file

**Usage:** `kwctl scaffold <COMMAND>`

###### **Subcommands:**

* `admission-request` — Scaffold an AdmissionRequest object
* `artifacthub` — Output an artifacthub-pkg.yml file from a metadata.yml file
* `manifest` — Output a Kubernetes resource manifest
* `vap` — Convert a Kubernetes `ValidatingAdmissionPolicy` into a Kubewarden `ClusterAdmissionPolicy`
* `verification-config` — Output a default Sigstore verification configuration file



## `kwctl scaffold admission-request`

Scaffold an AdmissionRequest object

**Usage:** `kwctl scaffold admission-request [OPTIONS] --operation <TYPE>`

###### **Options:**

* `--object <PATH>` — The file containing the new object being admitted
* `--old-object <PATH>` — The file containing the existing object
* `-o`, `--operation <TYPE>` — Kubewarden Custom Resource type

  Possible values: `CREATE`




## `kwctl scaffold artifacthub`

Output an artifacthub-pkg.yml file from a metadata.yml file

**Usage:** `kwctl scaffold artifacthub [OPTIONS] --metadata-path <PATH> --version <VALUE>`

###### **Options:**

* `-m`, `--metadata-path <PATH>` — File containing the metadata of the policy
* `-o`, `--output <FILE>` — Path where the artifact-pkg.yml file will be stored
* `-q`, `--questions-path <PATH>` — File containing the questions-ui content of the policy
* `-v`, `--version <VALUE>` — Semver version of the policy



## `kwctl scaffold manifest`

Output a Kubernetes resource manifest

**Usage:** `kwctl scaffold manifest [OPTIONS] --type <VALUE> <uri_or_sha_prefix>`

###### **Arguments:**

* `<URI_OR_SHA_PREFIX>` — Policy URI or SHA prefix. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory.

###### **Options:**

* `--allow-context-aware <ALLOW-CONTEXT-AWARE>` — Uses the policy metadata to define which Kubernetes resources can be accessed by the policy. Warning: review the list of resources carefully to avoid abuses. Disabled by default
* `--cert-email <VALUE>` — Expected email in Fulcio certificate
* `--cert-oidc-issuer <VALUE>` — Expected OIDC issuer in Fulcio certificates
* `--docker-config-json-path <DOCKER_CONFIG>` — Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details
* `--fulcio-cert-path <PATH>` — Path to the Fulcio certificate. Can be repeated multiple times
* `--github-owner <VALUE>` — GitHub owner expected in the certificates generated in CD pipelines
* `--github-repo <VALUE>` — GitHub repository expected in the certificates generated in CD pipelines
* `--rekor-public-key-path <PATH>` — Path to the Rekor public key. Can be repeated multiple times
* `--settings-json <VALUE>` — JSON string containing the settings for this policy
* `-s`, `--settings-path <PATH>` — File containing the settings for this policy
* `--sources-path <PATH>` — YAML file holding source information (https, registry insecure hosts, custom CA's...)
* `--title <VALUE>` — Policy title
* `-t`, `--type <VALUE>` — Kubewarden Custom Resource type

  Possible values: `ClusterAdmissionPolicy`, `AdmissionPolicy`

* `-a`, `--verification-annotation <KEY=VALUE>` — Annotation in key=value format. Can be repeated multiple times
* `--verification-config-path <PATH>` — YAML file holding verification config information (signatures, public keys...)
* `-k`, `--verification-key <PATH>` — Path to key used to verify the policy. Can be repeated multiple times



## `kwctl scaffold vap`

Convert a Kubernetes `ValidatingAdmissionPolicy` into a Kubewarden `ClusterAdmissionPolicy`

**Usage:** `kwctl scaffold vap [OPTIONS] --binding <VALIDATING-ADMISSION-POLICY-BINDING.yaml> --policy <VALIDATING-ADMISSION-POLICY.yaml>`

###### **Options:**

* `-b`, `--binding <VALIDATING-ADMISSION-POLICY-BINDING.yaml>` — The file containining the ValidatingAdmissionPolicyBinding definition
* `--cel-policy <URI>` — The CEL policy module to use

  Default value: `ghcr.io/kubewarden/policies/cel-policy:latest`
* `-p`, `--policy <VALIDATING-ADMISSION-POLICY.yaml>` — The file containining the ValidatingAdmissionPolicy definition



## `kwctl scaffold verification-config`

Output a default Sigstore verification configuration file

**Usage:** `kwctl scaffold verification-config`



## `kwctl verify`

Verify a Kubewarden policy from a given URI using Sigstore

**Usage:** `kwctl verify [OPTIONS] <uri>`

###### **Arguments:**

* `<URI>` — Policy URI. Supported schemes: registry://

###### **Options:**

* `--cert-email <VALUE>` — Expected email in Fulcio certificate
* `--cert-oidc-issuer <VALUE>` — Expected OIDC issuer in Fulcio certificates
* `--docker-config-json-path <PATH>` — Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details
* `--fulcio-cert-path <PATH>` — Path to the Fulcio certificate. Can be repeated multiple times
* `--github-owner <VALUE>` — GitHub owner expected in the certificates generated in CD pipelines
* `--github-repo <VALUE>` — GitHub repository expected in the certificates generated in CD pipelines
* `--rekor-public-key-path <PATH>` — Path to the Rekor public key
* `--sources-path <PATH>` — YAML file holding source information (https, registry insecure hosts, custom CA's...)
* `-a`, `--verification-annotation <KEY=VALUE>` — Annotation in key=value format. Can be repeated multiple times
* `--verification-config-path <PATH>` — YAML file holding verification config information (signatures, public keys...)
* `-k`, `--verification-key <PATH>` — Path to key used to verify the policy. Can be repeated multiple times



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>

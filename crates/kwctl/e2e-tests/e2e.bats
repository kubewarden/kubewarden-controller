#!/usr/bin/env bats

setup() {
    export KWCTL_TMPDIR=${BATS_TMPDIR}/kwctl # /tmp/kwctl

    export XDG_CONFIG_HOME=${KWCTL_TMPDIR}/.config
    export XDG_CACHE_HOME=${KWCTL_TMPDIR}/.cache
    export XDG_DATA_HOME=${KWCTL_TMPDIR}/.local/share

    rm -rf ${KWCTL_TMPDIR} && mkdir -p ${KWCTL_TMPDIR}
}

kwctl() {
    run cargo -q run --release -- "$@"
}

@test "list policies when no policies are pulled" {
    kwctl policies
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "pull a policy from HTTPS" {
    kwctl pull https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm
    [ "$status" -eq 0 ]
    kwctl policies
    [ "$status" -eq 0 ]
    [[ "$output" =~ "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm" ]]
}

@test "pull a policy from an OCI registry" {
    kwctl pull registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    kwctl policies
    [ "$status" -eq 0 ]
    [[ "$output" =~ "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9" ]]
}

@test "pull a policy from HTTPS to a file" {
    kwctl pull -o ${KWCTL_TMPDIR}/my-policy.wasm https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm
    [ "$status" -eq 0 ]
    kwctl policies
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
    run file ${KWCTL_TMPDIR}/my-policy.wasm
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*WebAssembly.*') -ne 0 ]
}

@test "execute a remote policy that is allowed" {
    kwctl run --request-path test-data/unprivileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "execute a remote policy that is rejected" {
    kwctl run --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
}

@test "execute a remote policy that is allowed with AdmissionReview object as the root document" {
    kwctl run --request-path test-data/unprivileged-pod-admission-review.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "execute a remote policy that is rejected with AdmissionReview object as the root document" {
    kwctl run --request-path test-data/privileged-pod-admission-review.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
}

@test "execute a remote policy that use context aware informtion using a pre-recorded session" {
    # replay a session where the namespace is found
    kwctl run \
    --request-path test-data/context-aware-policy-request-pod-creation-all-labels.json \
    --allow-context-aware \
    --replay-host-capabilities-interactions test-data/host-capabilities-sessions/context-aware-demo-namespace-found.yml \
    registry://ghcr.io/kubewarden/tests/context-aware-policy-demo:v0.1.0
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]

    # replay a session where something went wrong
    kwctl run \
    --request-path test-data/context-aware-policy-request-pod-creation-all-labels.json \
    --allow-context-aware \
    --replay-host-capabilities-interactions test-data/host-capabilities-sessions/context-aware-demo-namespace-not-found.yml \
    registry://ghcr.io/kubewarden/tests/context-aware-policy-demo:v0.1.0
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
}

@test "benchmark a policy" {
    kwctl bench \
      --warm-up-time 1 \
      --measurement-time 1 \
      --num-resamples 2 \
      --num-samples 2 \
      --request-path test-data/privileged-pod-admission-review.json \
      registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*validate.*warming up.*') -ne 0 ]
}

@test "remove a policy from the policy store" {
    kwctl pull registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    kwctl pull https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm
    kwctl policies
    [[ $(echo "$output" | wc -l) -eq 6 ]]
    [[ "$output" =~ "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9" ]]
    [[ "$output" =~ "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm" ]]
    kwctl rm registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    kwctl policies
    [[ $(echo "$output" | wc -l) -eq 5 ]]
    [[ "$output" =~ "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm" ]]
    kwctl rm https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm
    kwctl policies
    [ "$output" = "" ]
}

@test "fetch policy digest from an OCI registry" {
    kwctl digest registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [[ "$output" == "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9@sha256:0d6611ea12cf2904066308dde1c480b5d4f40e19b12f51f101a256b44d6c2dd5" ]]
    kwctl digest ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [[ "$output" == "ghcr.io/kubewarden/tests/pod-privileged:v0.1.9@sha256:0d6611ea12cf2904066308dde1c480b5d4f40e19b12f51f101a256b44d6c2dd5" ]]
}

@test "annotate rego policy" {
    kwctl annotate -m test-data/rego-annotate/metadata-correct.yml test-data/rego-annotate/no-default-namespace-rego.wasm -o /dev/null
    [ "$status" -eq 0 ]

    kwctl annotate -m test-data/rego-annotate/metadata-wrong.yml test-data/rego-annotate/no-default-namespace-rego.wasm -o /dev/null
    [ "$status" -ne 0 ]
    [[ "$output" == "Error: Wrong value inside of policy's metatada for 'executionMode'. This policy has been created using Rego" ]]
}

@test "save and load" {
    kwctl pull registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    kwctl pull https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm
    export privileged_registry_sha=$(sha256sum $XDG_CACHE_HOME/kubewarden/store/registry/ghcr.io/kubewarden/tests/pod-privileged:v0.1.9)
    export privileged_https_sha=$(sha256sum $XDG_CACHE_HOME/kubewarden/store/https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm)
    kwctl policies
    [[ $(echo "$output" | wc -l) -eq 6 ]]
    [[ "$output" =~ "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9" ]]
    [[ "$output" =~ "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm" ]]
    kwctl save --output policies.tar.gz registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9 https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm
    kwctl rm registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    kwctl rm https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm
    kwctl policies
    [ "$output" = "" ]
    kwctl load --input policies.tar.gz
    kwctl policies
    [[ $(echo "$output" | wc -l) -eq 6 ]]
    [[ "$output" =~ "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9" ]]
    [[ "$output" =~ "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm" ]]
    [[ "$privileged_registry_sha" = $(sha256sum $XDG_CACHE_HOME/kubewarden/store/registry/ghcr.io/kubewarden/tests/pod-privileged:v0.1.9) ]]
    [[ "$privileged_https_sha" = $(sha256sum $XDG_CACHE_HOME/kubewarden/store/https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm) ]]
    rm policies.tar.gz
 }

 @test "CLI app outputs colored text by default" {
    kwctl pull registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    kwctl inspect registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ "${output}" != "" ]
    [[ "${output}" == *$'\e['* ]]  # Check if output contains ANSI escape sequences
 }

@test "CLI app honors --no-color flag and disables colored output" {
    kwctl pull registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    kwctl --no-color inspect registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ "${output}" != "" ]
    [[ "${output}" != *$'\e['* ]]  # Check if output does not contain ANSI escape sequences
 }


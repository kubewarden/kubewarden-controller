#!/usr/bin/env bats

setup() {
    export KWCTL_TMPDIR=${BATS_TMPDIR}/kwctl # /tmp/kwctl

    export XDG_CONFIG_HOME=${KWCTL_TMPDIR}/.config
    export XDG_CACHE_HOME=${KWCTL_TMPDIR}/.cache
    export XDG_DATA_HOME=${KWCTL_TMPDIR}/.local/share

    rm -rf ${KWCTL_TMPDIR} && mkdir -p ${KWCTL_TMPDIR}
}

kwctl() {
    run cargo -q run -- "$@"
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
    kwctl pull registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    kwctl policies
    [ "$status" -eq 0 ]
    [[ "$output" =~ "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9" ]]
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
    kwctl run --request-path test-data/unprivileged-pod.json registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "execute a remote policy that is rejected" {
    kwctl run --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
}

@test "execute a remote policy that is allowed with AdmissionReview object as the root document" {
    kwctl run --request-path test-data/unprivileged-pod-admission-review.json registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "execute a remote policy that is rejected with AdmissionReview object as the root document" {
    kwctl run --request-path test-data/privileged-pod-admission-review.json registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
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
    kwctl digest registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    [[ "$output" == "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9@sha256:0d6611ea12cf2904066308dde1c480b5d4f40e19b12f51f101a256b44d6c2dd5" ]]
    kwctl digest ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    [[ "$output" == "ghcr.io/kubewarden/policies/pod-privileged:v0.1.9@sha256:0d6611ea12cf2904066308dde1c480b5d4f40e19b12f51f101a256b44d6c2dd5" ]]
}

#!/usr/bin/env bats

setup() {
    rm -rf ~/.cache/kubewarden
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
    kwctl pull https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.5/policy.wasm
    [ "$status" -eq 0 ]
    [ "$output" = "pulling policy..." ]
    kwctl policies
    [ "$status" -eq 0 ]
    [[ "$output" = *"https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.5/policy.wasm" ]]
}

@test "pull a policy from an OCI registry" {
    kwctl pull registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5
    [ "$status" -eq 0 ]
    [ "$output" = "pulling policy..." ]
    kwctl policies
    [ "$status" -eq 0 ]
    [[ "$output" = *"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5" ]]
}

@test "pull a policy from HTTPS to a file" {
    kwctl pull -o /tmp/my-policy.wasm https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.5/policy.wasm
    [ "$status" -eq 0 ]
    kwctl policies
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
    run file /tmp/my-policy.wasm
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*WebAssembly.*') -ne 0 ]
}

@test "execute a remote policy that is allowed" {
    kwctl run --request-path test-data/unprivileged-pod.json registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "execute a remote policy that is rejected" {
    kwctl run --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
}

@test "execute a remote policy that is allowed with AdmissionReview object as the root document" {
    kwctl run --request-path test-data/unprivileged-pod-admission-review.json registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "execute a remote policy that is rejected with AdmissionReview object as the root document" {
    kwctl run --request-path test-data/privileged-pod-admission-review.json registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
}

@test "remove a policy from the policy store" {
    kwctl pull registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5
    kwctl pull https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.5/policy.wasm
    kwctl policies
    [[ $(echo "$output" | wc -l) -eq 2 ]]
    [[ ${lines[0]} =~ "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5" ]]
    [[ ${lines[1]} =~ "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.5/policy.wasm" ]]
    kwctl rm registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5
    kwctl policies
    [[ $(echo "$output" | wc -l) -eq 1 ]]
    [[ ${lines[0]} =~ "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.5/policy.wasm" ]]
    kwctl rm https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.5/policy.wasm
    kwctl policies
    [ "$output" = "" ]
}

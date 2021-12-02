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
    kwctl pull -o /tmp/my-policy.wasm https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm
    [ "$status" -eq 0 ]
    kwctl policies
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
    run file /tmp/my-policy.wasm
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

@test "verify a signed policy from an OCI registry" {
    kwctl verify -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*The following required arguments were not provided.*') -ne 0 ]
    kwctl verify -k test-data/sigstore/cosign1.pub -k unexistent-path-to-key.pub -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*No such file or directory.*') -ne 0 ]
    kwctl verify -k test-data/sigstore/cosign1.pub -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*Policy successfully verified.*') -ne 0 ]
    kwctl verify -k test-data/sigstore/cosign1.pub -k test-data/sigstore/cosign2.pub -a env=prod registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*Policy successfully verified.*') -ne 0 ]
    kwctl verify -k test-data/sigstore/cosign3.pub registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*No signing keys matched given constraints*') -ne 0 ]
    kwctl verify -k test-data/sigstore/cosign2.pub -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*No signing keys matched given constraints*') -ne 0 ]
    # TODO should return instead: Annotation not satisfied missing_annotation="stable"
}

@test "pull a signed policy from an OCI registry" {
    kwctl pull -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Intending to verify annotations, but no verification keys were passed.*') -ne 0 ]
    kwctl pull -k test-data/sigstore/cosign1.pub -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*Policy successfully verified.*') -ne 0 ]
    [ $(expr "$output" : '.*Local checksum successfully verified.*') -ne 0 ]
}

@test "execute a signed policy from an OCI registry" {
    kwctl run -k test-data/sigstore/cosign1.pub -k test-data/sigstore/cosign2.pub -a env=prod --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
    [ $(expr "$output" : '.*Policy successfully verified.*') -ne 0 ]
    kwctl run -k test-data/sigstore/cosign1.pub -k test-data/sigstore/cosign3.pub -a env=prod -a stable=true --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*No signing keys matched given constraints*') -ne 0 ]
}

#!/usr/bin/env bats

setup() {
    rm -rf ~/.cache/kubewarden
}

kwctl() {
    run cargo -q run -- "$@"
}


@test "[Secure supply chain  tests] \"verify\" command should have some minimum command line flags" {
    kwctl verify --help
    [ $(expr "$output" : '.*--verification-annotation.*') -ne 0 ]
    [ $(expr "$output" : '.*--cert-email.*') -ne 0 ]
    [ $(expr "$output" : '.*--cert-oidc-issuer.*') -ne 0 ]
    [ $(expr "$output" : '.*--github-owner.*') -ne 0 ]
    [ $(expr "$output" : '.*--github-repo.*') -ne 0 ]
    [ $(expr "$output" : '.*--docker-config-json-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--fulcio-cert-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--verification-key.*') -ne 0 ]
    [ $(expr "$output" : '.*--rekor-public-key-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--sources-path.*') -ne 0 ]
}

@test "[Secure supply chain  tests] \"pull\" command should have some minimum command line flags" {
    kwctl pull --help
    [ $(expr "$output" : '.*--verification-annotation.*') -ne 0 ]
    [ $(expr "$output" : '.*--cert-email.*') -ne 0 ]
    [ $(expr "$output" : '.*--cert-oidc-issuer.*') -ne 0 ]
    [ $(expr "$output" : '.*--github-owner.*') -ne 0 ]
    [ $(expr "$output" : '.*--github-repo.*') -ne 0 ]
    [ $(expr "$output" : '.*--docker-config-json-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--fulcio-cert-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--verification-key.*') -ne 0 ]
    [ $(expr "$output" : '.*--rekor-public-key-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--sources-path.*') -ne 0 ]
}

@test "[Secure supply chain  tests] \"run\" command should have some minimum command line flags" {
    kwctl run --help
    [ $(expr "$output" : '.*--verification-annotation.*') -ne 0 ]
    [ $(expr "$output" : '.*--cert-email.*') -ne 0 ]
    [ $(expr "$output" : '.*--cert-oidc-issuer.*') -ne 0 ]
    [ $(expr "$output" : '.*--github-owner.*') -ne 0 ]
    [ $(expr "$output" : '.*--github-repo.*') -ne 0 ]
    [ $(expr "$output" : '.*--docker-config-json-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--fulcio-cert-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--verification-key.*') -ne 0 ]
    [ $(expr "$output" : '.*--rekor-public-key-path.*') -ne 0 ]
    [ $(expr "$output" : '.*--sources-path.*') -ne 0 ]
}

@test "[Secure supply chain  tests] verify a signed policy from an OCI registry" {
    kwctl verify -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Intending to verify annotations, but no verification keys were passed.*') -ne 0 ]
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
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]
    kwctl verify -k test-data/sigstore/cosign2.pub -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]
    kwctl verify --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
        --verification-config-path=test-data/sigstore/verification-config.yml \
        registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    kwctl verify --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
        --verification-config-path=test-data/sigstore/verification-config.yml \
        registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]
    kwctl verify --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
        --verification-config-path=test-data/sigstore/verification-config-keyless.yml \
        registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 0 ]
}

@test "[Secure supply chain  tests] pull a signed policy from an OCI registry" {
    kwctl pull -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Intending to verify annotations, but no verification keys were passed.*') -ne 0 ]
    kwctl pull -k test-data/sigstore/cosign1.pub -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*Policy successfully verified.*') -ne 0 ]
    [ $(expr "$output" : '.*Local checksum successfully verified.*') -ne 0 ]
    kwctl verify --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
        --verification-config-path=test-data/sigstore/verification-config.yml \
        registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    kwctl pull --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
        --verification-config-path=test-data/sigstore/verification-config.yml \
        registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]
}

@test "[Secure supply chain  tests] execute a signed policy from an OCI registry" {
    kwctl run -k test-data/sigstore/cosign1.pub -k test-data/sigstore/cosign2.pub -a env=prod --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
    [ $(expr "$output" : '.*Policy successfully verified.*') -ne 0 ]
    kwctl run -k test-data/sigstore/cosign1.pub -k test-data/sigstore/cosign3.pub -a env=prod -a stable=true --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]
    kwctl run --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
        --verification-config-path=test-data/sigstore/verification-config.yml \
        --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    kwctl run --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
        --verification-config-path=test-data/sigstore/verification-config.yml \
        --request-path test-data/privileged-pod.json \
        registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]
}


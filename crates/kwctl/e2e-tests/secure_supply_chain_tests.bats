#!/usr/bin/env bats

redefine_xdg_envvars() {
    export KWCTL_TMPDIR=${BATS_TMPDIR}/kwctl # /tmp/kwctl

    export XDG_CONFIG_HOME=${KWCTL_TMPDIR}/.config
    export XDG_CACHE_HOME=${KWCTL_TMPDIR}/.cache
    export XDG_DATA_HOME=${KWCTL_TMPDIR}/.local/share

    rm -rf ${KWCTL_TMPDIR} && mkdir -p ${KWCTL_TMPDIR}
}

setup_file() {
    # once for all tests in file
    redefine_xdg_envvars
    cosign initialize
}

setup() {
    # before every test
    redefine_xdg_envvars
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

# @test "[Secure supply chain  tests] Check TUF integration" {
#     mkdir -p "$XDG_CONFIG_HOME"/kubewarden/fulcio_and_rekor_data
#     FULCIO_AND_REKOR_DATA_DIR=$(readlink -f "$XDG_CONFIG_HOME"/kubewarden/fulcio_and_rekor_data)
#     rm -rf ${FULCIO_AND_REKOR_DATA_DIR}
#     kwctl verify \
#       --verification-config-path=test-data/sigstore/verification-config-keyless.yml \
#       registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
#     [ "$status" -eq 0 ]
#     [ -f ${FULCIO_AND_REKOR_DATA_DIR}/fulcio.crt.pem ]
#     [ -f ${FULCIO_AND_REKOR_DATA_DIR}/fulcio_v1.crt.pem ]
#     [ -f ${FULCIO_AND_REKOR_DATA_DIR}/rekor.pub ]
# }

@test "[Secure supply chain  tests] verify a signed policy from an OCI registry" {

    kwctl verify \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      -a env=prod -a stable=true \
      registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Intending to verify annotations, but no verification keys, OIDC issuer or GitHub owner were passed.*') -ne 0 ]

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

    kwctl verify \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      --verification-config-path=test-data/sigstore/verification-config.yml \
      registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]

    kwctl verify \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --verification-config-path=test-data/sigstore/verification-config.yml \
      registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*both a fulcio certificate and a rekor public key are required.*') -ne 0 ]

    kwctl verify \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      --verification-config-path=test-data/sigstore/verification-config.yml \
      registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*both a fulcio certificate and a rekor public key are required.*') -ne 0 ]

    kwctl verify \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      --verification-config-path=test-data/sigstore/verification-config.yml \
      registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]

    kwctl verify \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      --verification-config-path=test-data/sigstore/verification-config-keyless.yml \
      registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 0 ]

}

@test "[Secure supply chain  tests] pull a signed policy from an OCI registry" {
    kwctl pull \
      -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Intending to verify annotations, but no verification keys, OIDC issuer or GitHub owner were passed.*') -ne 0 ]


    kwctl pull \
      -k test-data/sigstore/cosign1.pub -a env=prod -a stable=true registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*Policy successfully verified.*') -ne 0 ]
    [ $(expr "$output" : '.*Local checksum successfully verified.*') -ne 0 ]

    kwctl verify \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      --verification-config-path=test-data/sigstore/verification-config.yml \
      registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]

    kwctl pull \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      --verification-config-path=test-data/sigstore/verification-config.yml \
      registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]
}

@test "[Secure supply chain  tests] execute a signed policy from an OCI registry" {
    kwctl run \
      -k test-data/sigstore/cosign1.pub \
      -k test-data/sigstore/cosign2.pub \
      -a env=prod \
      --request-path test-data/privileged-pod.json \
      registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
    [ $(expr "$output" : '.*Policy successfully verified.*') -ne 0 ]

    kwctl run -k test-data/sigstore/cosign1.pub -k test-data/sigstore/cosign3.pub -a env=prod -a stable=true --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]

    kwctl run \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      --verification-config-path=test-data/sigstore/verification-config.yml \
      --request-path test-data/privileged-pod.json registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    [ "$status" -eq 0 ]

    kwctl run \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      --verification-config-path=test-data/sigstore/verification-config.yml \
      --request-path test-data/privileged-pod.json \
      registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 1 ]
    [ $(expr "$output" : '.*Image verification failed: missing signatures.*') -ne 0 ]
}


@test "[Secure supply chain  tests] generate verification config and verify a Kubewarden policy" {
    mkdir -p ${XDG_CONFIG_HOME}/kubewarden
    run bash -c "cargo run -q -- scaffold verification-config > ${XDG_CONFIG_HOME}/kubewarden/verification-config.yml"

    kwctl verify \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio.crt.pem \
      --fulcio-cert-path ~/.sigstore/root/targets/fulcio_v1.crt.pem \
      --rekor-public-key-path ~/.sigstore/root/targets/rekor.pub \
      registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9
    [ "$status" -eq 0 ]
}

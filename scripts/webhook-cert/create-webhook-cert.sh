#!/usr/bin/env sh
# shellcheck shell=sh

set -xe

SCRIPT_DIR="$( dirname "$0" )"

## expected localhost path of the manager:
CERT_DIR=/tmp/k8s-webhook-server/serving-certs

rm -f "${SCRIPT_DIR}"/*.pem
## Create key and cert:
openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
    -keyout "${SCRIPT_DIR}"/key.pem \
    -out "${SCRIPT_DIR}"/cert.pem \
    -config "${SCRIPT_DIR}"/san-cert.conf -extensions 'v3_req'
## Verify cert:
openssl x509 -in "${SCRIPT_DIR}"/cert.pem -noout -text
# Copy to localhost folder:
mkdir -p "${CERT_DIR}"
cp -f "${SCRIPT_DIR}"/cert.pem  "${CERT_DIR}"/tls.crt
cp -f "${SCRIPT_DIR}"/key.pem  "${CERT_DIR}"/tls.key

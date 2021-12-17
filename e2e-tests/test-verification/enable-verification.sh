#!/usr/bin/env sh
set -ex

# cleanup:
kubectl delete policyservers.policies.kubewarden.io --all
kubectl delete clusteradmissionpolicies.policies.kubewarden.io --all

# create verification configmap:
kubectl delete configmap my-verification-config -n kubewarden --ignore-not-found
kubectl create configmap my-verification-config --from-file=verification-config=./resources/my-verification-config.yml --namespace=kubewarden

# test server without verification works:
kubectl apply -f ./resources/server-without-verification.yml
kubectl apply -f ./resources/policy.yml
kubectl wait --timeout=2m --for=condition=PolicyActive clusteradmissionpolicies --all

# test server with verification works:
kubectl delete clusteradmissionpolicies.policies.kubewarden.io --all
kubectl apply -f ./resources/server-with-verification.yml
kubectl apply -f ./resources/policy.yml
kubectl wait --timeout=2m --for=condition=PolicyActive clusteradmissionpolicies --all
kubectl logs -l app=kubewarden-policy-server-reserved-instance-for-tenant-a -n kubewarden | grep 'verified-signatures\|verified-local-checksum'

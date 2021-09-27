#!/bin/bash

for crd in $(kubectl get crds -o name);
do
  for crdItem in $(kubectl get "${crd##*/}" -o name);
  do
    kubectl patch "${crdItem}" --type json --patch='[ { "op": "remove", "path": "/metadata/finalizers" } ]'
  done
done

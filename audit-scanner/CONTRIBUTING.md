### Testing localy

Install Kubewarden stack normally. For now:

```console
git checkout feat-audit
cd kubewarden-controller
make install # install CRDs

helm upgrade -i --wait --namespace kubewarden --create-namespace \
  kubewarden-controller kubewarden/kubewarden-controller \
  --set image.tag=latest-feat-audit \
  --set image.repository=kubewarden/kubewarden-controller

kubectl apply -f config/samples/example-privileged-pod.yml

helm upgrade -i --wait \
  --namespace kubewarden \
  --create-namespace \
  kubewarden-defaults kubewarden/kubewarden-defaults \
  --set recommendedPolicies.enabled=True \
  --set recommendedPolicies.defaultPolicyMode=monitor

kubectl port-forward -n kubewarden service/policy-server-default 3000:8443
```

Then:


``` console
./bin/audit-scanner -k kubewarden --namespace default -l debug --policyServerFQDN localhost
```

### Testing locally

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

Install PolicyReports CRDs:
```
kubectl apply \
  -f config/crd/wgpolicyk8s.io_clusterpolicyreports.yaml \
  -f config/crd/wgpolicyk8s.io_policyreports.yaml
```

Then:

``` console
./bin/audit-scanner \
  -k kubewarden --namespace default \
  --policy-server-url https://localhost:3000 \
  -l debug
```

or to get results in JSON:

``` console
./bin/audit-scanner \
  -k kubewarden --namespace default \
  --policy-server-url https://localhost:3000 \
  -l debug --print
```

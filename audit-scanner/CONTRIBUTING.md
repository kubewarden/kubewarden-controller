### Testing locally

Install Kubewarden stack normally. `kubewarden-crds` by default install the
PolicyReports CRDs. And the audit feature is disabled by default.

Then:

``` console
kubectl port-forward -n kubewarden service/policy-server-default 3000:8443

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

### Testing locally

Install Kubewarden stack normally. `kubewarden-crds` by default install the
PolicyReports CRDs. And the audit feature is disabled by default.

Then:

```console
kubectl port-forward -n kubewarden service/policy-server-default 3000:8443

./bin/audit-scanner \
  -k kubewarden --namespace default \
  --policy-server-url https://localhost:3000 \
  -l debug
```

or to get results in JSON:

```console
./bin/audit-scanner \
  -k kubewarden --namespace default \
  --policy-server-url https://localhost:3000 \
  -l debug --output-scan
```

### Run against audit-scanner SA

To run with the `audit-scanner` ServiceAccount, install `kubewarden-controller`
chart, and, with the help of the kubectl [view-serviceaccount-kubeconfig](https://github.com/superbrothers/kubectl-view-serviceaccount-kubeconfig-plugin)
plugin:

```console
kubectl create token audit-scanner -n kubewarden | kubectl view-serviceaccount-kubeconfig > ./kubeconfig
```

If needed, patch the resulting kubeconfig, adding the missing
`certificate-authority`. E.g:

```yaml
clusters:
  - cluster:
    certificate-authority: /home/vic/.minikube/ca.crt
```

And use it:

```console
export KUBECONFIG=./kubeconfig
```

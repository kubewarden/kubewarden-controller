# kubewarden-crds

`kubewarden-crds` is the Helm chart that installs the Custom Resources Definition
required by the Kubewarden stack. It should be installed before installing
`kubewarden-controller` and `kubewarden-defaults` charts.

## Contents

This chart installs Kubewarden CRDs:
  `admissionpolicies.policies.kubewarden.io`
  `clusteradmissionpolicies.policies.kubewarden.io`
  `policyservers.policies.kubewarden.io`

It also installs PolicyReports CRDs:
  `policyreports.wgpolicyk8s.io`
  `clusterpolicyreports.wgpolicyk8s.io`

To skip installing these (maybe because for example they are already installed
and owned by a different Helm Release), set the value `policyReports.enable` to
`false`.

## Installing

For example:
```console
$ helm repo add kubewarden https://charts.kubewarden.io
$ helm install --create-namespace -n kubewarden kubewarden-crds kubewarden/kubewarden-crds
```

For a more comprehensive documentation about how to install the whole Kubewarden
stack, check the `kubewarden-controller` chart documentation out.

## Upgrading the charts

Please refer to the release notes of each version of the helm charts.
These can be found [here](https://github.com/kubewarden/helm-charts/releases).

## Uninstalling the charts

To uninstall/delete kubewarden-crds use the following command:

```console
$ helm uninstall -n kubewarden kubewarden-crds
```

The commands remove all the Kubernetes components associated with the chart.
Keep in mind that the chart is required by the `kubewarden-controller` chart.

If you want to keep the history use `--keep-history` flag.

# Kubewarden Admission Controller

Unified Helm chart for deploying the complete Kubewarden admission control stack.

> **Note:** This chart combines what were previously three separate charts:
> `kubewarden-crds` (CRDs), `kubewarden-controller` (controller), and
> `kubewarden-defaults` (default PolicyServer and recommended policies).

## Installation

```sh
helm install kubewarden kubewarden/kubewarden-controller -n kubewarden --create-namespace
```

## Migration from Three-Chart Setup

If you're currently running the legacy three-chart setup (`kubewarden-crds`, `kubewarden-controller`, `kubewarden-defaults`), follow these steps to migrate to the unified chart.

**⚠️ Important**: There will be a brief window during migration where no admission control is active. Plan accordingly.

### Prerequisites

- Access to your cluster with `kubectl` and `helm`
- Backup tool or `kubectl` configured

### Migration Steps

#### 1. Backup All Policies and PolicyServers

Uninstalling `kubewarden-crds` cascade-deletes **all** custom resources, so every policy and PolicyServer must be backed up:

```sh
kubectl get clusteradmissionpolicies -A -o yaml > clusteradmissionpolicies-backup.yaml
kubectl get admissionpolicies -A -o yaml > admissionpolicies-backup.yaml
kubectl get clusteradmissionpolicygroups -A -o yaml > clusteradmissionpolicygroups-backup.yaml
kubectl get admissionpolicygroups -A -o yaml > admissionpolicygroups-backup.yaml
kubectl get policyservers -o yaml > policyservers-backup.yaml
```

#### 2. Uninstall Old Charts

Uninstall in reverse order:

```sh
helm uninstall kubewarden-defaults -n kubewarden
helm uninstall kubewarden-controller -n kubewarden
helm uninstall kubewarden-crds -n kubewarden
```

This removes all CRDs and cascades deletion of all CRs (PolicyServers and policies).

#### 3. Install the Unified Chart

```sh
helm install kubewarden kubewarden/kubewarden-controller -n kubewarden
```

This creates:
- CRDs in `templates/crds/` (with `helm.sh/resource-policy: keep` to prevent deletion on uninstall)
- The controller
- The default PolicyServer and recommended policies (if enabled)

#### 4. Restore User Policies

Once the default PolicyServer is ready, re-apply all backed-up resources:

```sh
kubectl apply -f policyservers-backup.yaml
kubectl apply -f clusteradmissionpolicies-backup.yaml
kubectl apply -f admissionpolicies-backup.yaml
kubectl apply -f clusteradmissionpolicygroups-backup.yaml
kubectl apply -f admissionpolicygroups-backup.yaml
```

The controller's DefaultsApplier will overwrite any managed defaults with the correct ownership labels on the next reconciliation.

## Configuration

### Defaults

The chart can deploy a default PolicyServer and recommended policies managed by the controller:

```yaml
defaultConfigMapName: kubewarden-defaults

policyServer:
  enabled: true
  replicaCount: 1
  # ... (see values.yaml for full options)

recommendedPolicies:
  enabled: false  # Disabled by default
  defaultPolicyMode: "monitor"
  allowPrivilegeEscalationPolicy:
    # ... (see values.yaml)
```

When `policyServer.enabled: false` and `recommendedPolicies.enabled: false`, the defaults ConfigMap is not rendered and the controller cleans up all managed resources.

### CRDs

CRDs are installed in `templates/crds/` with the `helm.sh/resource-policy: keep` annotation. This means:
- `helm upgrade` will update CRDs
- `helm uninstall` will **not** delete CRDs (preventing catastrophic cascade-deletion of all cluster resources)

To fully remove CRDs after uninstall:

```sh
kubectl delete crd policyservers.policies.kubewarden.io
kubectl delete crd clusteradmissionpolicies.policies.kubewarden.io
kubectl delete crd admissionpolicies.policies.kubewarden.io
kubectl delete crd clusteradmissionpolicygroups.policies.kubewarden.io
kubectl delete crd admissionpolicygroups.policies.kubewarden.io
```

## Uninstall

```sh
helm uninstall kubewarden -n kubewarden
```

This removes:
- The controller deployment
- Managed defaults (resources with `kubewarden.io/managed-by=kubewarden-controller-defaults` label)
- ConfigMaps, Secrets, Services

It does **not** remove:
- CRDs (due to `helm.sh/resource-policy: keep`)
- User-managed PolicyServers and policies

## Version

- Chart version: 6.0.0-alpha.1
- App version: v2.0.0-alpha.1

## References

- [Kubewarden Documentation](https://docs.kubewarden.io/)
- [RFC 0026: Unified Admission Controller Chart](https://github.com/kubewarden/rfc/blob/main/rfc/0026-unified-admission-controller-chart.md)
